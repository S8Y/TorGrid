#!/usr/bin/env python3
"""
TorGrid — Multi-Tor SOCKS5 Proxy Pool with Web Dashboard
=========================================================
Spawns N isolated Tor instances, each on its own SOCKS5 port.
Provides a polished real-time Web UI for monitoring, management and stats.

Port layout:
  SOCKS proxies:  127.0.0.1:1738 + N  (1738..1757 for 20 instances)
  Auth SOCKS:     127.0.0.1:3738 + N  (3738..3757, if --auth-user is set)
  Control ports:  127.0.0.1:18000 + N (for stem monitoring)
  Web UI:         http://127.0.0.1:8080
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import secrets
import signal
import struct
import sys
import tempfile
import time
import traceback
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from subprocess import Popen
from typing import Optional

import aiohttp
from aiohttp_socks import ProxyConnector as SOCKSConnector
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from stem import Signal
from stem.control import Controller

# ─── CLI Args ──────────────────────────────────────────────

parser = argparse.ArgumentParser(
    prog="torgrid",
    description="Multi-Tor SOCKS5 proxy pool with web dashboard",
)
parser.add_argument(
    "-c", "--count", type=int, default=None,
    help="Number of Tor instances (default: 20, env: TORGRID_COUNT)",
)
parser.add_argument(
    "--auth-user", type=str, default="",
    help="SOCKS5 proxy username (enables auth on auth ports)",
)
parser.add_argument(
    "--auth-pass", type=str, default="",
    help="SOCKS5 proxy password",
)
parser.add_argument(
    "--auth-port-base", type=int, default=3738,
    help="Base port for authenticated SOCKS5 proxies (default: 3738)",
)
parser.add_argument(
    "--web-host", type=str, default=os.environ.get("TORGRID_WEB_HOST", "127.0.0.1"),
    help="Web UI bind address (default: 127.0.0.1)",
)
parser.add_argument(
    "--web-port", type=int, default=int(os.environ.get("TORGRID_WEB_PORT", "8080")),
    help="Web UI port (default: 8080)",
)
parser.add_argument(
    "--tor-bin", type=str, default="",
    help="Path to tor binary (default: auto-detect)",
)
ARGS = parser.parse_args()

# ─── Configuration ─────────────────────────────────────────

INSTANCE_COUNT = (
    ARGS.count
    or int(os.environ.get("TORGRID_COUNT", "20"))
)
SOCKS_BASE = 1738
AUTH_SOCKS_BASE = ARGS.auth_port_base
CONTROL_BASE = 18000
DATA_ROOT = Path(tempfile.gettempdir()) / "torgrid"
WEB_HOST = ARGS.web_host
WEB_PORT = ARGS.web_port
CIRCUIT_REBUILD = int(os.environ.get("TORGRID_REBUILD_INTERVAL", "600"))
MONITOR_INTERVAL = 15
RATE_LIMIT_WINDOW = 5
RESTART_BACKOFF = [30, 60, 120, 300]

PROXY_AUTH_USER = ARGS.auth_user
PROXY_AUTH_PASS = ARGS.auth_pass
PROXY_AUTH_ENABLED = bool(PROXY_AUTH_USER) and bool(PROXY_AUTH_PASS)

log = logging.getLogger("torgrid")


def find_tor_bin() -> str:
    """Locate the tor binary on this system."""
    if ARGS.tor_bin and os.path.isfile(ARGS.tor_bin):
        return ARGS.tor_bin
    candidates = ["tor", "tor.exe"]
    for name in candidates:
        for path in os.environ.get("PATH", "").split(os.pathsep):
            full = os.path.join(path, name)
            if os.path.isfile(full) and os.access(full, os.X_OK):
                return full
    common = [
        "/usr/sbin/tor",
        "/usr/bin/tor",
        "/usr/local/bin/tor",
        "C:\\Tor\\tor.exe",
        "C:\\Program Files\\Tor\\tor.exe",
        os.path.expanduser("~\\AppData\\Local\\Tor\\tor.exe"),
    ]
    for loc in common:
        if os.path.isfile(loc) and os.access(loc, os.X_OK):
            return loc
    return "tor"


TOR_BIN = os.environ.get("TORGRID_TOR_BIN") or find_tor_bin()


# ─── SOCKS5 Auth Proxy ────────────────────────────────────

class Socks5AuthProxy:
    """Minimal SOCKS5 proxy that requires username/password auth and
    forwards to a target SOCKS5 (Tor) port."""

    SOCKS5_VER = 5
    AUTH_USERPASS = 2
    AUTH_REJECT = 0xFF
    CMD_CONNECT = 1
    ATYP_IPV4 = 1
    ATYP_DOMAIN = 3
    ATYP_IPV6 = 4
    REP_SUCCESS = 0

    def __init__(self, listen_port: int, target_host: str, target_port: int,
                 username: str, password: str):
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.username = username
        self.password = password
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self):
        self._server = await asyncio.start_server(
            self._handle, host="127.0.0.1", port=self.listen_port,
        )

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    @property
    def proxy_url(self) -> str:
        return f"socks5://{self.username}:{self.password}@127.0.0.1:{self.listen_port}"

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            # 1. Auth negotiation
            data = await asyncio.wait_for(reader.readexactly(2), timeout=10)
            if data[0] != self.SOCKS5_VER:
                return
            nmethods = data[1]
            methods = await asyncio.wait_for(
                reader.readexactly(nmethods), timeout=5,
            )
            if self.AUTH_USERPASS not in methods:
                writer.write(struct.pack("!BB", self.SOCKS5_VER, self.AUTH_REJECT))
                await writer.drain()
                return

            writer.write(struct.pack("!BB", self.SOCKS5_VER, self.AUTH_USERPASS))
            await writer.drain()

            # 2. Username/password auth
            auth = await asyncio.wait_for(reader.readexactly(2), timeout=10)
            ulen = auth[1]
            uname = await asyncio.wait_for(reader.readexactly(ulen), timeout=5)
            plen_data = await asyncio.wait_for(reader.readexactly(1), timeout=5)
            plen = plen_data[0]
            passwd = await asyncio.wait_for(reader.readexactly(plen), timeout=5)

            if uname.decode(errors="replace") != self.username \
               or passwd.decode(errors="replace") != self.password:
                writer.write(struct.pack("!BB", 1, 1))  # auth failed
                await writer.drain()
                return

            writer.write(struct.pack("!BB", 1, 0))  # auth success
            await writer.drain()

            # 3. Request
            hdr = await asyncio.wait_for(reader.readexactly(4), timeout=10)
            if hdr[0] != self.SOCKS5_VER or hdr[1] != self.CMD_CONNECT:
                return

            atyp = hdr[3]
            if atyp == self.ATYP_IPV4:
                addr_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=5)
                addr = ".".join(str(b) for b in addr_bytes)
            elif atyp == self.ATYP_DOMAIN:
                dlen = (await asyncio.wait_for(reader.readexactly(1), timeout=5))[0]
                addr = (await asyncio.wait_for(
                    reader.readexactly(dlen), timeout=5,
                )).decode()
            elif atyp == self.ATYP_IPV6:
                addr_bytes = await asyncio.wait_for(reader.readexactly(16), timeout=5)
                addr = ":".join(f"{b:02x}" for b in addr_bytes)
            else:
                return

            port = struct.unpack(
                "!H",
                await asyncio.wait_for(reader.readexactly(2), timeout=5),
            )[0]

            # 4. Connect to Tor SOCKS and relay
            tor_reader, tor_writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_host, self.target_port),
                timeout=10,
            )

            # SOCKS5 handshake with Tor (no auth needed — our proxy handles it)
            tor_writer.write(struct.pack("!BBB", 5, 1, 0))  # version, 1 method, no auth
            await tor_writer.drain()
            tor_auth = await asyncio.wait_for(tor_reader.readexactly(2), timeout=10)
            if tor_auth[0] != 5 or tor_auth[1] != 0:
                tor_writer.close()
                return

            # Send CONNECT through Tor
            req = struct.pack("!BBBB", 5, 1, 0, atyp)
            if atyp == self.ATYP_IPV4:
                req += addr_bytes
            elif atyp == self.ATYP_DOMAIN:
                req += struct.pack("!B", dlen) + addr.encode()
            elif atyp == self.ATYP_IPV6:
                req += addr_bytes
            req += struct.pack("!H", port)
            tor_writer.write(req)
            await tor_writer.drain()
            resp = await asyncio.wait_for(tor_reader.readexactly(4), timeout=10)
            # Consume and forward bind addr from Tor response
            bind_atyp = resp[3]
            if bind_atyp == self.ATYP_IPV4:
                bind_rest = await asyncio.wait_for(tor_reader.readexactly(6), timeout=5)
            elif bind_atyp == self.ATYP_DOMAIN:
                bdlen = (await asyncio.wait_for(tor_reader.readexactly(1), timeout=5))[0]
                bind_rest = await asyncio.wait_for(tor_reader.readexactly(bdlen + 2), timeout=5)
                bind_rest = bytes([bdlen]) + bind_rest
            elif bind_atyp == self.ATYP_IPV6:
                bind_rest = await asyncio.wait_for(tor_reader.readexactly(18), timeout=5)
            else:
                tor_writer.close()
                return

            # Forward complete response to client
            writer.write(resp + bind_rest)
            await writer.drain()

            if resp[1] != self.REP_SUCCESS:
                tor_writer.close()
                return

            # 5. Bidirectional relay
            await asyncio.gather(
                self._relay(tor_reader, writer),
                self._relay(reader, tor_writer),
            )
            # Both directions finished — close both
            try:
                tor_writer.close()
            except Exception:
                pass
            try:
                writer.close()
            except Exception:
                pass

        except (asyncio.TimeoutError, ConnectionError, OSError,
                EOFError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _relay(self, src: asyncio.StreamReader,
                     dst: asyncio.StreamWriter,
                     close_on_done: bool = False):
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except Exception:
            pass
        finally:
            if close_on_done:
                try:
                    dst.close()
                except Exception:
                    pass


# ─── TorInstance ──────────────────────────────────────────

class TorInstance:
    """One Tor process with its own SOCKS5 proxy."""

    def __init__(self, idx: int, password: str):
        self.idx = idx
        self.socks_port = SOCKS_BASE + idx
        self.auth_port = AUTH_SOCKS_BASE + idx
        self.control_port = CONTROL_BASE + idx
        self.data_dir = DATA_ROOT / f"instance_{idx}"
        self.password = password
        self.process: Optional[Popen] = None
        self.controller: Optional[Controller] = None
        self.auth_proxy: Optional[Socks5AuthProxy] = None

        # Live stats
        self.exit_ip: Optional[str] = None
        self.exit_country: Optional[str] = None
        self.bandwidth_in: int = 0
        self.bandwidth_out: int = 0
        self.total_read: int = 0
        self.total_written: int = 0
        self.circuit_count: int = 0
        self.alive: bool = False
        self.error: Optional[str] = None
        self.started_at: Optional[float] = None
        self.last_newnym: Optional[float] = None
        self._last_read_total: int = 0
        self._last_written_total: int = 0
        self._restart_attempts: int = 0
        self._last_restart_attempt: float = 0

    @property
    def proxy_url(self) -> str:
        if PROXY_AUTH_ENABLED:
            return f"socks5://{PROXY_AUTH_USER}:{PROXY_AUTH_PASS}@127.0.0.1:{self.auth_port}"
        return f"socks5://127.0.0.1:{self.socks_port}"

    def hashed_password(self) -> str:
        """Generate Tor-compatible hashed control password."""
        result = __import__("subprocess").run(
            [TOR_BIN, "--hash-password", self.password],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if line.startswith("16:"):
                return line
        for line in result.stderr.strip().split("\n"):
            if "16:" in line:
                return line.strip()
        return result.stdout.strip().split("\n")[-1]

    def torrc_path(self) -> Path:
        return self.data_dir / "torrc"

    @property
    def uptime(self) -> float:
        if self.started_at and self.alive:
            return round(time.time() - self.started_at, 1)
        return 0.0

    def to_dict(self) -> dict:
        return {
            "id": self.idx,
            "proxy": self.proxy_url,
            "socks_port": self.socks_port,
            "control_port": self.control_port,
            "exit_ip": self.exit_ip,
            "exit_country": self.exit_country,
            "bandwidth_in": self.bandwidth_in,
            "bandwidth_out": self.bandwidth_out,
            "total_read": self.total_read,
            "total_written": self.total_written,
            "circuit_count": self.circuit_count,
            "uptime": self.uptime,
            "alive": self.alive,
            "error": self.error,
            "last_newnym": self.last_newnym,
            "auth_enabled": PROXY_AUTH_ENABLED,
        }


# ─── TorGrid Engine ───────────────────────────────────────

class TorGrid:
    """Manages a pool of Tor instances."""

    def __init__(self, count: int = INSTANCE_COUNT):
        self.count = count
        self.instances: list[TorInstance] = []
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None
        self._rebuild_task: Optional[asyncio.Task] = None
        self._revive_task: Optional[asyncio.Task] = None
        self._websockets: list[WebSocket] = []
        self._rate_limiter: dict[int, float] = {}

    # ─── Lifecycle ──────────────────────────────────────

    async def start(self):
        """Initialize and start all Tor instances."""
        self._kill_orphan_tors()
        DATA_ROOT.mkdir(parents=True, exist_ok=True)

        log.info("Starting %d Tor instances...", self.count)

        for idx in range(self.count):
            inst = TorInstance(idx, secrets.token_hex(16))
            self.instances.append(inst)

        tasks = [self._start_instance(inst) for inst in self.instances]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for inst, result in zip(self.instances, results):
            if isinstance(result, Exception):
                inst.alive = False
                inst.error = self._sanitize_error(result)
                log.warning("Instance %d FAILED: %s", inst.idx, inst.error)

        alive_count = sum(1 for i in self.instances if i.alive)
        log.info("%d/%d instances running", alive_count, self.count)

        # Start SOCKS5 auth proxies if credentials configured
        if PROXY_AUTH_ENABLED:
            log.info(
                "Starting auth proxies on ports %d-%d (user: %s)",
                AUTH_SOCKS_BASE, AUTH_SOCKS_BASE + self.count - 1,
                PROXY_AUTH_USER,
            )
            for inst in self.instances:
                if inst.alive:
                    proxy = Socks5AuthProxy(
                        listen_port=inst.auth_port,
                        target_host="127.0.0.1",
                        target_port=inst.socks_port,
                        username=PROXY_AUTH_USER,
                        password=PROXY_AUTH_PASS,
                    )
                    await proxy.start()
                    inst.auth_proxy = proxy

        self._running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        self._rebuild_task = asyncio.create_task(self._rebuild_loop())
        self._revive_task = asyncio.create_task(self._revive_loop())

    async def stop(self):
        """Shut down all Tor instances and background tasks."""
        self._running = False
        for task in [self._monitor_task, self._rebuild_task, self._revive_task]:
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        for inst in self.instances:
            if inst.auth_proxy:
                await inst.auth_proxy.stop()
            await self._stop_instance(inst)

        try:
            import shutil
            shutil.rmtree(str(DATA_ROOT), ignore_errors=True)
        except Exception:
            pass

        log.info("All instances stopped")

    @staticmethod
    def _kill_orphan_tors():
        """Kill any Tor processes left from previous runs."""
        if os.name == "nt":
            try:
                __import__("subprocess").run(
                    ["taskkill", "/f", "/im", "tor.exe"],
                    capture_output=True, timeout=5,
                )
            except Exception:
                pass
            return
        try:
            for proc in Path("/proc").iterdir():
                if not proc.name.isdigit():
                    continue
                try:
                    cmdline = (proc / "cmdline").read_text(errors="replace")
                    if "tor" in cmdline and "DataDirectory" in cmdline \
                       and str(DATA_ROOT) in cmdline:
                        os.kill(int(proc.name), signal.SIGKILL)
                except (OSError, IOError):
                    pass
        except Exception:
            pass

    @staticmethod
    def _sanitize_error(exc: Exception) -> str:
        msg = str(exc)
        msg = re.sub(r"/[\w/.-]*?/torgrid/", "<torgrid>/", msg)
        return msg[:200]

    # ─── Instance Management ────────────────────────────

    async def _start_instance(self, inst: TorInstance, retry: int = 0):
        """Spawn a single Tor process."""
        inst.data_dir.mkdir(parents=True, exist_ok=True)
        inst.error = None

        try:
            hashed_pw = inst.hashed_password()
        except Exception as e:
            raise RuntimeError(f"Password hashing failed: {e}")

        torrc = self._build_torrc(inst.idx, hashed_pw)
        with open(inst.torrc_path(), "w") as f:
            f.write(torrc)

        try:
            proc = await asyncio.create_subprocess_exec(
                TOR_BIN, "-f", str(inst.torrc_path()),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            inst.process = proc
            inst.started_at = time.time()

            await asyncio.sleep(2 + inst.idx * 0.15)

            connected = False
            for attempt in range(20 if retry == 0 else 30):
                try:
                    controller = Controller.from_port(port=inst.control_port)
                    controller.authenticate(password=inst.password)
                    inst.controller = controller
                    inst.alive = True
                    connected = True
                    break
                except Exception:
                    if inst.process.returncode is not None:
                        raise RuntimeError(
                            f"Tor process exited prematurely (code {inst.process.returncode})"
                        )
                    await asyncio.sleep(1.5)

            if not connected:
                raise RuntimeError(
                    f"Failed to connect to control port after "
                    f"{'20' if retry == 0 else '30'} attempts"
                )

        except Exception as e:
            inst.alive = False
            sanitized = self._sanitize_error(e)
            inst.error = sanitized
            raise RuntimeError(sanitized) from e

    def _build_torrc(self, idx: int, hashed_pw: str) -> str:
        data_dir = DATA_ROOT / f"instance_{idx}"
        # No Log lines — memory-only logging. Tor output goes to DEVNULL
        # and we monitor via the control port.
        return (
            f"# TorGrid instance {idx}\n"
            f"SocksPort 127.0.0.1:{SOCKS_BASE + idx}\n"
            f"ControlPort 127.0.0.1:{CONTROL_BASE + idx}\n"
            f"HashedControlPassword {hashed_pw}\n"
            f"DataDirectory {data_dir}\n"
            f"PidFile {data_dir}/tor.pid\n"
            f"SafeLogging 1\n"
            f"ClientOnly 1\n"
            f"ExitRelay 0\n"
            f"CircuitBuildTimeout 30\n"
            f"LearnCircuitBuildTimeout 0\n"
            f"MaxCircuitDirtiness {CIRCUIT_REBUILD}\n"
            f"NewCircuitPeriod {CIRCUIT_REBUILD // 2}\n"
            f"AvoidDiskWrites 1\n"
            f"DisableDebuggerAttachment 0\n"
            f"DNSPort 0\n"
        )

    async def _stop_instance(self, inst: TorInstance):
        """Kill a Tor process cleanly."""
        if inst.controller:
            try:
                inst.controller.signal(Signal.SHUTDOWN)
                await asyncio.sleep(1)
            except Exception:
                pass
            try:
                inst.controller.close()
            except Exception:
                pass
            inst.controller = None

        if inst.process and inst.process.returncode is None:
            try:
                inst.process.terminate()
                try:
                    await asyncio.wait_for(inst.process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    inst.process.kill()
                    await inst.process.wait()
            except Exception:
                pass

        inst.alive = False

    async def new_identity(self, idx: int) -> bool:
        """Request a new circuit (rate-limited)."""
        if idx < 0 or idx >= len(self.instances):
            raise HTTPException(404, "Instance not found")

        now = time.time()
        last = self._rate_limiter.get(idx, 0)
        if now - last < RATE_LIMIT_WINDOW:
            raise HTTPException(
                429, f"Rate limited — wait {RATE_LIMIT_WINDOW}s between rotations",
            )

        inst = self.instances[idx]
        if not inst.alive or not inst.controller:
            raise HTTPException(400, "Instance not available")

        try:
            inst.controller.signal(Signal.NEWNYM)
            inst.last_newnym = now
            self._rate_limiter[idx] = now
            await asyncio.sleep(1.5)
            inst.exit_ip = None
            inst.exit_country = None
            return True
        except Exception as e:
            inst.error = self._sanitize_error(e)
            raise HTTPException(500, f"New identity failed: {inst.error}")

    async def new_identity_all(self):
        results = []
        for idx in range(self.count):
            try:
                await self.new_identity(idx)
                results.append(True)
            except Exception:
                results.append(False)
        return results

    async def restart_instance(self, idx: int) -> bool:
        if idx < 0 or idx >= len(self.instances):
            raise HTTPException(404, "Instance not found")

        inst = self.instances[idx]
        # Stop auth proxy
        if inst.auth_proxy:
            await inst.auth_proxy.stop()
            inst.auth_proxy = None

        await self._stop_instance(inst)
        await asyncio.sleep(2)

        try:
            await self._start_instance(inst, retry=1)
            inst._restart_attempts = 0
            # Restart auth proxy
            if PROXY_AUTH_ENABLED:
                proxy = Socks5AuthProxy(
                    listen_port=inst.auth_port,
                    target_host="127.0.0.1",
                    target_port=inst.socks_port,
                    username=PROXY_AUTH_USER,
                    password=PROXY_AUTH_PASS,
                )
                await proxy.start()
                inst.auth_proxy = proxy
            return True
        except Exception as e:
            inst.alive = False
            inst.error = self._sanitize_error(e)
            raise HTTPException(500, f"Restart failed: {inst.error}")

    # ─── Background Monitoring ─────────────────────────

    async def _monitor_loop(self):
        while self._running:
            for inst in self.instances:
                if not inst.alive:
                    continue
                try:
                    try:
                        info = await self._resolve_ip(inst)
                        if info:
                            inst.exit_ip = info.get("ip", inst.exit_ip)
                            inst.exit_country = info.get("country", inst.exit_country)
                    except Exception:
                        pass

                    try:
                        circuits = inst.controller.get_circuits()
                        inst.circuit_count = sum(
                            1 for c in circuits if c.status == "BUILT"
                        )
                    except Exception:
                        pass

                    try:
                        new_read = int(inst.controller.get_info("traffic/read", "0"))
                        new_written = int(
                            inst.controller.get_info("traffic/written", "0"),
                        )

                        if inst._last_read_total > 0:
                            dt = MONITOR_INTERVAL
                            raw_in = max(0, (new_read - inst._last_read_total)) // dt
                            raw_out = max(
                                0, (new_written - inst._last_written_total),
                            ) // dt
                            inst.bandwidth_in = int(
                                0.4 * raw_in + 0.6 * inst.bandwidth_in,
                            )
                            inst.bandwidth_out = int(
                                0.4 * raw_out + 0.6 * inst.bandwidth_out,
                            )

                        inst.total_read = new_read
                        inst.total_written = new_written
                        inst._last_read_total = new_read
                        inst._last_written_total = new_written
                    except Exception:
                        pass

                    if inst.process and inst.process.returncode is not None:
                        inst.alive = False
                        inst.error = f"Exit code {inst.process.returncode}"

                except Exception as e:
                    inst.alive = False
                    inst.error = self._sanitize_error(e)

            await self._broadcast_state()
            await asyncio.sleep(MONITOR_INTERVAL)

    async def _revive_loop(self):
        while self._running:
            now = time.time()
            for inst in self.instances:
                if inst.alive:
                    inst._restart_attempts = 0
                    continue
                if not inst.error:
                    continue

                delay = RESTART_BACKOFF[
                    min(inst._restart_attempts, len(RESTART_BACKOFF) - 1)
                ]
                if now - inst._last_restart_attempt < delay:
                    continue

                inst._last_restart_attempt = now
                inst._restart_attempts += 1
                log.info(
                    "Reviving instance %d (attempt %d)...",
                    inst.idx, inst._restart_attempts,
                )
                if inst.auth_proxy:
                    await inst.auth_proxy.stop()
                    inst.auth_proxy = None
                await self._stop_instance(inst)
                await asyncio.sleep(1)
                try:
                    await self._start_instance(inst, retry=1)
                    if PROXY_AUTH_ENABLED:
                        proxy = Socks5AuthProxy(
                            listen_port=inst.auth_port,
                            target_host="127.0.0.1",
                            target_port=inst.socks_port,
                            username=PROXY_AUTH_USER,
                            password=PROXY_AUTH_PASS,
                        )
                        await proxy.start()
                        inst.auth_proxy = proxy
                    log.info("  -> Instance %d revived", inst.idx)
                except Exception as e:
                    log.warning("  -> Instance %d revive failed: %s", inst.idx, e)

            await asyncio.sleep(15)

    async def _resolve_ip(self, inst: TorInstance) -> Optional[dict]:
        """Get exit IP and country through this Tor instance."""
        for url in ("http://ip-api.com/json/", "https://check.torproject.org/"):
            try:
                connector = SOCKSConnector(
                    host="127.0.0.1", port=inst.socks_port, rdns=True,
                )
                timeout = aiohttp.ClientTimeout(total=20, connect=10)
                async with aiohttp.ClientSession(
                    connector=connector, timeout=timeout,
                ) as session:
                    async with session.get(url) as resp:
                        if resp.status != 200:
                            continue
                        if "ip-api" in url:
                            data = await resp.json()
                            if data.get("query"):
                                return {
                                    "ip": data["query"],
                                    "country": data.get("countryCode", ""),
                                }
                        else:
                            text = await resp.text()
                            m = re.search(
                                r"Your IP address appears to be: <strong>([^<]+)</strong>",
                                text,
                            )
                            if m:
                                return {
                                    "ip": m.group(1),
                                    "country": inst.exit_country or "",
                                }
            except Exception:
                continue
        return None

    async def _rebuild_loop(self):
        while self._running:
            await asyncio.sleep(CIRCUIT_REBUILD)
            log.info("Rebuilding circuits...")
            await self.new_identity_all()

    # ─── WebSocket ──────────────────────────────────────

    async def _broadcast_state(self):
        state = {
            "type": "state",
            "instances": [inst.to_dict() for inst in self.instances],
            "aggregate": self.aggregate_stats(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        dead = []
        for ws in self._websockets:
            try:
                await ws.send_json(state)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._websockets.remove(ws)

    def register_ws(self, ws: WebSocket):
        self._websockets.append(ws)

    def unregister_ws(self, ws: WebSocket):
        self._websockets[:] = [w for w in self._websockets if w is not ws]

    # ─── Stats ─────────────────────────────────────────

    def aggregate_stats(self) -> dict:
        alive = [i for i in self.instances if i.alive]
        uptimes = [i.uptime for i in alive]
        max_uptime = max(uptimes) if uptimes else 0
        return {
            "total": self.count,
            "alive": len(alive),
            "dead": self.count - len(alive),
            "total_bandwidth_in": sum(i.bandwidth_in for i in alive),
            "total_bandwidth_out": sum(i.bandwidth_out for i in alive),
            "total_read": sum(i.total_read for i in alive),
            "total_written": sum(i.total_written for i in alive),
            "total_circuits": sum(i.circuit_count for i in alive),
            "uptime": round(max_uptime, 1),
            "proxy_list": [i.proxy_url for i in self.instances],
            "auth_enabled": PROXY_AUTH_ENABLED,
        }


# ─── FastAPI App ────────────────────────────────────────────

grid: Optional[TorGrid] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global grid
    TorGrid._kill_orphan_tors()
    grid = TorGrid(count=INSTANCE_COUNT)
    await grid.start()
    yield
    await grid.stop()


app = FastAPI(title="TorGrid", docs_url=None, redoc_url=None, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_credentials=False,
    allow_methods=[],
    allow_headers=[],
)

HTML_PATH = Path(__file__).parent / "static" / "index.html"


@app.get("/", response_class=HTMLResponse)
async def root():
    if HTML_PATH.exists():
        return HTML_PATH.read_text(encoding="utf-8")
    return "<h1>TorGrid</h1><p>UI not found</p>"


@app.get("/api/instances")
async def get_instances():
    if not grid:
        raise HTTPException(503, "System starting…")
    return {"instances": [inst.to_dict() for inst in grid.instances]}


@app.get("/api/stats")
async def get_stats():
    if not grid:
        raise HTTPException(503, "System starting…")
    return grid.aggregate_stats()


@app.get("/api/proxies")
async def get_proxies():
    if not grid:
        raise HTTPException(503, "System starting…")
    return {"proxies": [inst.proxy_url for inst in grid.instances]}


@app.post("/api/instances/{idx}/new-identity")
async def api_new_identity(idx: int):
    if not grid:
        raise HTTPException(503, "System starting…")
    return await grid.new_identity(idx)


@app.post("/api/new-identity-all")
async def api_new_identity_all():
    if not grid:
        raise HTTPException(503, "System starting…")
    results = await grid.new_identity_all()
    return {"status": "ok", "results": results}


@app.post("/api/instances/{idx}/restart")
async def api_restart(idx: int):
    if not grid:
        raise HTTPException(503, "System starting…")
    return await grid.restart_instance(idx)


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    if grid:
        grid.register_ws(ws)
        try:
            state = {
                "type": "state",
                "instances": [inst.to_dict() for inst in grid.instances],
                "aggregate": grid.aggregate_stats(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            await ws.send_json(state)
        except Exception:
            pass
    try:
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_json({"type": "pong"})
    except WebSocketDisconnect:
        pass
    finally:
        if grid:
            grid.unregister_ws(ws)


# ─── Entry Point ────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    print(f"███ TorGrid v1.2 ███")
    print(f"Instances: {INSTANCE_COUNT}")
    print(f"SOCKS:     {SOCKS_BASE}-{SOCKS_BASE + INSTANCE_COUNT - 1}")
    if PROXY_AUTH_ENABLED:
        print(f"Auth:      {AUTH_SOCKS_BASE}-{AUTH_SOCKS_BASE + INSTANCE_COUNT - 1}  user={PROXY_AUTH_USER}")
    print(f"Web UI:    http://{WEB_HOST}:{WEB_PORT}")
    print(f"Tor bin:   {TOR_BIN}")
    print(f"Data:      {DATA_ROOT}")
    print(f"Logging:   memory-only (no files)")
    uvicorn.run(app, host=WEB_HOST, port=WEB_PORT, log_level="info")
