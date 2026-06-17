#!/usr/bin/env python3
"""
TorGrid — Multi-Tor SOCKS5 Proxy Pool with Web Dashboard
=========================================================
Spawns N isolated Tor instances, each on its own SOCKS5 port.
Provides a polished real-time Web UI for monitoring, management and stats.

Port layout:
  SOCKS proxies:  127.0.0.1:1738 + N  (1738..1757 for 20 instances)
  Control ports:  127.0.0.1:18000 + N (for stem monitoring)
  Web UI:         http://127.0.0.1:8080
"""

from __future__ import annotations

import asyncio
import os
import re
import secrets
import signal
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

# ─── Configuration ─────────────────────────────────────────────

INSTANCE_COUNT   = int(os.environ.get("TORGRID_COUNT", "20"))
SOCKS_BASE       = 1738
CONTROL_BASE     = 18000
DATA_ROOT        = Path("/tmp/torgrid")
WEB_HOST         = os.environ.get("TORGRID_WEB_HOST", "127.0.0.1")
WEB_PORT         = int(os.environ.get("TORGRID_WEB_PORT", "8080"))
TOR_BIN          = "/usr/sbin/tor"
CIRCUIT_REBUILD  = int(os.environ.get("TORGRID_REBUILD_INTERVAL", "600"))
MONITOR_INTERVAL = 15
RATE_LIMIT_WINDOW = 5          # seconds between new-identity calls per instance
RESTART_BACKOFF   = [30, 60, 120, 300]  # progressive delay before retry

# ─── TorInstance ──────────────────────────────────────────────

class TorInstance:
    """One Tor process with its own SOCKS5 proxy."""

    def __init__(self, idx: int, password: str):
        self.idx = idx
        self.socks_port = SOCKS_BASE + idx
        self.control_port = CONTROL_BASE + idx
        self.data_dir = DATA_ROOT / f"instance_{idx}"
        self.password = password
        self.process: Optional[Popen] = None
        self.controller: Optional[Controller] = None

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
        self._last_bw_in: int = 0
        self._last_bw_out: int = 0
        self._last_read_total: int = 0
        self._last_written_total: int = 0
        self._restart_attempts: int = 0
        self._last_restart_attempt: float = 0

    @property
    def proxy_url(self) -> str:
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

    def log_path(self) -> Path:
        return self.data_dir / "tor.log"

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
        }


# ─── TorGrid Engine ───────────────────────────────────────────

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
        self._rate_limiter: dict[int, float] = {}  # idx -> last newnym time

    # ─── Lifecycle ──────────────────────────────────────────

    async def start(self):
        """Initialize and start all Tor instances."""
        # Clean up orphans from previous runs
        self._kill_orphan_tors()
        DATA_ROOT.mkdir(parents=True, exist_ok=True)

        print(f"[TorGrid] Starting {self.count} Tor instances...")

        for idx in range(self.count):
            inst = TorInstance(idx, secrets.token_hex(16))
            self.instances.append(inst)

        tasks = [self._start_instance(inst) for inst in self.instances]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for inst, result in zip(self.instances, results):
            if isinstance(result, Exception):
                inst.alive = False
                inst.error = self._sanitize_error(result)
                print(f"  [TorGrid] Instance {inst.idx} FAILED: {inst.error}")

        alive = sum(1 for i in self.instances if i.alive)
        print(f"[TorGrid] {alive}/{self.count} instances running")

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
            await self._stop_instance(inst)

        # Clean up data dirs
        try:
            import shutil
            shutil.rmtree(str(DATA_ROOT), ignore_errors=True)
        except Exception:
            pass

        print("[TorGrid] All instances stopped")

    @staticmethod
    def _kill_orphan_tors():
        """Kill any Tor processes left from previous runs that we spawned."""
        import signal as sig
        try:
            for proc in Path("/proc").iterdir():
                if not proc.name.isdigit():
                    continue
                try:
                    cmdline = (proc / "cmdline").read_text(errors="replace")
                    if "tor" in cmdline and "DataDirectory" in cmdline and str(DATA_ROOT) in cmdline:
                        os.kill(int(proc.name), sig.SIGKILL)
                except (OSError, IOError):
                    pass
        except Exception:
            pass

    @staticmethod
    def _sanitize_error(exc: Exception) -> str:
        """Return a safe error message without internal paths."""
        msg = str(exc)
        # Remove absolute paths
        msg = re.sub(r"/[\w/.-]*?/torgrid/", "<torgrid>/", msg)
        return msg[:200]

    # ─── Instance Management ────────────────────────────────

    async def _start_instance(self, inst: TorInstance, retry: int = 0):
        """Spawn a single Tor process with its own config."""
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

            # Stagger startup to avoid thundering herd on Tor network
            await asyncio.sleep(2 + inst.idx * 0.15)

            # Connect controller with timeout
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
        return (
            f"# TorGrid instance {idx}\n"
            f"SocksPort 127.0.0.1:{SOCKS_BASE + idx}\n"
            f"ControlPort 127.0.0.1:{CONTROL_BASE + idx}\n"
            f"HashedControlPassword {hashed_pw}\n"
            f"DataDirectory {DATA_ROOT / f'instance_{idx}'}\n"
            f"PidFile {DATA_ROOT / f'instance_{idx}' / 'tor.pid'}\n"
            f"Log warn file {DATA_ROOT / f'instance_{idx}' / 'tor.log'}\n"
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
        """Request a new circuit for one instance (rate-limited)."""
        if idx < 0 or idx >= len(self.instances):
            raise HTTPException(404, "Instance not found")

        now = time.time()
        last = self._rate_limiter.get(idx, 0)
        if now - last < RATE_LIMIT_WINDOW:
            raise HTTPException(429, f"Rate limited — wait {RATE_LIMIT_WINDOW}s between rotations")

        inst = self.instances[idx]
        if not inst.alive or not inst.controller:
            raise HTTPException(400, "Instance not available")

        try:
            inst.controller.signal(Signal.NEWNYM)
            inst.last_newnym = now
            self._rate_limiter[idx] = now
            await asyncio.sleep(1.5)
            # Clear cached IP so monitor refreshes it
            inst.exit_ip = None
            inst.exit_country = None
            return True
        except Exception as e:
            inst.error = self._sanitize_error(e)
            raise HTTPException(500, f"New identity failed: {inst.error}")

    async def new_identity_all(self):
        """Rotate all identities."""
        results = []
        for idx in range(self.count):
            try:
                await self.new_identity(idx)
                results.append(True)
            except Exception:
                results.append(False)
        return results

    async def restart_instance(self, idx: int) -> bool:
        """Restart a single Tor instance."""
        if idx < 0 or idx >= len(self.instances):
            raise HTTPException(404, "Instance not found")

        inst = self.instances[idx]
        await self._stop_instance(inst)
        await asyncio.sleep(2)

        try:
            await self._start_instance(inst, retry=1)
            inst._restart_attempts = 0
            return True
        except Exception as e:
            inst.alive = False
            inst.error = self._sanitize_error(e)
            raise HTTPException(500, f"Restart failed: {inst.error}")

    # ─── Background Monitoring ─────────────────────────────

    async def _monitor_loop(self):
        """Periodically check health, IPs, and bandwidth."""
        while self._running:
            for inst in self.instances:
                if not inst.alive:
                    continue

                try:
                    # Exit IP + country (try ip-api first for country)
                    try:
                        info = await self._resolve_ip(inst)
                        if info:
                            inst.exit_ip = info.get("ip", inst.exit_ip)
                            inst.exit_country = info.get("country", inst.exit_country)
                    except Exception:
                        pass

                    # Circuits
                    try:
                        circuits = inst.controller.get_circuits()
                        inst.circuit_count = sum(
                            1 for c in circuits if c.status == "BUILT"
                        )
                    except Exception:
                        pass

                    # Bandwidth (smoothed)
                    try:
                        new_read = int(inst.controller.get_info("traffic/read", "0"))
                        new_written = int(inst.controller.get_info("traffic/written", "0"))

                        if inst._last_read_total > 0:
                            dt = MONITOR_INTERVAL
                            raw_in = max(0, (new_read - inst._last_read_total)) // dt
                            raw_out = max(0, (new_written - inst._last_written_total)) // dt
                            # Exponential moving average (alpha=0.4)
                            inst.bandwidth_in = int(0.4 * raw_in + 0.6 * inst.bandwidth_in)
                            inst.bandwidth_out = int(0.4 * raw_out + 0.6 * inst.bandwidth_out)

                        inst.total_read = new_read
                        inst.total_written = new_written
                        inst._last_read_total = new_read
                        inst._last_written_total = new_written
                    except Exception:
                        pass

                    # Process health
                    if inst.process and inst.process.returncode is not None:
                        inst.alive = False
                        inst.error = f"Exit code {inst.process.returncode}"

                except Exception as e:
                    inst.alive = False
                    inst.error = self._sanitize_error(e)

            await self._broadcast_state()
            await asyncio.sleep(MONITOR_INTERVAL)

    async def _revive_loop(self):
        """Periodically attempt to restart dead instances with backoff."""
        while self._running:
            now = time.time()
            for inst in self.instances:
                if inst.alive:
                    inst._restart_attempts = 0
                    continue
                if not inst.error:
                    continue  # freshly started, give it time

                delay = RESTART_BACKOFF[
                    min(inst._restart_attempts, len(RESTART_BACKOFF) - 1)
                ]
                if now - inst._last_restart_attempt < delay:
                    continue

                inst._last_restart_attempt = now
                inst._restart_attempts += 1
                print(f"[TorGrid] Reviving instance {inst.idx} "
                      f"(attempt {inst._restart_attempts})...")
                await self._stop_instance(inst)
                await asyncio.sleep(1)
                try:
                    await self._start_instance(inst, retry=1)
                    print(f"  -> Instance {inst.idx} revived")
                except Exception as e:
                    print(f"  -> Instance {inst.idx} revive failed: {e}")

            await asyncio.sleep(15)

    async def _resolve_ip(self, inst: TorInstance) -> Optional[dict]:
        """Get exit IP (and country) through this Tor instance."""
        # Primary: ip-api gives both IP and country
        try:
            connector = SOCKSConnector(
                host="127.0.0.1", port=inst.socks_port, rdns=True
            )
            timeout = aiohttp.ClientTimeout(total=20, connect=10)
            async with aiohttp.ClientSession(
                connector=connector, timeout=timeout
            ) as session:
                async with session.get("http://ip-api.com/json/") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("query"):
                            return {
                                "ip": data["query"],
                                "country": data.get("countryCode", ""),
                            }
        except Exception:
            pass

        # Fallback: check.torproject.org (IP only)
        try:
            connector = SOCKSConnector(
                host="127.0.0.1", port=inst.socks_port, rdns=True
            )
            timeout = aiohttp.ClientTimeout(total=20, connect=10)
            async with aiohttp.ClientSession(
                connector=connector, timeout=timeout
            ) as session:
                async with session.get("https://check.torproject.org/") as resp:
                    text = await resp.text()
                    m = re.search(
                        r"Your IP address appears to be: <strong>([^<]+)</strong>",
                        text,
                    )
                    if m:
                        return {"ip": m.group(1), "country": inst.exit_country or ""}
        except Exception:
            pass

        return None

    async def _rebuild_loop(self):
        """Periodically rebuild all circuits."""
        while self._running:
            await asyncio.sleep(CIRCUIT_REBUILD)
            print(f"[TorGrid] Rebuilding circuits...")
            await self.new_identity_all()

    # ─── WebSocket ──────────────────────────────────────────

    async def _broadcast_state(self):
        """Push state to all connected WebSocket clients."""
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

    # ─── Stats ─────────────────────────────────────────────

    def aggregate_stats(self) -> dict:
        alive = [i for i in self.instances if i.alive]
        dead = [i for i in self.instances if not i.alive]
        uptimes = [i.uptime for i in alive]
        max_uptime = max(uptimes) if uptimes else 0
        return {
            "total": self.count,
            "alive": len(alive),
            "dead": len(dead),
            "total_bandwidth_in": sum(i.bandwidth_in for i in alive),
            "total_bandwidth_out": sum(i.bandwidth_out for i in alive),
            "total_read": sum(i.total_read for i in alive),
            "total_written": sum(i.total_written for i in alive),
            "total_circuits": sum(i.circuit_count for i in alive),
            "uptime": round(max_uptime, 1),
            "proxy_list": [i.proxy_url for i in self.instances],
        }


# ─── FastAPI App ────────────────────────────────────────────

grid: Optional[TorGrid] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global grid
    # Kill orphan Tor processes from any previous run
    TorGrid._kill_orphan_tors()
    grid = TorGrid(count=INSTANCE_COUNT)
    await grid.start()
    yield
    await grid.stop()


app = FastAPI(title="TorGrid", docs_url=None, redoc_url=None, lifespan=lifespan)

# Restrictive CORS — same-origin by default
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
        return HTML_PATH.read_text()
    return "<h1>TorGrid</h1><p>UI not found — ensure static/index.html exists</p>"


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
        # Push initial state immediately
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

    print(f"███ TorGrid v1.1 ███")
    print(f"Instances: {INSTANCE_COUNT}")
    print(f"SOCKS:     {SOCKS_BASE}-{SOCKS_BASE + INSTANCE_COUNT - 1}")
    print(f"Web UI:    http://{WEB_HOST}:{WEB_PORT}")
    print(f"Data:      {DATA_ROOT}")
    uvicorn.run(app, host=WEB_HOST, port=WEB_PORT, log_level="info")
