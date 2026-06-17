# TorGrid — Multi-Tor SOCKS5 Proxy Pool

Spawns N isolated Tor instances, each on its own SOCKS5 port with a unique exit IP.
Provides a real-time Web dashboard for monitoring, management and stats.
 
<img width="1543" height="972" alt="{40656FB6-6234-4A2F-B848-B4763B6F80C7}" src="https://github.com/user-attachments/assets/8eed6435-ecbc-48c4-8a5a-9703c1e80cce" />
 

```
                ┌─ Tor #0  (127.0.0.1:1738)
                ├─ Tor #1  (127.0.0.1:1739)
Client ──→ HTTP─┼─ Tor #2  (127.0.0.1:1740)   20 unique exit IPs
                ├─ ...
                └─ Tor #19 (127.0.0.1:1757)
```

## Quick Start

### Linux / macOS
```bash
# 1. Install Tor
apt install -y tor          # Debian/Ubuntu
brew install tor            # macOS

# 2. Install Python deps
pip3 install -r requirements.txt

# 3. Start TorGrid (20 instances default)
python3 torgrid.py

# Or with custom count:
TORGRID_COUNT=10 python3 torgrid.py        # env var
python3 torgrid.py -c 10                   # or CLI flag

# With SOCKS5 proxy authentication:
python3 torgrid.py --auth-user myuser --auth-pass mypass

# Full example: 15 instances with auth on ports 5000+
python3 torgrid.py -c 15 --auth-user tor --auth-pass hunter2 --auth-port-base 5000
```

### Windows
```powershell
# 1. Install Tor from https://www.torproject.org/download/tor/
#    Make sure tor.exe is in your PATH

# 2. Install Python deps
pip install -r requirements.txt

# 3. Start TorGrid
python torgrid.py

# Or with custom count:
$env:TORGRID_COUNT=10; python torgrid.py
```

### 3. Open the dashboard
```
http://127.0.0.1:8080
```

## Port Layout

| Service | Range | Description |
|---------|-------|-------------|
| SOCKS5 proxies | 1738–1757 | 20 Tor SOCKS5 endpoints |
| Control ports | 18000–18019 | Stem monitoring (internal) |
| Web UI | 8080 | Dashboard + API |

## Architecture

**Backend (Python + FastAPI):**
- `TorGrid` class spawns/manages N Tor processes via asyncio
- Each Tor instance gets an isolated DataDirectory, torrc, SocksPort, ControlPort
- Background monitor loop checks health, exit IPs, bandwidth every 15s
- Periodic circuit rebuild (NEWNYM) every 10 minutes
- WebSocket pushes real-time state to all connected dashboard clients

**Frontend (single-page HTML/CSS/JS):**
- Dark cyberpunk theme with glass morphism cards
- Real-time WebSocket updates (no page refresh needed)
- Per-instance status cards: IP, country, bandwidth, circuits, uptime
- Aggregate stats bar: alive/dead count, total bandwidth, circuits, uptime
- Proxy list bar with one-click "Copy All" button
- Filter/search instances by IP, port, or status
- Individual "New Identity" and "Restart" buttons per instance

**Design influences:**
- Glass morphism with multi-layer shadow stacks (frontier-ui §16)
- Ambient scan-line overlay on cards
- Breathing/pulse animations on live indicators
- Dark cyberpunk palette with cyan/purple/rose accents
- Click ripple feedback on interactive elements

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Web UI dashboard |
| GET | `/api/instances` | All instance details (JSON) |
| GET | `/api/stats` | Aggregate stats |
| GET | `/api/proxies` | Clean SOCKS5 proxy list |
| POST | `/api/instances/{idx}/new-identity` | Rotate one circuit |
| POST | `/api/new-identity-all` | Rotate all circuits |
| POST | `/api/instances/{idx}/restart` | Restart one instance |
| WS | `/ws` | Real-time state stream |

### Proxies endpoint (for scripting)

```bash
# Get clean list for importing into other tools
curl -s http://127.0.0.1:8080/api/proxies | jq -r '.proxies[]'

# Output:
# socks5://127.0.0.1:1738
# socks5://127.0.0.1:1739
# ...
```

## Configuration

All via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `TORGRID_COUNT` | `20` | Number of Tor instances to spawn |
| `WEB_HOST` | `127.0.0.1` | Web UI bind address (change to `0.0.0.0` for remote) |
| `WEB_PORT` | `8080` | Web UI port |

Change defaults by editing the top of `torgrid.py`.

## Security

- **Web UI binds to 127.0.0.1 only** by default — not exposed to network
- Each Tor instance uses a **unique random password** for its control port
- Tor instances are configured as **ClientOnly** — no exit relay
- **No PII logged** — SafeLogging enabled, no identifying info in Tor logs
- **DNS through Tor** — all lookups go through Tor's own DNS
- Data directories are isolated per-instance under `/tmp/torgrid/`

## Resource Usage (20 Instances)

| Resource | Estimate |
|----------|----------|
| RAM | ~600MB–1GB (30-50MB per Tor) |
| CPU | Low after bootstrapping |
| Boot time | ~60s (parallel) |
| Disk | ~50MB (log files, cached descriptors) |

The main constraint is **RAM per Tor instance**. Each Tor maintains its own network consensus, circuit state, and descriptor cache. On memory-constrained systems, reduce `TORGRID_COUNT`.

## Use Cases

- **Web scraping** with IP rotation (each request lands on a different exit)
- **Privacy-respecting API testing** through multiple anonymity channels
- **Geolocation testing** (Tor exits from different countries)
- **Load testing / distributed crawling** with parallel SOCKS endpoints
- **Penetration testing** where source IP diversity matters

## Known Limitations

- Tor exit nodes are blocked by Cloudflare, Google, banking sites
- Each circuit is slower than VPN (3-hop relay) — expect 200ms-5s latency
- Some sites return CAPTCHAs for Tor traffic — use `--ExitNodes {country}` to limit
- 20 instances × 50MB = ~1GB RAM minimum
- Tor circuits rotate every ~10 min by default (configurable)

## File Structure

```
torgrid/
├── torgrid.py          # Backend: Tor manager + FastAPI + WebSocket
├── static/
│   └── index.html      # Web UI (single-page app)
├── requirements.txt    # Python deps
└── run.sh              # Quick-start script
```

## Comparison to Existing Tools

| Feature | TorGrid | multitor | torpool | rotating-tor-http-proxy |
|---------|---------|----------|---------|------------------------|
| SOCKS5 proxy pool | ✓ | ✓ | ✓ | ✗ (HTTP only) |
| Real-time Web UI | ✓ | ✗ | ✗ (HAProxy stats) | ✗ (HAProxy stats) |
| Per-instance control | ✓ | ✓ | ✗ | ✗ |
| IP/bandwidth monitoring | ✓ | ✗ | ✗ | ✗ |
| Copy proxy list | ✓ | ✗ | ✗ | ✗ |
| Filter/search | ✓ | ✗ | ✗ | ✗ |
| REST API | ✓ | ✗ | ✗ | ✗ |

## License

MIT
