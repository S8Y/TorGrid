#!/usr/bin/env bash
# TorGrid — Quick start
set -euo pipefail

echo "=== TorGrid ==="
echo ""

# Check tor
if ! command -v tor &>/dev/null; then
    echo "ERROR: tor not found. Install with: apt install -y tor"
    exit 1
fi

# Kill any old tor daemons
echo "[+] Stopping system Tor if running..."
systemctl stop tor@default 2>/dev/null || true
systemctl mask tor@default 2>/dev/null || true
killall -9 tor 2>/dev/null || true
sleep 1

# Install deps
echo "[+] Installing Python deps..."
pip3 install -q -r "$(dirname "$0")/requirements.txt" 2>&1 | tail -2

# Clean old state
rm -rf /tmp/torgrid

# Fire it up
COUNT=${TORGRID_COUNT:-20}
echo "[+] Starting TorGrid with ${COUNT} instances..."
echo "    SOCKS ports: $((1738))-$((1738 + COUNT - 1))"
echo "    Web UI:      http://127.0.0.1:8080"
echo ""

cd "$(dirname "$0")"
TORGRID_COUNT=$COUNT exec python3 torgrid.py
