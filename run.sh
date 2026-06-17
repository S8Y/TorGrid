#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
echo "=== TorGrid ==="
pip install -q -r requirements.txt 2>/dev/null
python3 torgrid.py "$@"
