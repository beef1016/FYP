#!/usr/bin/env bash
#
# Native (venv) launcher — starts Caddy (HTTPS on :443) and the Flask app
# (loopback :5000) together in ONE terminal. Ctrl+C stops both.
#
# Prereqs on Kali:
#   python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
#   sudo apt install -y caddy libnss3-tools nmap nuclei whatweb gobuster exploitdb dirb
#
# Usage:
#   EXPLOITLINK_AUTH_PASSWORD='your-strong-password' ./start.sh
#
set -euo pipefail

# Password is mandatory (run.py refuses to start without it).
: "${EXPLOITLINK_AUTH_PASSWORD:?Set EXPLOITLINK_AUTH_PASSWORD before running (e.g. EXPLOITLINK_AUTH_PASSWORD=secret ./start.sh)}"

export FLASK_APP=run.py
# Lab mode by default so RFC1918/LAN targets (Metasploitable) are allowed.
export EXPLOITLINK_ALLOW_PRIVATE_TARGETS="${EXPLOITLINK_ALLOW_PRIVATE_TARGETS:-true}"

# Stop Caddy when this script exits (so Ctrl+C on Flask cleans up both).
trap 'echo; echo "[*] Stopping Caddy..."; sudo caddy stop 2>/dev/null || true' EXIT

echo "[*] Starting Caddy (HTTPS reverse proxy, :443 -> 127.0.0.1:5000)..."
sudo caddy start --config Caddyfile

echo "[*] Applying database migrations..."
venv/bin/flask db upgrade

echo "[*] ExploitLink is up — open https://localhost/  (Ctrl+C to stop both)"
venv/bin/python run.py
