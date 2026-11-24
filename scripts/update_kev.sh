#!/usr/bin/env bash
#
# Refresh the local CISA KEV (Known Exploited Vulnerabilities) catalog used for
# OFFLINE exploit-correlation enrichment.
#
# The running ExploitLink app NEVER fetches this itself — it only reads the local
# mirror. Run this script out-of-band (e.g. nightly cron, or before a demo) so
# scans stay fully offline while the data is kept current. This mirrors the
# "searchsploit -u" / "nuclei -update-templates" maintenance pattern.
#
# Usage:  bash scripts/update_kev.sh
#
set -euo pipefail

FEED_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Resolve <repo>/app/data/kev regardless of where the script is invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/app/data/kev"
DEST_FILE="$DEST_DIR/known_exploited_vulnerabilities.json"

mkdir -p "$DEST_DIR"

echo "[KEV] Downloading CISA KEV feed..."
echo "[KEV]   $FEED_URL"

TMP="$DEST_FILE.tmp"
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$FEED_URL" -o "$TMP"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TMP" "$FEED_URL"
else
    echo "[KEV] ERROR: neither curl nor wget is installed." >&2
    exit 1
fi

# Sanity-check it's valid JSON with the expected shape before replacing.
if command -v python3 >/dev/null 2>&1; then
    COUNT="$(python3 - "$TMP" <<'PY'
import json, sys
with open(sys.argv[1]) as fh:
    data = json.load(fh)
vulns = data.get("vulnerabilities", [])
assert isinstance(vulns, list) and vulns, "no vulnerabilities array"
print(len(vulns))
PY
)"
    echo "[KEV] Validated catalog: $COUNT known-exploited CVEs."
fi

mv "$TMP" "$DEST_FILE"
echo "[KEV] Saved to $DEST_FILE"
echo "[KEV] Done. The next scan's correlation will use the refreshed catalog."
