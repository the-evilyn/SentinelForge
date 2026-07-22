#!/usr/bin/env bash
#
# Generate benign attack telemetry against the LAB target so you can watch the
# detections fire end-to-end. Safe by design: it only hits the local DVWA
# container and a throwaway SSH endpoint. Do NOT point this at anything you do
# not own.
#
# Usage: ./scripts/simulate-attack.sh [target_host] [web_port]
set -euo pipefail

TARGET="${1:-localhost}"
WEB_PORT="${2:-8080}"
BASE_URL="http://${TARGET}:${WEB_PORT}"

log() { printf '\033[36m[sim]\033[0m %s\n' "$1"; }

log "Target web app: ${BASE_URL}"

# --- 1. SQL injection probes (trigger Wazuh 100120 / Suricata 1000003) --------
log "Sending SQL injection probes..."
sqli_payloads=(
  "id=1' OR '1'='1"
  "id=1 UNION SELECT username,password FROM users"
  "id=1; SELECT sleep(2)"
  "search=%27%20OR%201=1--"
)
for p in "${sqli_payloads[@]}"; do
  curl -s -o /dev/null "${BASE_URL}/vulnerabilities/sqli/?${p}" || true
  sleep 0.5
done

# --- 2. Path traversal (trigger Suricata 1000004) -----------------------------
log "Sending path traversal probe..."
curl -s -o /dev/null "${BASE_URL}/../../../../etc/passwd" || true

# --- 3. SSH brute force (trigger Wazuh 100100 / Suricata 1000002) -------------
# Requires sshpass; we expect these to FAIL — that is the point.
if command -v sshpass >/dev/null 2>&1; then
  log "Simulating SSH brute force (8 failed logins)..."
  for i in $(seq 1 8); do
    sshpass -p "wrongpass${i}" \
      ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
      "baduser@${TARGET}" exit 2>/dev/null || true
  done
else
  log "sshpass not installed; skipping SSH brute-force simulation."
fi

log "Done. Check the Wazuh dashboard / alerts.json and Suricata eve.json."
