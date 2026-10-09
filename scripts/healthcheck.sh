#!/usr/bin/env bash
#
# Quick status check for the lab stack. Exits non-zero if a core service is down.
set -euo pipefail

fail=0
check() {
  local name="$1" cmd="$2"
  if eval "$cmd" >/dev/null 2>&1; then
    printf '\033[32m  OK \033[0m %s\n' "$name"
  else
    printf '\033[31m FAIL\033[0m %s\n' "$name"
    fail=1
  fi
}

echo "SentinelForge health check"
check "docker compose services up" "docker compose ps --status running | grep -q wazuh"
check "Wazuh manager process"      "docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-control status"
check "DVWA target reachable"      "curl -fsS http://localhost:8080 -o /dev/null"
check "Suricata eve.json present"  "docker compose exec -T wazuh.manager test -f /var/log/suricata/eve.json"

exit "$fail"
