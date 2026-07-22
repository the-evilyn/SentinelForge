# Architecture & detection design

## Components

| Service | Image | Role |
|---------|-------|------|
| `wazuh.manager` | `wazuh/wazuh-manager:4.9.0` | Log analysis, decoders, rules, `alerts.json`, REST API |
| `suricata` | `jasonish/suricata:7.0` | Network IDS; shares the target's netns, writes `eve.json` |
| `dvwa` | `vulnerables/web-dvwa` | The intentionally vulnerable "victim" web app |

The Wazuh **indexer** and **dashboard** are intentionally left out of the default
compose to keep the lab light and avoid the TLS bootstrap. To add them, generate
certs with the official `wazuh-certs-tool.sh`, mount them, and add the two
services — notes below.

## Data flow

1. `simulate-attack.sh` (or a real adversary) hits the DVWA target.
2. **Suricata** sees the packets on the shared interface and writes signatures
   matches to `/var/log/suricata/eve.json`.
3. The **Wazuh manager** ingests both the target's host/web logs and Suricata's
   `eve.json`, runs decoders, then the rule engine (shipped rules + our
   `local_rules.xml`), and writes matches to `alerts.json`.
4. `alert_forwarder.py` reads `alerts.json`, keeps level ≥ N, and POSTs a
   formatted message to a chat webhook.

## Why correlation rules matter

A single failed SSH login is noise. The value is in **stateful correlation**:

- `100100` fires only when one source IP causes **8 failures in 120 s**.
- `100101` is the money rule — a **successful** login from an IP that just
  tripped `100100`. That sequence is what separates "someone's knocking" from
  "someone's in". Sigma can't express this stateful chain on its own, which is
  exactly why both Sigma (portable, static) and Wazuh rules (stateful) are here.

## Detection coverage matrix

| ATT&CK | Sigma | Wazuh | Suricata |
|--------|:-----:|:-----:|:--------:|
| T1110.001 Brute force | ✅ | ✅ 100100 | ✅ 1000002 |
| T1078 Valid accounts | — | ✅ 100101 | — |
| T1059.004 Unix shell | ✅ | ✅ 100110 | — |
| T1105 Ingress tool transfer | ✅ | — | ✅ 1000005 |
| T1190 Exploit public app | ✅ | ✅ 100120 | ✅ 1000003 |
| Recon / port scan | — | — | ✅ 1000001 |
| Path traversal | — | — | ✅ 1000004 |

## Adding the indexer + dashboard (optional)

```bash
# 1. Generate certs (one-time)
docker run --rm -v "$PWD/config/certs:/certs" \
  wazuh/wazuh-certs-tool:0.0.2 -A

# 2. Add wazuh.indexer and wazuh.dashboard services pinned to 4.9.0,
#    mounting ./config/certs, then `docker compose up -d`.
```

See the upstream `wazuh-docker` single-node example for the full service blocks.

## Hardening notes (for a real deployment)

- Replace DVWA with your actual monitored assets and deploy **Wazuh agents**.
- Terminate the dashboard behind TLS + SSO; never expose `55000` publicly.
- Ship `alerts.json` to cold storage (S3 + object lock) for retention.
- Pair with the [secure-aws-landing-zone](https://github.com/CedricCloudOps/secure-aws-landing-zone)
  repo so the SIEM itself runs on a hardened account.
