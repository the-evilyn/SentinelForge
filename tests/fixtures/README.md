# Synthetic Telemetry Fixtures

This directory contains sanitized, synthetic telemetry fixtures designed for offline detection and correlation testing without requiring live Docker containers, external network access, or third-party APIs.

## Privacy & Safety Principles

1. **No Real Credentials or Tokens:** All authentication failures and successes use simulated, benign usernames (`admin`, `root`, `deploy`, `alice_analyst`, `backup_svc`). No actual secrets or valid private keys are stored.
2. **RFC-Reserved Documentation IP Ranges:**
   - `192.0.2.0/24` (TEST-NET-1, RFC 5737): Represents the simulated external attacker.
   - `198.51.100.0/24` (TEST-NET-2, RFC 5737): Represents internal / benign corporate clients.
   - `203.0.113.0/24` (TEST-NET-3, RFC 5737): Represents low-volume background Internet scanners.
   - `10.0.0.5` (RFC 1918): Represents the target lab host (`web-01` / `dvwa.lab`).
   - `127.0.0.1`: Represents internal localhost health probes.
3. **RFC 2606 Reserved Domains:** `example.com`, `example.org`, and local lab domain `dvwa.lab`.

---

## Fixture Files & Schemas

### 1. `ssh_auth.log`
- **Format:** Standard Linux `/var/log/auth.log` (Syslog RFC 3164).
- **Schema:** `<Month> <Day> <Time> <Hostname> sshd[<PID>]: <Message>`
- **Scenarios:**
  - **SSH Brute Force + Compromise:** 8 rapid failures within 32 seconds from `192.0.2.15`, followed by a successful login for account `deploy` at T+45s.
  - **Benign Password Typo:** Legitimate user `alice_analyst` mistypes password once at 14:02:10, then successfully logs in at 14:02:16.
  - **Benign Publickey Authentication:** Scheduled backup service `backup_svc` connects via RSA publickey.
  - **Low-volume Scan:** 2 isolated password failures from `203.0.113.88` separated by 8 minutes (below detection thresholds).

### 2. `apache_access.log`
- **Format:** Apache Combined Log Format (`%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"`).
- **Scenarios:**
  - **SQL Injection:** Probes using `UNION SELECT`, `' OR '1'='1`, and `sleep(5)`.
  - **Directory Traversal:** Probe using `../../../../etc/passwd` returning 404.
  - **Benign Web Requests:** Standard browsing to `/index.php` and CSS assets.
  - **False-Positive Resistance:** Legitimate search query `/search?q=credit+union+selection` containing SQL keywords in natural language context.
  - **Local Healthcheck:** Probing `/health` from `127.0.0.1`.

### 3. `suricata_eve.json`
- **Format:** Suricata 7.0 Extensible Event Format (Newline-delimited JSON).
- **Schema:**
  - `timestamp`: ISO-8601 with microseconds and UTC offset.
  - `event_type`: `"alert"`, `"flow"`, `"http"`.
  - `src_ip`, `src_port`, `dest_ip`, `dest_port`, `proto`: Network layer 3/4 headers.
  - `alert`: Sub-object containing `signature_id`, `signature`, `category`, `severity`.
- **Scenarios:**
  - SID `1000001`: Port scan (SYN burst).
  - SID `1000002`: Repeated SSH connections.
  - SID `1000003`: SQL injection (UNION SELECT).
  - SID `1000004`: Path traversal.
  - Benign HTTP GET and closed TCP flow events without alerts.

### 4. `synthetic_events.json`
- **Format:** JSON array of structured test cases.
- **Fields:**
  - `scenario_id`: Unique scenario identifier (e.g. `SCEN-SSH-001`).
  - `scenario_name`: Human-readable title.
  - `classification`: `"malicious"` or `"benign"`.
  - `events`: Array of pre-normalized event objects matching the `engine.models.Event` schema.
