# SentinelForge — Component-by-Component Provenance & Attribution Audit

> **Platform:** SentinelForge — Security Detection & Incident Response Platform<br>
> **Lead Developer & Architect:** Evilyn (Final-Year Cybersecurity Engineering Student, ENSI Tanger)<br>
> **Repository:** [https://github.com/the-evilyn/SentinelForge](https://github.com/the-evilyn/SentinelForge)<br>
> **Original Upstream Educational Baseline:** [soc-detection-lab](https://github.com/CedricCloudOps/soc-detection-lab) by Cedric Severin DJIGUIMDE<br>
> **License:** [MIT License](LICENSE)<br>
> **Audit Date:** October 2026

---

## 1. Executive Summary of Project Provenance

**SentinelForge** began with the exploration of an educational blue-team laboratory repository ([`CedricCloudOps/soc-detection-lab`](https://github.com/CedricCloudOps/soc-detection-lab), commit [`7cd0f0e`](https://github.com/CedricCloudOps/soc-detection-lab/commit/7cd0f0e2ccfd5d5bdad3eb4ed433340c8ad1d4d8)), which provided a containerized demonstration setup with Wazuh SIEM, Suricata NIDS, DVWA, and an alert forwarder script.

To transform this baseline into a standalone, portfolio-grade **Security Detection and Incident Response Platform**, **Evilyn** architected and implemented an independent detection, correlation, and scoring pipeline.

A quantitative Git analysis between the upstream baseline (`7cd0f0e`) and SentinelForge (`HEAD`) reveals:
- **Baseline Repository (`7cd0f0e`):** 26 total files, ~800 lines of configuration, scripts, and documentation; zero standalone Python detection or correlation engine.
- **SentinelForge Contributions:** **57 files changed/added**, **+5,127 lines of production Python code, tests, schemas, datasets, and architecture documentation**, expanding test coverage from 16 to 85 passing tests.

---

## 2. Component Categorization

### Category A: Original SentinelForge Implementations (100% Newly Authored by Evilyn)
These components were conceived, architected, and written from scratch. They contain no upstream code:

1. **Typed Security Data Models (`engine/models.py`):**
   - Strictly typed, immutable dataclasses: `Event`, `Alert`, `Incident`, `MITREAttack`, and `RiskScore`.
   - UTC ISO-8601 validation and timestamp normalization.
2. **Modular Ingestion Layer (`engine/ingestion/`):**
   - `BaseParser` interface with line-level non-crashing error resilience (`IngestionResult`, `ParseError`).
   - Parsers for Linux authentication logs (`AuthLogParser`), Apache combined logs (`ApacheLogParser`), Suricata EVE JSON (`SuricataEveParser`), and Wazuh alert streams (`WazuhAlertsParser`).
3. **Canonical Normalization Engine (`engine/normalization/`):**
   - `EventNormalizer` converting heterogeneous logs into canonical `Event` instances with standardized `EventType` categories.
4. **Modular Detection Framework (`engine/detection/`):**
   - `BaseRule` class supporting single-event pattern matching and threshold evaluation.
   - Built-in detection catalog: `DET-SSH-001` (SSH brute force), `DET-WEB-001` (SQL injection indicators), and `DET-WEB-002` (Directory traversal).
5. **Stateful Event Correlation Engine (`engine/correlation/`):**
   - Sliding time-window state tracking per composite identity (`source_ip`, target host).
   - Sequence escalation: Correlating brute-force failures transitioning into successful valid account access (`T1110.001` $\rightarrow$ `T1078`).
   - Incident grouping with ordered chronological evidence timelines.
6. **Explainable Risk Scoring Algorithm (`engine/scoring/`):**
   - Mathematical formula: $\text{Base} \times (0.6 + 0.4 \times \text{Confidence}) + \text{Freq} + \text{Seq} + \text{Exp}$.
   - Logarithmic frequency dampening preventing score inflation, with auditable factor breakdowns.
7. **Alert Suppression & Deduplication (`engine/suppression/`):**
   - Sliding suppression windows and contextual benign allowlisting (`127.0.0.1` health checks, `backup_svc`).
8. **MITRE ATT&CK Matrix Module (`engine/mitre/`):**
   - Offline enterprise technique catalog and automated coverage reporting across registered rules.
9. **Forensic Reporting & Evidence Integrity (`engine/reporting/`):**
   - Deterministic JSON and Markdown incident reporting.
   - Chronological SHA-256 evidence integrity hashing over raw telemetry.
10. **Offline Replay & Quality Benchmarking (`engine/evaluation/` & `tools/sentinelforge_cli.py`):**
    - Standalone CLI runner capable of processing telemetry streams and calculating Precision, Recall, and False Positive Rates on labeled datasets without Docker.
11. **Synthetic Telemetry Datasets & Labeled Scenarios:**
    - `tests/fixtures/` (`ssh_auth.log`, `apache_access.log`, `suricata_eve.json`, `synthetic_events.json`).
    - `datasets/` (`datasets/authentication/ssh_scenarios.jsonl`, `datasets/web/web_scenarios.jsonl`).
12. **Automated Unit & Integration Test Suite (`tests/`):**
    - 69 newly authored test cases across 10 test modules expanding coverage to 85 passing tests.
13. **Architecture & Engineering Specifications (`docs/`):**
    - `docs/architecture.md`, `docs/DETECTION_ENGINE.md`, `docs/THREAT_MODEL.md`, `docs/ROADMAP.md`, `docs/PROJECT_AUDIT.md`.

---

### Category B: Adapted & Security-Hardened Components (Derived from Upstream Baseline)
These components were part of the upstream baseline but were modified by Evilyn for security hardening, compatibility, or project integration:

1. **`docker-compose.yml`:**
   - Restricted all published ports (`8080`, `1514`, `1515`, `55000`) to `127.0.0.1` (localhost only).
   - Added shared named volume `dvwa_logs` to bridge the web-telemetry ingestion gap into Wazuh Manager.
   - Updated Compose project name to `sentinelforge`.
2. **`tools/alert_forwarder.py`:**
   - Updated Slack attachment branding from `soc-detection-lab • Wazuh` to `SentinelForge • Wazuh`.
3. **`scripts/healthcheck.sh`:**
   - Updated banner text to `SentinelForge health check`.
4. **`playbooks/ir-ssh-bruteforce.md` & `playbooks/ir-web-attack.md`:**
   - Extended incident triggers to reference native SentinelForge detection rules (`DET-SSH-001`, `CORR-SSH-002`, `DET-WEB-001`, `DET-WEB-002`).
5. **`.github/workflows/ci.yml`:**
   - Added `engine` directory to Ruff linting step.
6. **`.gitignore`:**
   - Added negative pattern `!tests/fixtures/*.log` to track test fixtures while ignoring runtime logs.
7. **`README.fr.md`:**
   - Fully rewritten to present SentinelForge's architecture, 85 tests, and CLI in French with clear attribution.

---

### Category C: Inherited Upstream Baseline Components (Preserved Verbatim)
These components remain from the upstream educational repository and are preserved with original copyright:

1. **`LICENSE`:**
   - Verbatim MIT License copyright © 2026 Cedric Severin DJIGUIMDE (CedricCloudOps).
2. **`detections/sigma/`:**
   - Three Sigma YAML rules (`linux_curl_pipe_sh.yml`, `ssh_bruteforce.yml`, `web_sqli_attempt.yml`) authored by CedricCloudOps.
3. **`config/suricata/custom.rules`:**
   - Custom Suricata network rules (SIDs 1000001–1000005).
4. **`config/wazuh/local_decoder.xml` & `config/wazuh/local_rules.xml`:**
   - Custom Wazuh XML rules and decoders.
5. **`scripts/simulate-attack.sh`:**
   - Local Bash attack simulation script targeting DVWA.
6. **`scripts/validate_sigma.py`:**
   - Structural YAML validator for Sigma rules.
7. **`tests/test_alert_forwarder.py`:**
   - 16 original unit tests for `alert_forwarder.py`.

---

## 3. Comprehensive File-by-File Provenance Matrix

| File / Path | Category | Primary Author | Description & Purpose |
|:---|:---|:---|:---|
| `LICENSE` | Inherited | CedricCloudOps | Original MIT License text (verbatim) |
| `CREDITS.md` | New | Evilyn | Detailed provenance audit and component attribution |
| `README.md` | Adapted | Evilyn | Comprehensive English documentation and quickstart |
| `README.fr.md` | Adapted | Evilyn | French documentation and quickstart |
| `docker-compose.yml` | Adapted | CedricCloudOps / Evilyn | Security-hardened Docker Compose lab stack |
| `.env.example` | Inherited | CedricCloudOps | Environment variable template |
| `.gitignore` | Adapted | CedricCloudOps / Evilyn | Git ignore rules with fixture preservation |
| `pyproject.toml` | Inherited | CedricCloudOps | Ruff linter configuration |
| `pytest.ini` | Adapted | CedricCloudOps / Evilyn | Pytest configuration with engine paths |
| `requirements-dev.txt` | Inherited | CedricCloudOps | Development and testing dependencies |
| `.github/workflows/ci.yml` | Adapted | CedricCloudOps / Evilyn | CI pipeline with multi-stage verification |
| `config/suricata/custom.rules` | Inherited | CedricCloudOps | Suricata NIDS rule definitions |
| `config/wazuh/local_decoder.xml`| Adapted | CedricCloudOps / Evilyn | Wazuh web access decoder with SentinelForge header |
| `config/wazuh/local_rules.xml`  | Adapted | CedricCloudOps / Evilyn | Wazuh correlation XML rules with SentinelForge header |
| `detections/sigma/*.yml` (3 files)| Inherited | CedricCloudOps | Portable Sigma detection rules |
| `docs/architecture.md` | New | Evilyn | Comprehensive architecture and data flow guide |
| `docs/DETECTION_ENGINE.md` | New | Evilyn | Detection engineering and rule specification guide |
| `docs/THREAT_MODEL.md` | New | Evilyn | Threat modeling and security posture analysis |
| `docs/ROADMAP.md` | New | Evilyn | Engineering roadmap and verification criteria |
| `docs/PROJECT_AUDIT.md` | New | Evilyn | Baseline codebase audit and configuration review |
| `engine/models.py` | New | Evilyn | Canonical typed security data models |
| `engine/ingestion/*.py` (5 files)| New | Evilyn | Resilient multi-source log parsers |
| `engine/normalization/*.py` (2 files)| New | Evilyn | Canonical UTC event normalizer |
| `engine/detection/*.py` (5 files)| New | Evilyn | Rule framework, engine, and detection rules |
| `engine/correlation/*.py` (2 files)| New | Evilyn | Stateful sliding-window event correlator |
| `engine/scoring/*.py` (2 files)| New | Evilyn | Multi-factor explainable risk scorer |
| `engine/suppression/*.py` (2 files)| New | Evilyn | Alert deduplicator and allowlist engine |
| `engine/mitre/*.py` (2 files)| New | Evilyn | MITRE ATT&CK technique catalog and matrix |
| `engine/reporting/*.py` (2 files)| New | Evilyn | Deterministic JSON/Markdown forensic reporter |
| `engine/evaluation/*.py` (2 files)| New | Evilyn | Offline replay runner and benchmark calculator |
| `playbooks/*.md` (2 files) | Adapted | CedricCloudOps / Evilyn | Incident response playbooks with SentinelForge triggers |
| `scripts/healthcheck.sh` | Adapted | CedricCloudOps / Evilyn | Stack health check with SentinelForge banner |
| `scripts/simulate-attack.sh` | Inherited | CedricCloudOps | Local benign attack generator |
| `scripts/validate_sigma.py` | Inherited | CedricCloudOps | Sigma YAML structural validator |
| `tools/alert_forwarder.py` | Adapted | CedricCloudOps / Evilyn | Alert webhook forwarder with SentinelForge footer |
| `tools/sentinelforge_cli.py` | New | Evilyn | Standalone CLI entrypoint (`replay` and `benchmark`) |
| `tests/fixtures/*` (4 files) | New | Evilyn | Synthetic sanitized security log fixtures |
| `datasets/*` (2 files) | New | Evilyn | Labeled benchmark evaluation datasets |
| `tests/test_alert_forwarder.py`| Inherited | CedricCloudOps | 16 original tests for alert forwarder |
| `tests/test_*.py` (10 files) | New | Evilyn | 69 new automated unit and integration tests |

---

## 4. License Compliance

This project strictly adheres to the **MIT License**:
- The upstream copyright notice is preserved verbatim in [`LICENSE`](LICENSE).
- All upstream source files retain their original author comments and copyright notices.
- Evilyn's original contributions are clearly documented and distinguished above.
