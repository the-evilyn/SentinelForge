# IR Playbook — Web Application Attack (SQL Injection)

**Trigger:** SentinelForge rule `DET-WEB-001` (SQL Injection) / `DET-WEB-002` (Path Traversal), Wazuh rule `100120`, or Suricata `sid:1000003`. MITRE: **T1190** (Exploit Public-Facing Application).

> Aligned with NIST SP 800-61r2 and OWASP guidance.

## 1. Detection & validation
- [ ] Pull the offending request(s): `srcip`, `url`/query, user-agent, timestamp.
- [ ] Decide probe vs. successful exploitation: 200 with abnormal response size,
      DB errors in app logs, or data in the response = likely success.
- [ ] Check whether the source is a known scanner or the blue team itself.

## 2. Triage (severity)
| Condition | Severity |
|-----------|----------|
| Blocked / WAF-mitigated probe | Low |
| Reaching the app, no evidence of data access | Medium |
| Evidence of data exfiltration or auth bypass | **Critical** |

## 3. Containment
- [ ] Block the `srcip` at the edge (WAF / security group / reverse proxy).
- [ ] If exploitation is confirmed, take the affected endpoint offline or enable
      WAF blocking mode.
- [ ] Snapshot the web/app/DB hosts for forensics before changing anything.

## 4. Eradication
- [ ] Identify the vulnerable parameter and patch (parameterised queries / ORM).
- [ ] Review DB audit logs for unauthorised queries; rotate DB credentials.
- [ ] Search for web shells or modified files dropped via the injection.

## 5. Recovery
- [ ] Deploy the fix, redeploy from a clean artifact.
- [ ] Restore data from backup if integrity is in question.
- [ ] Monitor for repeat attempts from related infrastructure.

## 6. Hardening / lessons learned
- [ ] Add/extend WAF rules; enable input validation and prepared statements.
- [ ] Add the payload pattern to `detections/sigma/web_sqli_attempt.yml`.
- [ ] Run a dependency + SAST scan on the app.
- [ ] Capture detection-time / response-time metrics for the report.
