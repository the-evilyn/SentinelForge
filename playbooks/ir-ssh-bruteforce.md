# IR Playbook — SSH Brute Force / Credential Access

**Trigger:** SentinelForge rule `DET-SSH-001` / `CORR-SSH-002` (SSH brute force & compromise escalation), or Wazuh rule `100100` / `100101`. MITRE: **T1110.001**, **T1078**.

> Aligned with NIST SP 800-61r2 (Detection → Containment → Eradication → Recovery
> → Post-incident).

## 1. Detection & validation
- [ ] Confirm the alert in the Wazuh dashboard / `alerts.json`. Note `srcip`,
      `agent`, target `user`, and timestamp window.
- [ ] Distinguish **brute force** (100100, failures only) from **likely
      compromise** (100101, a success followed the failures). The latter is a
      page-now event.
- [ ] Correlate with Suricata `sid:1000002` for the network-side view.

## 2. Triage (severity)
| Condition | Severity |
|-----------|----------|
| Failures only, internet-facing host | High |
| Failures only, internal host | Medium |
| Successful login after brute force (rule 100101) | **Critical** |

## 3. Containment
- [ ] Block the source IP at the host firewall / security group:
      `sudo iptables -A INPUT -s <srcip> -j DROP` (or update the AWS SG).
- [ ] If 100101 fired: **isolate** the host (detach from network / quarantine SG).
- [ ] Force-expire the targeted account's credentials and any keys.

## 4. Eradication
- [ ] Review `/var/log/auth.log` and shell history for the targeted user.
- [ ] Hunt for persistence: new users, cron jobs, modified `authorized_keys`,
      unexpected systemd units.
- [ ] Confirm no lateral movement (check other hosts for the same `srcip`).

## 5. Recovery
- [ ] Restore from known-good state if compromise is confirmed.
- [ ] Re-enable access only after credentials rotated and keys reissued.
- [ ] Verify the brute-force alerts have stopped.

## 6. Hardening / lessons learned
- [ ] Disable SSH password auth (`PasswordAuthentication no`) — keys only.
- [ ] Restrict SSH to a bastion / VPN; never expose 22 to `0.0.0.0/0`.
- [ ] Deploy `fail2ban` or rely on the Wazuh active-response block.
- [ ] Record dwell time and detection time for metrics.
