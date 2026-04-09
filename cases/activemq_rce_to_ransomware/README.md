# Detection Card

| Field | Detail |
|-------|--------|
| **Case** | Apache ActiveMQ RCE → LockBit Ransomware |
| **Source** | [The DFIR Report](https://thedfirreport.com/2026/02/23/apache-activemq-exploit-leads-to-lockbit-ransomware/) |
| **ATT&CK Techniques** | T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter), T1003.001 (LSASS Memory) |
| **Detection Target** | Service-origin execution → shell activity → LSASS access within 45 minutes |
| **Key Insight** | ~40-minute window between initial foothold and credential access is the last point where attacker presence is still localized and containable |
| **Telemetry Required** | Process creation (Sysmon Event ID 1), Process access (Sysmon Event ID 10) |
| **SIEM / Query Language** | Elastic Security / EQL |
| **Confidence** | Medium-High (behavioral sequence, not signature-dependent) |
| **Known Bypasses** | Delayed execution beyond time window; non-LSASS credential techniques (token theft, Kerberoasting); execution without shell interpreters (WMI, direct API) |
| **False Positive Sources** | Admin tools accessing LSASS; security software with service-context execution |
| **Validation Status** | ✔ Tested — functional and behavioral scenarios (see [validation.md](./validation.md)) |
| **Detection Version** | v2 ([detection.eql](./detection.eql)) |

---

→ [Full Investigation](./investigation.md) · [Validation & Iteration Log](./validation.md) · [Detection Rule](./detection.eql)
