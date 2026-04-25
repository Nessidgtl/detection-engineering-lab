# Detection Card

| Field | Detail |
|-------|--------|
| **Case** | Seven Epochs of Scarlet Goldfinch → ClickFix Paste-and-Run Process Chain |
| **Source** | [Red Canary - Scarlet Goldfinch's year in ClickFix](https://redcanary.com/blog/threat-intelligence/scarlet-goldfinch-clickfix/), [Red Canary 2026 Threat Detection Report - Scarlet Goldfinch](https://redcanary.com/threat-detection-report/threats/scarlet-goldfinch/) |
| **ATT&CK Techniques** | T1204.004 (Malicious Copy and Paste), T1218.005 (Mshta), T1059.001 (PowerShell), T1059.003 (Windows Command Shell), T1105 (Ingress Tool Transfer), T1027 (Obfuscated Files or Information) |
| **Detection Target** | Behavioral process lineage of paste-and-run delivery: `explorer.exe → command interpreter → download LOLBin → external network egress`. Anchored on what the technique cannot change without abandoning paste-and-run entirely |
| **Key Insight** | Command-line strings rotate across Scarlet Goldfinch's seven observed epochs; the process chain underneath does not. Detection at the lineage layer survives obfuscation that breaks string matching, including Epoch 7's substring-index variant |
| **Telemetry Required** | Elastic Defend endpoint events (`endpoint.events.process` and `endpoint.events.network`), with `process.parent.name`, `process.entity_id`, `process.parent.entity_id`, `process.pe.original_file_name`, `event.action`, `destination.ip` |
| **SIEM / Query Language** | Elastic Security / EQL (Rule 1: process chain sequence) + KQL (Rule 2: LOLBin external egress). Two correlated rules due to cross-data-stream EQL constraints in this deployment |
| **Confidence** | High when both rules fire on the same host within 2 minutes; medium when either fires alone. Behavioral-invariant anchor reduces brittleness against future TTP rotation |
| **Known Bypasses** | Process-tree-breaking techniques (e.g., `Invoke-CimMethod` reparenting under `WmiPrvSE.exe`, used in Epoch 5); FileFix variants pasting into File Explorer address bar; renamed LOLBins where `process.pe.original_file_name` is not captured by the sensor; intermediate parent processes between `explorer.exe` and the command interpreter (Epoch 3 forfiles pattern misses Rule 1) |
| **False Positive Sources** | Administrator paste-and-run workflows for legitimate IT troubleshooting; scheduled tasks invoking curl, certutil, or bitsadmin against external destinations (Rule 2 only); environments where LOLBins are used in legitimate scripted automation |
| **Validation Status** | ✔ Tested - 3 epoch simulations (Epoch 1 ✔, Epoch 3 partial ✘/✔, Epoch 7 ✔), 3 FP scenarios (admin curl ✔/✔ known FP, browser download ✘/✘, scheduled task ✘/✔). Cross-data-stream EQL constraint discovered and architecture adjusted (see [validation.md](./validation.md)) |
| **Detection Version** | v1 ([detection.eql](./detection.eql), [detection-lolbin.kql](./detection-lolbin.kql)) |

---

→ [Full Investigation](./investigation.md) · [Validation & Iteration Log](./validation.md) · [Rule 1 (EQL)](./detection.eql) · [Rule 2 (KQL)](./detection-lolbin.kql)
