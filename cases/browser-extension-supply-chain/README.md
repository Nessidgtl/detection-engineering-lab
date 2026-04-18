# Detection Card

| Field | Detail |
|-------|--------|
| **Case** | Browser Extension Supply Chain Compromise → Malicious Update Pipeline |
| **Source** | [Red Canary - Moving up the Assemblyline](https://redcanary.com/blog/threat-detection/assemblyline-browser-extensions/) |
| **ATT&CK Techniques** | T1195.001 (Compromise Software Supply Chain), T1176 (Browser Extensions), T1539 (Steal Web Session Cookie), T1041 (Exfiltration Over C2 Channel), T1027 (Obfuscated Files or Information) |
| **Detection Target** | Structural delta between two extension versions - co-occurring changes to worker, content scripts, domains, and behavioral signatures before the update executes |
| **Key Insight** | The detection window is between "new version written to disk" and "extension's first post-update execution" - the last point where containment is clean and credentials haven't left the environment |
| **Telemetry Required** | Assemblyline static analysis reports (file tree, entropy via `file_infos`, heuristics from JsJaws / URLCreator / FrankenStrings / Characterize) |
| **SIEM / Query Language** | Elastic Security / KQL (detection logic lives in Python comparison engine; SIEM rule only surfaces structured alerts) |
| **Confidence** | Medium-High (structural co-occurrence, not signature-dependent; validated against realistic Cyberhaven simulation) |
| **Known Bypasses** | Exfiltration via pre-existing trusted domain; low-entropy readable payloads; splitting the attack across multiple version bumps; attackers using Manifest V2 or non-standard background script filenames |
| **False Positive Sources** | Legitimate major refactors with new infrastructure domains; extensions with heavily-bundled or minified JavaScript; first-version submissions (no prior baseline to diff against) |
| **Validation Status** | ✔ Tested - 2 FP baselines (uBlock Origin, Bitwarden), 1 synthetic TP, 1 realistic Cyberhaven simulation (see [validation.md](./validation.md)) |
| **Detection Version** | v1 ([compare_extension.py](./compare_extension.py)) |

---
→ [Full Investigation](./investigation.md) · [Validation & Iteration Log](./validation.md) · [Detection Script](./compare_extension.py)
