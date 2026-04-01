# Detection Engineering Lab

A hands-on detection engineering lab focused on translating attacker behavior into practical, testable detections.


## Focus Areas
- Decomposing attacks into step-by-step behavior chains
- Understanding system-level behavior (processes, tokens, logs)
- Building detections from *behavior*, not tools or signatures
- Identifying false positives, blind spots, and bypass opportunities


## Approach
Instead of mapping techniques directly from MITRE ATT&CK, this project focuses on:
- How attacks unfold in real life
- What telemetry is actually available
- Why detections fail, drift, or generate noise
- How attackers adapt to evade detection logic  


## Repository Structure
- [cases/](./cases/) → Real-world inspired attack scenarios analyzed end-to-end, from behavior to detection and validation
- [detections/](./detections/) → Reusable detection logic based on common attacker behaviors, independent of specific tools or cases
