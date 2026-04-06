# Detection Engineering Lab

A hands-on detection engineering lab focused on translating attacker behavior into practical, testable detections.


## Focus Areas
- Decomposing attacks into step-by-step behavior chains
- Understanding system-level behavior (processes, tokens, logs)
- Building detections from *behavior*, not tools or signatures
- Identifying false positives, blind spots, and bypass opportunities


## Approach
Instead of relying purely on [MITRE ATT&CK](https://attack.mitre.org/) mappings, this project focuses on how attacks actually unfold in real environments:

- How attackers move from initial access to full compromise
- What telemetry is realistically available at each stage
- Why detections fail, drift, or generate noise
- How attackers adapt to evade detection logic

The goal is to bridge the gap between theoretical techniques and practical detection engineering.


## Repository Structure
- [cases/](./cases/) → Real-world inspired attack scenarios analyzed end-to-end, from behavior to detection and custom code validation
- [detections/](./detections/) → Reusable detection logic based on common attacker behaviors, independent of specific tools or cases
- [tools/](./tools/) → Commonly abused tools and techniques, analyzed from a behavioral and detection perspective for reuse across attack scenarios
