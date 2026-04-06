# Detection Engineering Lab

A hands-on detection engineering lab focused on translating attacker behavior into practical, testable detections inspired by intriguing real-world scenarios.


## Focus Areas
- Decomposing attacks into step-by-step behavior chains
- Understanding system-level behavior (processes, tokens, logs)
- Building detections from *behavior*, not tools or static signatures
- Identifying false positives, blind spots, and bypass opportunities


## Approach
Instead of relying purely on [MITRE ATT&CK](https://attack.mitre.org/) mappings, this project focuses on how attacks actually unfold in real environments:

- How attackers move from initial access to full compromise
- What telemetry is realistically available at each stage
- Why detections fail, drift, or generate noise
- How attackers adapt to evade detection logic

The goal is to bridge the gap between theoretical techniques and practical real-world detection engineering.


## Repository Structure
- [cases/](./cases/) → Real-world inspired attack scenarios analyzed end-to-end, from behavior to detection and custom code validation
- [tools/](./tools/) → Commonly abused tools and techniques, analyzed and reused across multiple attack scenarios
- [patterns/](./behavior_patterns/) → Commonly recognized attacker behaviors, analyzed from a tool- and case-agnostic perspective
