# Detection Engineering Lab

Behavior-driven detection engineering from *attack behavior → logs → detection → bypass analysis*

This repository documents a structured approach to detection engineering by breaking real-world attack behavior into analyzable chains, then translating them into practical detections.


## Focus Areas
- Decomposing attacks into step-by-step behavior chains
- Understanding what actually happens on a system (processes, tokens, logs)
- Building detections from *behavior*, not tools or signatures
- Identifying false positives, blind spots, and bypasses


## Approach
Instead of mapping techniques directly from MITRE ATT&CK, this project focuses on:
- How attacks actually unfold in real life
- What telemetry is actually available
- Why detections fail, drift, or generate noise
- How attackers adapt and evade detection logic  


## Repository Structure
- [chains/](./chains/) → Attack behavior broken into clear, logical steps
- [detections/](./detections/) → Detection logic (EQL/KQL) with reasoning and tradeoffs
- [methodology/](./methodology/) → Detection thinking, patterns, and design approach
