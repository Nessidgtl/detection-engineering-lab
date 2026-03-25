# Detection Engineering Lab


This repository documents a structured approach to detection engineering by breaking real-world attack behavior into analyzable chains, then translating them into practical detections.

⸻

## Focus
- Decomposing attacks into step-by-step behavior chains
- Understanding what actually happens on a system (processes, tokens, logs)
- Building detections from behavior, not signatures
- Identifying false positives, blind spots, and bypasses

Instead of mapping techniques directly from MITRE ATT&CK, this project focuses on:
- How attacks unfold in reality
- What telemetry is actually available
- Why detections fail or become noisy
- How attackers can adapt or evade

⸻

## Structure
- chains/ → Attack behavior broken into clear, logical steps
- detections/ → Detection logic (EQL/KQL) with reasoning and tradeoffs
- methodology/ → Detection thinking, patterns, and design approach

