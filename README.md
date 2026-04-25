# Detection Engineering Lab

Writing a detection rule is the easy part. Making it survive in production is what this portfolio focuses on.

Each case in this repository takes a real-world attack scenario and works through the full detection lifecycle: understanding how the attack unfolds, identifying the highest-value detection window, writing the rule, testing it against real telemetry, documenting what broke, and iterating until the detection holds up under realistic conditions.

The focus is on the analytical work that makes detections survive in production - not on tool familiarity or signature writing.

## What's Inside

**[tools/](./tools/)** - Behavioral profiles of commonly abused tools and malware families. What they look like in telemetry, not what they are.

**[cases/](./cases/)** - End-to-end detection investigations built from real attack reports. Including:
  - an investigation identifying where in the attack chain detection matters most
  - the detection logic written in EQL, KQL, or custom engines depending on the detection window
  - full documentation of what failed during testing and how the detection was improved, and bypass analysis with false positive assessment and triage guidance.

## Cases

| Case | ATT&CK Focus | Detection Target | Status |
|------|-------------|-------------------|--------|
| [Apache ActiveMQ → LockBit](./cases/activemq_rce_to_ransomware/) | Initial Access → Credential Access | Service-origin execution → shell → LSASS access within a constrained time window | Validated (v2) |
| [Browser Extension Supply Chain](./cases/browser-extension-supply-chain/) | Supply Chain Compromise → Exfiltration | Structural delta between extension versions, co-occurring changes to worker, scripts, and domains before execution | Validated (v1) |
| [Seven Epochs of Scarlet Goldfinch](./cases/scarlet-goldfinch-clickfix/) | User Execution → Ingress Tool Transfer | Behavioral process lineage of paste-and-run delivery, anchored on what the technique cannot change without abandoning itself | Validated (v1) |
| *More cases in progress* | | | |

## Methodology

Every case follows the same process:

1. **Attack decomposition** - Break down a real intrusion report into a step-by-step behavior chain with timestamps and dependencies.
2. **Detection window identification** - Find the moment where the attacker is generating detectable artifacts but hasn't yet achieved their objective (credentials harvested, lateral movement started, data exfiltrated).
3. **Detection design** - Write a behavioral rule targeting that window, chaining weak signals into a high-confidence sequence.
4. **Validation** - Test against real telemetry in a lab environment matched to the attack surface. Document what the telemetry actually looks like. Fix what breaks.
5. **Iteration** - Remove fragile assumptions, expand coverage based on observed behavior, document known bypasses and limitations.

The goal is detections that work because they target behavior the attacker cannot easily change, not because they match a specific tool or signature.

## Lab Environments

- **Endpoint detection cases:** Windows VM with Elastic Defend and Sysmon (ProcessCreate, ProcessAccess, NetworkConnect), Elastic Cloud Serverless as SIEM
- **Pre-execution / supply chain cases:** Ubuntu VM, Assemblyline static analysis pipeline, Filebeat, Elastic Cloud Serverless

Manual attack simulation across both. Each step executed and observed individually. No automated frameworks.

## Contact

- Email: nessi.dgtl@gmail.com
- LinkedIn: [anya-nessi-240283188](https://www.linkedin.com/in/anya-nessi-240283188)
