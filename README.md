# Detection Engineering Lab

Writing a detection rule is the easy part. Making it survive in production is what this portfolio focuses on.

Each case in this repository takes a real-world attack scenario and works through the full detection lifecycle: understanding how the attack unfolds, identifying the highest-value detection window, writing the rule, testing it against real telemetry, documenting what broke, and iterating until the detection holds up under realistic conditions.

The focus is on the analytical work that makes detections survive in production - not on tool familiarity or signature writing.


## What's Inside

**[cases/](./cases/)** - End-to-end detection investigations built from real attack reports. Each case includes:
- An investigation narrative identifying *where* in the attack chain detection matters most and *why*
- Detection logic written in EQL, KQL, or custom engines depending on the detection window, tested and validated in a lab environment
- Honest documentation of what failed during testing and how the detection was improved
- Bypass analysis, false positive assessment, and triage guidance

**[tools/](./tools/)** - Behavioral profiles of commonly abused tools and malware families, focused on what they look like in telemetry rather than what they are


## Cases

| Case | ATT&CK Focus | Detection Target | Status |
|------|-------------|-------------------|--------|
| [Apache ActiveMQ → LockBit](./cases/activemq_rce_to_ransomware/) | Initial Access → Credential Access | Service-origin execution → shell → LSASS access within a constrained time window | Validated (v2) |
| [Browser Extension Supply Chain](./cases/browser_extension_supply_chain/) | Supply Chain Compromise → Exfiltration | Structural delta between extension versions - co-occurring changes to worker, scripts, and domains before execution | Validated (v1) |
| *More cases in progress* | | | |


## Methodology

Every case follows the same process:

1. **Attack decomposition** - Break down a real intrusion report into a step-by-step behavior chain with timestamps and dependencies
2. **Detection window identification** - Find the moment where the attacker is generating detectable artifacts but hasn't yet achieved their objective (like credentials harvested or lateral movement started)
3. **Detection design** - Write a behavioral rule targeting that window, chaining weak signals into a high-confidence sequence
4. **Validation** - Test against real telemetry in a lab environment matched to the attack surface (Windows + Sysmon for endpoint cases, Linux + static analysis pipelines for pre-execution cases), document what the telemetry actually looks like, fix what breaks
5. **Iteration** - Remove fragile assumptions, expand coverage based on observed behavior, document known bypasses and limitations

The goal is detections that work because they target behavior the attacker *cannot easily change*, not because they match a specific tool or signature.


## Lab Environments
- **Endpoint detection cases:** Windows VM with Sysmon (ProcessCreate + ProcessAccess), Elastic Security as SIEM
- **Pre-execution / supply chain cases:** Ubuntu VM, Assemblyline static analysis pipeline, Filebeat, Elastic Cloud Serverless

→ Manual attack simulation across both - each step executed and observed individually, no automated frameworks.


## Contact

Interested in Detection Engineering and Blue Team roles focused on real-world, behavior-based detection

- Email: [nessi.dgtl@gmail.com](mailto:nessi.dgtl@gmail.com)
- LinkedIn: [linkedin.com/in/anna-nechaeva-240283188](https://www.linkedin.com/in/anna-nechaeva-240283188)
