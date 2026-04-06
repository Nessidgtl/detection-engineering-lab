# **Detection: Multi-Stage LSASS Credential Dumping**

## **Attacker Intent Scenario**

An attacker with existing presence on a Windows OS attempts to extract credentials by accessing the LSASS process memory.

Instead of relying on a specific tool *(like procdump or mimikatz)*, the attacker may use various methods to dump memory or directly access LSASS, aiming to extract NTLM hashes or plaintext credentials for following lateral movement.


## **Behavior Chain**

This type of attack often follows this sequence of observable events:

1. User Execution
    - A user-initiated or user-context process begins execution
    - Often originates from:
        - User-writable directories
        - User-facing applications *(browser, document viewer)*
2. Execution Capabilities (Optional)
    - A process capable of dumping memory or executing code runs.
    - Processes like:
        - Command-line tools
        - Scripting engines
        - Renamed or custom binaries
3. Memory Dump Artifact (Optional)
    - A .dmp file is often created on disk
    - For easier access often written to:
        - Temp directories
        - User folders
4. Most Critical Invariant: LSASS Access
    - A process finally attempts to access LSASS memory


## **Required Telemetry**

To support this detection, we could check:

- Process Creation Logs:
    - Parent-child relationships
    - Command-line arguments
    - Execution path
    - User context / integrity level
- File Creation Logs:
    - Especially .dmp files
    - File path and parent process
- Process / Memory Access Logs
    - Access attempts to lsass.exe
    - Access rights (if currently available)

## **Detection Logic (EQL)**

```eql
sequence by host.id with maxspan=5m

/* 1. Suspicious execution */
[process where event.type == "start" and (
    process.parent.name in ("winword.exe","excel.exe","outlook.exe","chrome.exe","firefox.exe","msedge.exe")
    or process.executable : ("C:\\Users\\*\\AppData\\*","C:\\Users\\Public\\*")
)]

/* 2. Optional: tool signal (may not be really required) */
?[process where event.type == "start" and
    process.name in ("procdump.exe","rundll32.exe")
]

/* 3. Optional: dump artifact */
?[file where event.type == "creation" and file.extension == "dmp"]

/* 4. Core event: LSASS access */
[process where event.type == "access" and
    process.Ext.api.target_process_name == "lsass.exe"
]
```

## **Detection Strategy**

The interesting thing about this detection, is that it does not rely on specific tools.

Instead, it focuses on:

- Context *(who executed it and from where)*
- Artifacts presence *(memory dump files, if present)*
- Invariant presence *(LSASS access)*

So this detection remains effective even if:

- Tools are renamed
- Custom binaries are used
- Known utilities are replaced


## **Likely False Positives**

- Legitimate admin or debugging activity:
    - System admins
    - IT troubleshooting tools
- Security tools doing memory inspection
- Software crash diagnostics

But these could still be whitelisted, as they are distinguishable by:

- Known parent processes
- Expected execution paths
- Known and trusted binaries


## **Bypass Considerations**

Still, an attacker may try to evade detection by:

- Avoiding .dmp file creation at all
- Using direct system calls to bypass logging
- Injecting into trusted processes
- Using signed or living-off-the-land binaries


## **What Still Cannot Be Avoided**

Even with these evasions, some things will remain:

- Basic process execution must occur
- LSASS must be accessed (one way or the other)
- Execution logs still leak:
    - Unusual parent-child relationships
    - Suspicious paths
    - Elevated privileges

This is why I chose to treat LSASS access as the critical behavior event.


## **Detection Philosophy**

This detection follows a layered approach to raise alert confidence:

- Weak signals alone → too noisy
- Combined signals → better, higher confidence

It basically combines:

- Context (user-driven execution)
- Capability (tool or engine)
- Artifacts (dump file)
- Core action (LSASS access)


## **MITRE ATT&CK Mapping**

- Credential Access
    - OS Credential Dumping (T1003)
    - LSASS Memory (T1003.001)
