# **Meterpreter**

## **Overview**

Meterpreter (short for Meta-Interpreter) is an advanced, dynamically extensible post-exploitation payload from the Metasploit Framework. It is used by penetration testers and ethical hackers to interact with a compromised target machine, explore its file system, execute code, and perform post-exploitation tasks.

It is highly regarded for its stealth and efficiency, often described as a “Swiss army knife” for post-exploitation.

## **Key Characteristics**

- **In-Memory Only (Fileless):** Meterpreter resides entirely in the target’s RAM and does not write files to the disk. This makes it difficult to detect with traditional antivirus software that scans for file-based malware.
- **No New Processes:** It uses in-memory DLL injection, injecting itself into an already running, compromised process (like `explorer.exe` or `svchost.exe`). This reduces the forensic footprint and prevents the creation of suspicious new processes.
- **Encrypted Communication:** It establishes an encrypted communication channel between the attacker’s machine and the target, protecting the command-and-control (C2) traffic from detection.
- **Extensible:** Meterpreter can load new modules (extensions) on the fly over the network at runtime without needing to recompile the payload.
- **Process Migration:** It can "migrate" from its initial compromised process to another, allowing it to move to a more stable or stealthier process to maintain access.

## **Main Capabilities**

Once a Meterpreter session is established, it provides a powerful set of built-in commands for post-exploitation:

- **File System Manipulation:** Searching, downloading, and uploading files.
- **Credential Harvesting:** Dumping password hashes (`hashdump`) and accessing tools like Mimikatz or built-in credential extraction techniques to gain access to cleartext passwords.
- **Keylogging:** Capturing keystrokes on the victim's machine.
- **Surveillance:** Taking screenshots, capturing webcam video, or recording audio.
- **Privilege Escalation:** Elevating privileges to that of a local system administrator (SYSTEM).
- **Network Pivoting:** Using the compromised machine as a "pivot" point to attack other systems within the internal network.

## **How It Works**

1. **Exploitation:** A vulnerability is exploited to deliver the payload
2. **Stager:** A small "stager" code executes on the target, which loads the full Meterpreter DLL into memory.
3. **Connection:** The payload connects back to the attacker's listener (reverse TCP or HTTPS).
4. **Interactive Session:** Attacker receives a meterpreter > prompt, enabling interactive control.

## **Telemetry / Artifacts**

Meterpreter is designed to minimize artifacts, so detection relies on indirect signals:

- Unusual parent-child process relationships (ex. service → shell spawn)
- Code injection indicators in legitimate processes (memory access, handle operations)
- Long-lived or periodic outbound connections (beaconing)
- Memory-resident execution (no file on disk)
- Post-compromise activity like credential access or privilege escalation

## **Detection Insights**

Meterpreter rarely appears as a file or obvious binary. Detection should focus on the behaviors it produces, not catching the tool itself:

- Monitor unexpected outbound connections from non-browser processes
- Detect process injection behavior (ex. abnormal memory access patterns)
- Identify spawned shells from exploited applications/services
- Look for credential dumping activity following initial access
- Correlate execution → network → privilege escalation chains

Meterpreter is not unique in its behavior - many modern post-exploitation frameworks follow similar patterns, steadily making behavior-based detections broadly applicable beyond this specific tool.

## **MITRE ATT&CK Mapping**

- Command and Scripting Interpreter (T1059)
- Ingress Tool Transfer (T1105)
- Remote Services / Lateral Movement (T1021)
- Process Injection (T1055)
- Credential Access (multiple techniques)

## **References**

- Official documentation: https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/
- MITRE ATT&CK: https://attack.mitre.org/
