u# **Phishing → Macro/Script → Child Process**

## **Understand the behavior:**

- ### **What is happening?**
    - A user opens a phishing attachment (usually Office or similarly benign looking docs)
    - Document contains macro or embedded script
    - User interaction triggers code execution
    - That code spawns a new process
- ### **What is required?**
    - User opens the file
    - Macro/embedded links/other doc-based techniques are enabled (or bypassed)
    - Execution capability on the target system exists (like PowerShell or cmd)
- ### **What artifacts are created?**
    - Office app spawning a process
    - Script interpreter execution
    - Possibly network connection after that

## **Simulate:**

*Run a simple “suspicious” program chain:*

```
winword.exe → powershell.exe
excel.exe → cmd.exe
outlook.exe → wscript.exe
```

## **Notes / Observations:**

This is a very common initial access scenario. Normally office applications:

- Handle documents
- Do not spawn shells or scripting engines

In this case:

- The attacker does not need extra exploits
- Execution is delegated to user interaction and built-in scripting tools
- The anomaly lies in the unexpected child process, not the document itself

This quickly becomes a behavioral anomaly, very visible, very traceable, yet easily missable due to common lack of behavioral baseline or too narrow detection logic.

## **First Detection Idea:**

*Alert when Office or email client applications spawn scripting engines, command-line interpreters, or other known execution utilities*

## **Stress-Test:**

- ### **Can attacker bypass it?**
    - Use LOLBins
    - Use indirect execution (like mshta.exe or rundll32.exe)
    - Use child → grandchild execution chains
    - Disable macros → use other embedded techniques
- ### **What still cannot be avoided?**
    - Some execution must still happen
    - A process chain must exist (adds relatively rare execution pattern)
    - The initial trigger still originates from user application (adds parent process and timing after opening)

## **Adjusted Detection:**

*Alert on Office or email client processes spawning child or descendant processes:*
- *associated with scripting, command execution, or known execution utilities (including multi-step process chains)*
- *especially when the behavior occurs shortly after document interaction*
- *or deviates from established user or system baselines*

***Key Idea:** This detection identifies initial access execution by focusing on abnormal process creation chain originated from user-facing applications. Nothing fancy, but extremely common.*

****References:***
- MITRE ATT&CK – T1566 (Phishing), T1204 (User Execution), T1059 (Command Execution)
- Microsoft – Office spawning child processes detection guidance
- Red Canary / Atomic Red Team – macro → PowerShell execution patterns