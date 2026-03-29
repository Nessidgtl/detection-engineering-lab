# **Authentication → Remote Execution**

## **Understand the behavior:**

- ### **What is happening?**
    - After successful authentication, the attacker executes something on the remote host:
        - commands
        - scripts
        - binaries
- ### **What is required?**
    - Valid established access to target system
    - Remote execution mechanism:
        - SMB (service creation, admin actions)
        - WinRM / PowerShell remoting
        - WMI
        - RDP (interactive execution)
- ### **What artifacts are created?**
    - New process on Host B
    - Parent process may look unusual
    - Network connection from Host A
    - Logon session and logon session id tied to execution

## **Simulate (Powershell):**

```powershell
# PsExec-style (SMB + service creation)
psexec \\target cmd.exe

# WMI remote execution
wmic /node:target process call create "cmd.exe"

# WinRM / PowerShell remoting
Enter-PSSession -ComputerName target
Invoke-Command -ComputerName target -ScriptBlock { cmd.exe }

# RDP (manual)
mstsc /v:target
# then run cmd.exe or powershell.exe on target for better signals
```

## **Notes / Observations:**

Curious thing I noticed - processes appear on target host (desktop in my case), but are not locally initiated. Even with normal initiation, parent-child relationships look weird:
```
services.exe → cmd.exe
wmiprvse.exe → powershell.exe
```

Problem is, not even knowing that this remote logon is suspicious yet, for the right logs, we already have to shift focus to the context on the host machine, not the target one.

So it raises some logical problems:

- The attacker does not need to run tools locally on the target machine, can just keep hiding his activity on the compromised one
- Execution is often performed through easily missed built-in system mechanisms (like services.exe or wmiprvse.exe)
- The parent process may appear legitimate, but hopefully, the execution context could tell another story

## **First Detection Idea:**

*Alert when processes are spawned on a system by service or management processes in contexts that do not align with expected administrative or remote management activity*

## **Stress-Test:**

- ### **Can attacker bypass it?**
    - Use legitimate admin tools
    - Blend into normal troubleshooting and general IT activity
    - Use RDP (could appear as more “normal” execution)
    - Act through renamed binaries
- ### **What still cannot be avoided?**
    - Some process must execute on Host B
    - It must have some parent
    - Execution context will exist (and often will look weird)
    - Timing between events still matters and can be traced

## **Adjusted Detection:**

*Alert on process execution on a target system*
- *originating from service or remote management processes*
- *where the parent–child relationship and execution context do not align with expected administrative activity*
- *especially when preceded by remote authentication events*

***Key Idea:** This detection focuses on identifying malicious remote execution through abnormal process creation patterns on the target system, where legitimate system processes are used as intermediaries for attacker-initiated actions.*
