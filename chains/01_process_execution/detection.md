# Chain 1: User action → Process execution

## **Understand the behavior:**

- ### **What is happening?**
    - User performs an action that results in a creation of a new process
- ### **What was required? What counted as action:**
    - Double-clicking a file
    - Opening a document
    - Running a downloaded executable
    - Clicking something that triggers code
- ### **What artifacts are created?**
    - Parent-Child relationship
    - Context (user, integrity, privileges) change
    - Command-line
    - File path
    - Next steps for created process

## **Simulate (Powershell):**

    *Open notepad.exe through double-click.*
    *Run as admin -> Powershell (High) -> notepad.exe (High)*

## **Notes / Observations:**
After opening both notepad.exe versions under different context, I closed Powershell only.
It created a sequence of interesting consequences observed through Process Explorer:
- The parent process (PowerShell) terminated
- Notepad continued running independently
- In process tools, it appeared as: *<Non-existent Process> → notepad.exe (High)*

After careful research of this situation I found out the existence of a basic rule:
- When a parent process terminates, the child process continues running with its original context (in this case, High integrity).
- The parent-child relationship is preserved only as a recorded PID leftover, so once the parent exits, the child appears as having a non-existent parent.
- This happens because process relationships are fixed at creation time and are not updated dynamically during runtime.
- So it can be difficult to understand what triggered a suspicious child process later on without reliable historical logging (like Sysmon or any available SIEM), allowing to check what process this specific PID was assigned to earlier.

## **First Detection Idea (for the most interesting case):**

*Alert when a user-facing application spawns a scripting or execution engine (PowerShell, cmd, wscript)*

## **Stress-Test:**

- ### **Can attacker bypass it?**
    - use a less suspicious parent
    - inject into existing process
    - use signed binaries
- ### **What still cannot be avoided?**
    - Process execution still happens
    - Execution context (path, command-line, privilege) often leaks

## **Adjusted Detection:**

*Alert on execution engines (PowerShell, cmd, wscript) when they are:*
- *spawned by user-facing applications*
- *executed from user-writable directories*
- *running with elevated privileges outside expected service context*

****Key Idea:** This detection is designed to not rely on specific tools. Instead, it focuses on execution context and parent-child relationships that are uncommon in normal user activity.*
