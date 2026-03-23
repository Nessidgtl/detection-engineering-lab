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

```powershell
# Launch PowerShell from Explorer-like context
Start-Process powershell.exe -ArgumentList "-NoProfile -Command `"Start-Sleep 5`""

# Launch cmd as another execution engine
Start-Process cmd.exe /c "timeout /t 5"
```

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
