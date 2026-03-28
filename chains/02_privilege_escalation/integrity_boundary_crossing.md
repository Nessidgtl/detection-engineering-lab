# Medium → High Integrity process (Integrity Boundary Crossing)

## **Understand the behavior:**

- ### **What is happening?**
    - A process running under Medium integrity leads to the execution of a High integrity process (this is the basic case of a privilege boundary crossing).
    
- ### **What is required?**
    - User context exists (user already logged in)
    - A mechanism to elevate:
        - UAC prompt (legitimate path)
        - Credential input (confirmation you have admin rights)
        - Exploit / bypass
- ### **What counts as action?**
    - “Run as administrator”
    - UAC approval
    - Application requesting elevation
    - Exploit triggering elevation silently
- ### **What artifacts are created?**
    - New process (High integrity)
    - Parent process (usually Medium)
    - Token change (meaning new security context)
    - Possible different user (if new creds used)

## **Simulate (Powershell):**

```powershell
Start-Process notepad -Verb runAs
```

## **Notes / Observations:**

During my simple simulation, I found an interesting detail in the Powershell creation context: the parent of this Powershell version was not my explorer.exe (Medium), but consent.exe (High).

Apparently, sometimes the parent–child relationship looks “weird” like that because UAC introduces intermediate processes (like consent.exe).

- These processes are created by Windows after an elevation request is made by user
- This prevents the original Medium integrity process from directly creating the High integrity process (the key concept of how integrity boundaries work)

So instead:

- The Medium process initiates the elevation request only
- consent.exe (running as High) creates the elevated process (notepad.exe as High)

So even though it looks like: consent.exe (High) → notepad.exe (High), the execution is still user-initiated, not system-initiated.

## **First Detection Idea (for the most interesting case):**

*Alert when a Medium integrity process spawns a High integrity process in an unusual context*

## **Stress-Test:**

- ### **Can attacker bypass it?**
    - Use already elevated process
    - Inject into High integrity process
    - Use existing services / scheduled tasks
    - Token theft instead of UAC
- ### **What still cannot be avoided?**
    - A High integrity process must exist at some point
    - New security context is created (parent-child relationship, execution path)
    - Privilege boundary is crossed somehow

## **Adjusted Detection:**

*Alert when a High integrity process originates from a Medium integrity context, where the parent chain, execution path, or behavior does not match expected admin tools or workflows*

****Key Idea:** This detection is designed to not rely on specific tools. Instead, it focuses on identifying elevated execution that originates from user-driven contexts, using execution context, process lineage, and behavior patterns.*
