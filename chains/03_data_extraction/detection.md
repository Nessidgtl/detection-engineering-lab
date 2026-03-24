# Chain 3: Dump file → Credential extraction

## **Understand the behavior:**

- ### **What is happening?**
    - A previously created memory dump file is being read and parsed to extract credentials.
- ### **What is required?**
    - Dump file exists (.dmp)
    - Tool or code capable of parsing it
    - Read access to the file
- ### **What artifacts are created?**
    - Process reading .dmp file
    - File access event (read)
    - Possible output:
        - credentials in memory
        - text output / console
    - Command-line often reveals intent

## **Simulate (Powershell):**

```powershell
Get-Content C:\Users\lab\Desktop\lsass.dmp
```

## **Notes / Observations:**

During this simulation I noticed that all I could find is basically almost benign looking

```
Process: powershell.exe
Action: File Read
Target: C:\Users\lab\Desktop\lsass.dmp
```

Though dump file contains highly important credential information, its access at this stage becomes detached from the earlier, more protected interaction with the source process. Typical sequence of events:

- LSASS is protected with strict access controls and monitoring
- After dumping, its memory is converted into a regular file (.dmp)
- The operating system no longer treats this data as sensitive memory, but as normal file content

So now:

- The attacker doesn't have to interact with LSASS at all
- Any process with file read access can parse the dump

So even though in logs it looks like *powershell.exe reads lsass.dmp*, we have to somehow treat it as *credential extraction*, just without direct interaction with the protected system process.

## **First Detection Idea:**

*Alert when a process accesses dump files associated with sensitive processes in user contexts or non-standard locations*

## **Stress-Test:**

- ### **Can attacker bypass it?**
    - Parse dump on another machine
    - Rename file
    - Encrypt or obfuscate dump
    - Use in-memory parsing (no file artifact left)
 
- ### **What still cannot be avoided?**
    - Dump must be read somewhere (execution context must exist)
    - Parsing requires processing the data (often large binary dump)
    - Often involves unusual tools or behavior

## **Adjusted Detection:**

*Alert on dump file creation and subsequent access:*
- *originating from user-driven or unusual execution contexts*
- *where sensitive process memory has been converted into a file*
- *and is accessed outside expected admin tools or debugging workflows*

****Key Idea:** This detection is designed to not rely on specific credential dumping tools. Instead, it shifts focus from high-signal protected memory access to lower-signal dump file access, where sensitive data is exposed to normal file operations and must be detected through context rather than direct process interaction.*
