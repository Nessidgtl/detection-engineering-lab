# **Detection Validation: Execution → Shell → LSASS**

**Based on [Original Conceptual Detection](./investigation.md#detection-logic-eql) (Apache ActiveMQ case)*

### **Summary:**

Final version of the detection is designed to target execution from user-writable or service-linked context followed by shell activity and LSASS access within a short time window.

During validation, it:

- has been successfully tested with real telemetry
- reliably identified common post-exploitation activity patterns
- while avoiding overly broad coverage that could reduce accuracy or increase noise


### **Hypothesis:**

Service or task-based execution that leads to shell activity and credential access is a consistent and detectable attacker behavior.


### **Detection Strategy:**

Main focus is placed on a high-frequency behavior chain:

  > **service/task execution → shell → LSASS access**

The detection is designed to prioritize stability over covering every possible variant, with the option to extend coverage as needed.


# **Validation**

### ***Environment:**

- Windows (lab VM)
- Sysmon (ProcessCreate + ProcessAccess)
- SIEM: Elastic Security

## **1. Functional Validation**

Simulates ideal conditions to verify rule logic.

### **Command:**

```powershell
:: Step 1 - simulate suspicious execution
copy C:\\Windows\\System32\\cmd.exe C:\\Users\\Public\\cmd.exe

:: Step 2 - suspicious shell
C:\\Users\\Public\\cmd.exe /c powershell -nop -w hidden -c whoami

:: Step 3 - LSASS access using rundll32
tasklist | findstr lsass

rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump <PID> C:\\Windows\\Temp\\lsass.dmp full
```

### **Observed Telemetry:**

- **Parent process:**
    - `powershell.exe` acted as the effective parent for subsequent execution
    - `cmd.exe` did not consistently preserve a detectable parent-child chain
- **Child processes:**
    - `cmd.exe` executed from `C:\\Users\\Public\\`
    - `powershell.exe` spawned with obfuscated flags (`nop -w hidden`)
    - `rundll32.exe` used to invoke `comsvcs.dll` for LSASS dump
- **Command-line patterns:**
    - `cmd.exe /c powershell -nop -w hidden -c whoami`
    - `rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump <PID> ...`
    - Command lines referenced `System32` despite execution from a user-writable directory
- **Timing:**
    - All three stages executed sequentially, well within the 45-minute `maxspan`
    - No strict process lineage required; correlation succeeded on `host.id` + temporal proximity

### **Result:** ✔ Detection triggered

### **Key Insights:**

- LSASS access required enabling **Sysmon Event ID 10** via a custom config addition
- Field mapping needed adjustment:
    - `event.code == "10"`
    - `winlog.event_data.TargetImage`
- **Strict parent assumptions** caused misses → relaxed
- Command-line filtering (like excluding `System32`) caused **false negatives**
- Process lineage **inconsistent** → correlation must not depend on it
- Detection triggered reliably with `powershell.exe` as parent, but not with `cmd.exe` - mostly due to telemetry visibility differences



## **2. Behavioral Validation**

Simulates realistic attacker behavior with indirect execution, nested shells, encoded PowerShell, and LOLBins.

### **Command:**

```powershell
:: Step 1 - simulate service-like execution path
mkdir C:\\ProgramData\\svc-cache
copy C:\\Windows\\System32\\cmd.exe C:\\ProgramData\\svc-cache\\svc.exe

:: Step 2 - suspicious shell via PowerShell (encoded command)
powershell -nop -w hidden -c "Start-Process C:\\ProgramData\\svc-cache\\svc.exe -ArgumentList '/c powershell -nop -w hidden -enc SQBFAFgAIAAoACcAdwBoAG8AYQBtAGkAJwApAA=='"

:: Step 3 - LSASS access using rundll32
$lsassPid = (Get-Process lsass).Id
rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump $lsassPid C:\\ProgramData\\svc-cache\\lsass.dmp full
```

### **Observed Telemetry:**

- **Execution chain:** `powershell.exe` → `svc.exe` → `powershell.exe` → `rundll32.exe`
- **Parent-child relationships** were not consistently preserved across all events
- Some steps required **host-level correlation** instead of strict lineage
- Payload launched via `Start-Process` and nested PowerShell (`/c powershell ...`) - added indirection did not break detection
- **Command-line visibility** was full via Sysmon (`process.args`, `process.command_line`):
    - `nop`, `w hidden`, `enc` all visible
    - Encoded payload execution clearly present
    - `rundll32.exe` command line included `comsvcs.dll`, `MiniDump`, LSASS PID
- No major telemetry gaps observed after previous functional fixes

### **Result:**

| Step | Outcome |
| --- | --- |
| Initial execution | ✔ Detected |
| Payload execution | ✔ Detected |
| LSASS access | ✔ Detected |
| Full sequence | ✔ Triggered |

### **Key Insights:**

- Detection survived **multi-stage, indirect execution**
- Parent-child relationships were **not reliable**
- Command-line telemetry provided **strong signal**
- Execution from user-writable paths remained a **consistent indicator**
- Behavior-based detection proved more stable than path or lineage assumptions
- `rundll32.exe` executed from `C:\\Windows\\System32\\` (expected) - path-based filtering for rundll32 was removed, detection now focuses on behavior (`comsvcs.dll` + `MiniDump`)



## **Detection Results**

| Scenario | Result | Notes |
| --- | --- | --- |
| Functional test | ✔ | Baseline validation with simple execution |
| Realistic execution | ✔ | Multi-stage attacker-like behavior with indirection and obfuscation |



### **Key Observations:**

- Detection successfully captured a **realistic post-exploitation chain**
- Works despite:
    - nested execution
    - obfuscation
    - imperfect lineage
- Strongest signals:
    - LSASS access
    - command-line behavior
- Weakest signals:
    - parent-child relationships
- Key takeaway:
  - *Behavioral correlation is more reliable than strict lineage or path assumptions*



# **Detection Improvements**

### 1. Remove unreliable assumptions

- Removed: path-based constraints on `rundll32.exe`, fragile `System32` / `Program Files` exclusions
- Focus on: command-line behavior (`comsvcs.dll`, `MiniDump`)

### 2. Accept and design for imperfect lineage

- Detection uses `sequence by host.id`
- Avoids over-reliance on strict parent-child relationships

### 3. Targeted command-line filtering on LOLBins

- rundll32.exe is gated on the comsvcs.dll / MiniDump command-line pattern, the specific LSASS dump technique observed in the source incident
- Shells (cmd.exe, powershell.exe) remain unconstrained at this stage to preserve coverage of varied attacker behavior
- Future improvement: extend command-line gating to other LOLBins (wmic, mshta) as alternative LSASS techniques are added


### 4. Expand parent process coverage

- Added `powershell.exe`, `cmd.exe`, `services.exe`, `svchost.exe` alongside original `java.exe` / `javaw.exe`
- Reflects real execution chains observed during validation

### 5. Consider alternative LSASS access methods

- Current detection focuses on `rundll32 + comsvcs.dll`
- Other known dumping techniques (like `procdump` or direct memory access) are a future improvement

### 6. Improve robustness of sequence correlation

- Evaluate time window sensitivity
- Continue prioritizing host-based grouping over process lineage



## **Bypass Considerations**

**Intentionally excluded:**

| Technique | Reason |
| --- | --- |
| **Delayed execution** | Long delays between stages break sequence-based detection. Not included to avoid overly large time windows and increased noise. |
| **Non-shell execution paths** | Execution via WMI, services, or direct API calls may bypass PowerShell/cmd visibility. Excluded to keep detection focused on available telemetry. |
| **Alternative LSASS dumping methods** | Tools like `procdump`, direct memory access, or custom implementations excluded to avoid overcomplicating the rule and introducing false positives. |
| **Execution from non-suspicious directories** | Attackers may use legitimate paths (like `System32`). Detection prioritizes suspicious staging locations for higher signal. |
| **Removal of PowerShell flags** | Attackers can execute without `-enc`, `-nop`, etc. Detection does not rely solely on these to avoid brittleness. |
| **Living-off-the-land variations beyond rundll32** | Other LOLBins (like `wmic` or `mshta`) not included to maintain focus and clarity of detection scope. |



## **Limitations**

- Dependent on:
    - command-line visibility
    - Sysmon Event ID 10
- Sequence-based → can be bypassed with delay
- Focused on one LSASS technique (`comsvcs.dll`)
- Does not cover low-noise or custom tradecraft
- May miss fileless or in-memory-only credential access
- May trigger on admin scripts using PowerShell, automation tools or security software interacting with LSASS (if not whitelisted properly depending on the environment)



# **Final Detection (v2)**

*Design notes and considerations (inline)*

```eql
sequence by host.id with maxspan=45m

/* 1. Suspicious execution from service-linked or user-writable context */
[process where event.type == "start" and (
    /* relaxed parent constraints — reflects real execution chains observed during validation */
    process.parent.name in (
        "java.exe","javaw.exe","powershell.exe",
        "cmd.exe","services.exe","svchost.exe"
    ) and

    /* kept strong signal: suspicious staging locations */
    process.executable : (
        "C:\\Users\\*",
        "C:\\Windows\\Temp\\*",
        "C:\\ProgramData\\*"
    )
)]

/* 2. Shell or LSASS-dump LOLBin execution
   - shells count on their own (broad command-line visibility downstream)
   - rundll32 counts only when invoking the comsvcs.dll MiniDump technique */
[process where event.type == "start" and
    (
        process.name in ("cmd.exe","powershell.exe")
        or
        (process.name == "rundll32.exe" and
         process.command_line : ("*comsvcs.dll*", "*MiniDump*"))
    )
]

/* 3. LSASS access (Sysmon Event ID 10), excluding known benign processes */
[process where event.code == "10" and
    winlog.event_data.TargetImage like "*lsass.exe" and
    not process.name in ("MsMpEng.exe","csrss.exe","wininit.exe")
]

```

**Designed as a baseline detection to be tuned per environment.*
