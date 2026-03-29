# **Execution → Immediate Outbound Connection (Beacon Start)**

## **Understand the behavior:**

- ### **What is happening?**
    - A process executes on the host
    - Almost immediately, it makes an outbound network connection
    - It’s often done to establish C2 (Command and Control), allowing the attacker to:
        - Receive commands
        - Send data
        - Maintain remote control
- ### **What is required? (Attacker POV)**
    - A successfully executed process (script, binary or LOLBin)
    - Network connection from the host
    - A reachable external endpoint (C2 server, redirector etc.)
    - A mechanism to initiate communication:
        - built-in networking (PowerShell, curl or WinHTTP)
        - embedded malware networking logic
- ### **What artifacts are created? (on the host)**
    
    - Process side:
    
      - Process creation event
      - Process command-line (often includes URL/IP)
      - Parent-child relationship
    
    - Network side:
    
      - Outbound connection event
      - Destination:
        - external IP
        - domain name
      - Port (often 80/443, sometimes unusual)
    
    - Time relationship between process start and network connection (this is the strongest signal).
    

## **Notes / Observations:**

**What is beaconing?**

Beaconing - periodic communication from compromised host to attacker-controlled system.

Main observable artifacts:

- Repeated, usually outbound connections (interval-based)
- Often small, regular traffic
- Can use HTTP/HTTPS/DNS protocols

Typical event chains during beaconing simulations:

```
powershell.exe → outbound HTTPS connection
cmd.exe → curl → external IP
malware.exe → connects to C2 server
```

**Normal applications:**

- Wait for user interaction
- Or start with performing internal tasks first

**Malicious execution:**

- Often connects immediately (because it needs instructions to proceed)

## **First Detection Idea:**

*Alert when a newly spawned process initiates an outbound network connection shortly after execution*

## **Stress-Test:**

- ### **Can attacker bypass it?**
    - Delay beaconing initiation
    - Inject into another process
    - Use trusted processes (browser)
    - Use DNS or indirect channels
- ### **What still cannot be avoided?**
    - At some point, communication still must happen
    - A process (often a rare one) must initiate that connection
    - Timing relationship still exists (even if delayed)

## **Adjusted Detection:**

*Alert on processes initiating outbound network connections:*
- *where the process behavior and network activity are inconsistent with its typical role*
- *including newly executed, rarely seen, or user-initiated processes*
- *establishing communication with external or uncommon destinations*

***Key Idea:** This detection identifies the transition from execution to command-and-control by focusing on processes performing network communication that does not align with their expected role or typical behavior, regardless of when the connection occurs.*
