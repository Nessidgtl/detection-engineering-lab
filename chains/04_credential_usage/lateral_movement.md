# **Credentials → Authentication (Lateral Movement)**

## **Understand the behavior:**

- ### **What is happening?**
    - Stolen credentials are used to authenticate to a different system
    - Lateral movement begins (access expands beyond initial host)
- ### **What is required?**
    - Valid credentials (password, NTLM hash, token or ticket)
    - Network access to another system
    - Authentication mechanism (like SMB, RDP or WinRM)
- ### **What artifacts are created?**
    - Authentication events (success/failure)
    - Logon types (network, remote interactive)
    - Source → destination relationship
    - Account + host pairing

## **Simulate:**

*No code in this case, but quick RDP from laptop to the desktop does the trick.*

## **Notes / Observations:**

Any type of logon is a normal and frequent event on any system, but its context is usually highly predictable:

- Users usually access a limited and repeatable set of systems
- Admin access follows the same defined patterns
- Source–destination relationships tend to remain stable over time

So at this stage:

- The attacker does not need special tools to use credentials
- In logs, the activity appears as legitimate authentication
- The anomaly lies in who is accessing what, from where, and when (context only)

Some possible contextual additions "marking" the login as more suspicious:

- User logs into system they never accessed before
- One user suddenly accessing many hosts
- Authentication shortly after dump activity

These signals, when combined with any remote logon event, can provide enough context to build a logical and at least a little less noisy detection.

## **First Detection Idea:**

*Alert on authentication attempts to remote systems originating from user workstations using accounts or access patterns that are uncommon for that user or host*

## **Stress-Test:**

- ### **Can attacker bypass it?**
    - Use legitimate admin accounts
    - Blend into normal admin behavior
    - Use common protocols (SMB or RDP)
    - Simply wait a bit between stages
- ### **What still cannot be avoided?**
    - Authentication must still occur
    - Source and destination are logged and can be traced
    - Account usage is visible
    - Time difference between prior events still matters

## **Adjusted Detection:**

*Alert on authentication activity between systems that differs from user or host baseline behavior*
- *especially when involving new source–destination relationships, unusual logon types*
- *or occurring shortly after suspicious credential access or dump-related activity*

***Key Idea:** This detection focuses on how stolen credentials are used rather than how they are obtained, identifying abnormal authentication patterns and relationships between systems that do not align with expected user or admin behavior.*
