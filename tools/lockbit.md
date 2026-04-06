# **LockBit**

## **Overview**

LockBit is a widely used and rapidly evolving ransomware family that operates under a Ransomware-as-a-Service (RaaS) model. It enables affiliates (attackers) to deploy ransomware in exchange for sharing a portion of the profits with the operators. LockBit is known for its speed, automation, and adaptability, making it one of the most active and impactful ransomware families in recent years.

It is designed to rapidly encrypt large environments while evading detection, often combining data exfiltration and encryption as part of a double extortion strategy. Over time, multiple versions (ex. LockBit 2.0, 3.0) have introduced improvements in stealth, propagation, and defense evasion.

## **Key Characteristics**

- **Ransomware-as-a-Service (RaaS)**: LockBit is not used by a single group but by multiple affiliates, which leads to variation in initial access techniques and execution patterns.
- **Fast Encryption Mechanism**: Optimized for speed, allowing rapid encryption of files across systems and network shares to minimize defender response time.
- **Double Extortion Model**: Combines file encryption with data exfiltration, threatening public release of stolen data if ransom is not paid.
- **Customizable Payloads**: Affiliates can configure ransom notes, encryption behavior, and execution parameters using a builder.
- **Defense Evasion Techniques**: Includes disabling security tools, clearing logs, and avoiding certain system paths to remain stealthy.
- **Automated Propagation**: Capable of spreading across networks using available credentials and accessible shares.
- **Use of Legitimate Tools**: Often leverages built-in system utilities (LOLBins) and common admin tools to blend into normal activity.

## **Main Capabilities**

Once executed in an environment, LockBit provides attackers with the ability to:

- **File Encryption**: Encrypt user and system files across local and network drives.
- **Data Exfiltration**: Steal sensitive data prior to encryption for extortion purposes.
- **Credential Abuse**: Use harvested or provided credentials to expand access.
- **Lateral Movement**: Spread across systems using SMB shares, remote services, or administrative tools.
- **Persistence (depending on campaign objectives)**: Maintain access for staging or delayed execution.
- **System Disruption**: Impact business operations by targeting critical systems and backups.

## **How It Works**

1. **Initial Access:** Gained via phishing, exposed services (ex. RDP), exploitation, or credential compromise.
2. **Execution & Staging:** The ransomware payload is deployed, often alongside tools for reconnaissance, credential access, and lateral movement.
3. **Privilege Escalation & Discovery:** Attackers enumerate the environment, escalate privileges, and identify valuable targets.
4. **Lateral Movement:** Spread across the network using valid accounts, remote execution tools, or shared resources.
5. **Data Exfiltration:** Sensitive data is collected and transferred out of the environment.
6. **Defense Evasion:** Security tools may be disabled, logs cleared, and backups targeted.
7. **Encryption & Ransom Note Deployment:** Files are encrypted and ransom notes are dropped across systems.

## **Telemetry / Artifacts**

LockBit activity generates multiple observable signals across the attack chain:

- Sudden spikes in file modification and renaming activity
- Creation of ransom notes across multiple directories
- Use of administrative tools or scripts for lateral movement
- Unusual authentication activity (ex. lateral movement with valid accounts)
- Outbound connections potentially related to data exfiltration
- Disabling or tampering with security tools and services
- Execution of processes from uncommon or user-controlled directories
- Deletion of shadow copies or backup-related activity

## **Detection Insights**

LockBit is not a single observable event but a sequence of behaviors that unfold over time. Detection should focus on identifying early-stage activity before encryption occurs, as post-encryption detection is often too late.

- Monitor for unusual lateral movement using valid credentials, especially across multiple hosts in a short time
- Detect mass file access or modification patterns indicative of encryption activity
- Identify use of administrative tools in abnormal contexts (ex. remote execution from non-admin workstations)
- Watch for backup deletion or shadow copy removal, which often precedes encryption
- Correlate authentication anomalies, process execution, and network activity across the environment
- Look for data exfiltration signals prior to impact, such as large outbound transfers

In many cases, the ransomware binary creation is the least valuable detection point, because often it's the final stage of an already successful intrusion.

## **MITRE ATT&CK Mapping**

- Initial Access (multiple techniques depending on affiliate)
- Valid Accounts (T1078)
- Lateral Movement (T1021)
- Data Encrypted for Impact (T1486)
- Exfiltration (multiple techniques)
- Inhibit System Recovery (T1490)

## **References**

- MITRE ATT&CK: https://attack.mitre.org/software/S1202/
- Public reporting from trusted sources like Microsoft, Mandiant, and Red Canary on LockBit campaigns (ex. https://www.microsoft.com/en-us/security/blog/?s=lockbit)
