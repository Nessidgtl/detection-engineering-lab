# **certutil**

## **Overview**

certutil is a legitimate Windows command-line utility that is part of the Certificate Services infrastructure. It is designed for managing certificates, certificate authorities (CAs), and cryptographic operations within Windows environments.

Although its primary purpose is administrative, certutil is widely abused by attackers as a “Living off the Land Binary” (LOLBin). It allows them to perform actions like downloading files, encoding/decoding data, and interacting with certificates, all while using a trusted, signed Microsoft binary. This makes it especially valuable for evading detection and bypassing application whitelisting controls.

## **Key Characteristics**

- **Legitimate Signed Binary**: certutil is a native Windows tool signed by Microsoft, making it inherently trusted in most environments.
- **Dual-Use Functionality**: Designed for certificate management but easily repurposed for malicious actions like file transfer and data manipulation.
- **Proxy for File Downloading**: Can retrieve files from remote URLs, often used as a replacement for tools like curl or wget on Windows systems.
- **Encoding/Decoding Capabilities**: Supports Base64 encoding and decoding, which attackers use to obfuscate payloads.
- **No Additional Tooling Required**: Already present on most Windows systems, eliminating the need to drop external binaries.
- **Blends with Administrative Activity**: Its legitimate use in enterprise environments can make malicious usage harder to distinguish.

## **Main Capabilities**

When abused by attackers, certutil can be used for:

- **File Downloading**: Retrieve payloads from remote servers using HTTP/HTTPS
- **Data Encoding/Decoding**: Encode or decode payloads (ex. Base64) to evade detection
- **Payload Staging**: Save downloaded content locally for later execution
- **Certificate Manipulation**: Interact with certificate stores (less common in attacks, but possible)
- **Data Obfuscation**: Transform data to hide malicious content within scripts or files

## **How It Works**

1. **Execution:** Attacker runs certutil from the command line or through script
2. **Command Usage:** Specific flags are used depending on the goal (ex. -urlcache, -decode)
3. **File Retrieval or Transformation:**
    - Downloads payload from remote source
    - Or decodes previously staged content
4. **Follow-on Execution:** The resulting file is executed or used in further stages of the attack

## **Telemetry / Artifacts**

certutil usage produces observable artifacts despite being a legitimate tool:

- Process execution (certutil.exe) with command-line arguments
- Presence of URLs in command-line parameters
- File creation in user-writable directories
- Base64-encoded or decoded files appearing on disk
- Parent processes that are unusual for administrative activity (ex. Office apps, browsers)
- Network connections initiated by certutil

## **Detection Insights**

certutil abuse is a strong example of why context matters more than the binary itself. Since the tool is legitimate, detection should focus on how and where it is used:

- Monitor for certutil execution with URL-related arguments (ex. -urlcache, -split)
- Detect downloads to suspicious locations such as user directories or temp folders
- Identify unusual parent processes spawning certutil (ex. Word, Excel, browser processes)
- Look for Base64 decoding activity followed by execution of resulting files
- Correlate certutil activity with follow-on execution (ex. newly created binaries launched shortly after download/decoding)
- Watch for certutil in environments where certificate management is not expected

## **MITRE ATT&CK Mapping**

- Signed Binary Proxy Execution (T1218)
- Ingress Tool Transfer (T1105)
- Obfuscated Files or Information (T1027)

## **References**

- MITRE ATT&CK: https://attack.mitre.org/software/S0160/
- LOLBAS Project: https://lolbas-project.github.io/lolbas/Binaries/Certutil/
