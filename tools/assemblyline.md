# **Assemblyline**

## **Overview**

Assemblyline is an open-source malware analysis framework developed by the Canadian Centre for Cyber Security (CCCS). It's designed to automate the triage of large volumes of files: unpacking archives, running them through a configurable pipeline of analysis services, and producing structured reports with scoring, heuristics, and extracted indicators.

It is used by defenders rather than attackers. CERT teams, SOC analysts, and threat researchers run it as a scalable alternative to manual reverse engineering for initial file triage.

## **Key Characteristics**

- **Service-Based Architecture:** Analysis is split across discrete services (YARA, JsJaws, FrankenStrings, Characterize, URLCreator, etc.) that can be enabled or disabled per-submission. Each service contributes its own findings to a unified report.
- **Recursive Extraction:** Archives, embedded files, and extracted payloads are automatically re-submitted through the full pipeline. A `.zip` containing a `.docx` containing a macro with a base64 blob gets analyzed at every layer without manual intervention.
- **Scoring and Heuristics:** Services produce heuristics with stable IDs and human-readable names. Scores aggregate across services into a single `max_score`, giving a high-level verdict (Informative / Suspicious / Malicious) alongside the detailed findings.
- **Static-Only by Default:** The base deployment performs static analysis. Dynamic analysis (sandbox detonation) is available through add-on services like CAPE but isn't part of the default pipeline.
- **Structured Output:** Results are returned as JSON via REST API or the official Python client, making Assemblyline easy to integrate into detection pipelines, SIEMs, and custom tooling.
- **Configurable Submission Profiles:** Threat intelligence feed services can be disabled per-submission, useful when the goal is pre-disclosure detection rather than IOC matching.

## **Main Capabilities**

- **Archive unpacking:** Extracts `.zip`, `.7z`, `.rar`, `.tar`, `.crx`, and other container formats via the `Extract` service.
- **JavaScript analysis:** `JsJaws` runs behavioral analysis on JavaScript, flagging patterns like `CookieHarvesting`, `Base64Decoding`, `EvalUsage`, `NetworkRequest`.
- **URL and domain extraction:** `URLCreator` parses URLs and domains from file content and tags them in the report.
- **Encoded string detection:** `FrankenStrings` surfaces Base64, hex, XOR, and other encoding patterns, useful for spotting hidden payloads in otherwise benign-looking files.
- **File characterization:** `Characterize` computes entropy, file type, and structural metadata for every extracted file.
- **YARA matching:** When enabled with rule sets, the `Yara` service matches against known malicious signatures.
- **Custom services:** Teams can write their own services in Python and deploy them into the pipeline alongside the built-in ones.

## **How It Works**

1. **Submission:** A file is submitted via the web UI, REST API, or Python client, with an optional submission profile selecting which services to run.
2. **Extraction:** The Extract service unpacks the archive, producing a tree of embedded files.
3. **Fan-out:** Each file in the tree is dispatched to every enabled service in parallel.
4. **Heuristic evaluation:** Services produce sections with optional heuristics, tags, and scores attached to specific findings.
5. **Aggregation:** Results are collected into a single submission report containing `file_tree`, `file_infos`, `results` per-service, and a top-level `max_score`.
6. **Consumption:** The report is available via the UI for human triage or via API for automated pipelines.

## **Telemetry / Artifacts**

Unlike offensive tools, Assemblyline doesn't produce telemetry on victim systems. It runs in the analyst's environment. Relevant artifacts for *using* Assemblyline are:

- REST API submission logs (what was submitted, when, by which user)
- Service execution metrics (timing, success/failure per service)
- Structured JSON reports (retrievable by submission ID)
- Extracted child files and their individual analysis reports

## **Detection Insights**

Assemblyline itself is a detection tool, but its output shape matters for anyone building detection pipelines on top of it:

- Heuristic IDs are stable across versions, safe to match on in downstream rules.
- `max_score` drifts between analyses even for the same file (new service versions, updated rules), so absolute thresholds are less reliable than version-to-version deltas.
- Threat intel services (YARA TI feeds, external lookups) should be disabled when the goal is catching novel threats before public disclosure. Otherwise detections match against already-known IOCs and the pre-disclosure window is lost.
- Services run in isolated containers. A service failure produces no findings rather than failing loudly, so monitoring the `errors` field in reports matters for pipeline reliability.
- Recursive extraction means a single submission can produce dozens of child file reports, so detection logic needs to walk the `file_tree` rather than analyzing only the root file.

## **MITRE ATT&CK Mapping**

Assemblyline is used to *analyze* attacker techniques rather than execute them, so ATT&CK mapping applies to the behaviors it surfaces in analyzed samples rather than to the tool itself. Common signatures observed in Assemblyline output map to:

- Obfuscated Files or Information (T1027): `Base64Decoding`, `EncodeURI`, `SplitReverseJoin`
- Command and Scripting Interpreter (T1059): `EvalUsage`, `Long One-Liner`
- Steal Web Session Cookie (T1539): `CookieHarvesting`
- Ingress Tool Transfer (T1105): `NetworkRequest`, `PrepareNetworkRequest`

## **References**

- Official documentation: https://cybercentrecanada.github.io/assemblyline4_docs/
- GitHub: https://github.com/CybercentreCanada/assemblyline
- Red Canary detection research: https://redcanary.com/blog/threat-detection/assemblyline-browser-extensions/
