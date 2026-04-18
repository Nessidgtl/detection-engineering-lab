# Detection Validation: Extension Supply Chain - Malicious Update Pipeline

*Based on the detection designed in [investigation.md](./investigation.md)*

---

## What we’re building and why

Browser extensions update silently. When a legitimate extension gets compromised at the source, the malicious code arrives through the official channel, signed by the original publisher, installed by the browser itself. Between late 2024 and early 2026, at least five publicly documented extensions were compromised this way. In every case, the compromise was discovered after execution - reactively, through network telemetry or public reporting.

This pipeline was designed to learn whether you can catch it before the code runs. What follows is the full build: the decision behind each component, what broke along the way, how each issue was resolved, and how the pipeline performed end-to-end against both legitimate extensions and a realistic supply chain simulation.

The first instinct was to write an EQL rule - watch for suspicious network connections from browser context, flag cookie access patterns, etc. But by the time Elastic sees those signals, the code has already executed and credentials may already be in transit. The attack surface here isn’t process execution. It’s a zip archive containing update files written in JavaScript. The best detection window is the moment between “*the extension updated on disk*” and “*the new code runs for the first time*”. EQL doesn’t operate in that window. A structural comparison engine does.

Working backwards from that, the pipeline needed five things:

1. **An isolated environment** to analyze potentially malicious files safely (here, an Ubuntu VM on VirtualBox)
2. **A static analysis framework** that produces structured, comparable JSON reports ([Assemblyline](https://github.com/CybercentreCanada/assemblyline), the same tool Red Canary used to validate their detection across 2,850 real extension comparisons)
3. **A custom comparison script** that extracts signals from two reports, computes the delta, and fires rules when suspicious combinations co-occur
4. **A log shipper** to get alerts from disk into the SIEM (Filebeat watching a directory, decoupled from detection logic)
5. **A SIEM detection rule** to surface alerts for triage (a simple query on a dedicated index)

One thing deliberately not built for the home lab: automated inventory-driven submission. In production, a scheduled script would detect version changes and trigger the pipeline. For self-validation, manual submission was more than enough.

### Environment used:

- Oracle VirtualBox VM, Ubuntu 22.04 LTS (4 vCPUs, 8 GB RAM, 80 GB disk)
- Assemblyline 4.7.2 (Docker Compose, 17 containers)
- Filebeat 8.19.14
- Elastic Cloud Serverless (Security project, GCP us-east4)

---

# Building the Pipeline

## Phase 1: Infrastructure

### Deploying Assemblyline

The Assemblyline Docker Compose repository has been restructured since many community deployment guides were written - the `full_appliance` and `minimal_appliance` subdirectories no longer exist. The current layout uses a single root-level `docker-compose.yaml` with deployment profiles (minimal, full, archive) selected via `COMPOSE_PROFILES` in `.env`.

After adjusting for this, 16 of 17 containers came up healthy on first boot. The ingester was the only exception - it crash-looped with `resource_already_exists_exception` errors because multiple services were racing to create the same Elasticsearch indices during startup. A container restart resolved it immediately.

The more pressing problem was memory. With 17 containers and Elasticsearch allocated 2 GB, the system had almost nothing left:

```
total: 7.8Gi    used: 5.7Gi    free: 188Mi    swap: 0B
```

No swap had been configured. Without it, an Elasticsearch OOM kill under analysis load would have been inevitable - and it would have manifested as incomplete analysis results with no obvious error. A 4 GB swap file was added before proceeding any further.

---

## Phase 2: The authentication problem

The Assemblyline login page loaded, the UI looked healthy, but no password worked. After five failed attempts the account locked for 60 seconds:

```
"Authentication failure. (U:admin) [Wrong username or password]"
"Maximum password retry of 5 was reached. This account is locked for the next 60 seconds..."
```

Several attempts to reset the password from inside the running container failed - the expected Python modules either didn’t exist in this version or required undocumented constructor arguments:

```python
# Module doesn't exist in 4.7.2
docker exec -it ui python3 -m assemblyline.odm.random_data.create_admin_user
# → No module named assemblyline.odm.random_data.create_admin_user

# Constructor requires an argument the docs don't mention
AssemblylineDatastore()
# → TypeError: missing 1 required positional argument: 'datastore_object'
```

A full redeploy with `docker compose down -v` and a corrected `.env` still didn’t work. Querying the datastore directly revealed the actual problem:

```python
ds = forge.get_datastore()
user = ds.user.get('admin')
print(user)  # None - no admin user exists
```

The bootstrap process had never created an admin user. No error in any log. The fix was manual user creation via the Assemblyline ODM:

```python
from assemblyline.common import forge
from assemblyline.common.security import get_password_hash
from assemblyline.odm.models.user import User

ds = forge.get_datastore()
user = User({
    'uname': 'admin', 'name': 'Admin',
    'password': get_password_hash('admin123'),
    'type': ['admin', 'user'], 'is_admin': True
})
ds.user.save('admin', user)
```

*Worth noting for anyone deploying Assemblyline: if the bootstrap fails during initial `docker compose up`, there is no error message and no admin user exists. The only diagnostic path is querying the datastore directly.*

---

## Phase 3: Nginx and container networking

After a redeploy cycle, the frontend showed “API server unreachable.” Nginx had cached the UI container’s old IP at startup - Docker assigned new IPs after the volume wipe, but nginx didn’t re-resolve. `docker compose restart nginx_minimal` fixed it immediately.

*General Docker consideration: restart reverse proxies after downstream services get new IPs.*

---

## Phase 4: Connecting Filebeat to Elastic Cloud

### Elastic Serverless vs. Classic

The public deployment guide assumed classic Elastic Cloud with `cloud.id` and `cloud.auth`. The actual environment was Elastic Serverless - a meaningfully different deployment model:

| Classic | Serverless |
| --- | --- |
| `cloud.id` + `cloud.auth` | Direct ES URL + API key |
| Port 9200 | Port 443 |
| ILM supported | ILM not supported |
| Automatic index template setup | Manual index creation required |
| API key `encoded` format | `id:api_key` format |

### The API key problem

Getting a working API key took three attempts. Cloud console project API keys don’t authenticate against the data plane (`401`). An Elasticsearch API key with `read_ilm` privilege failed because ILM doesn’t exist in Serverless. The `encoded` base64 format that documentation recommends returned `401`. What finally worked:

```yaml
api_key: "6zXSj..."  # id:api_key format
```

Filebeat also tried to create an index template on first connection (`403 Forbidden`). Disabled template and ILM setup, created the index manually:

```yaml
setup.template.enabled: false
setup.ilm.enabled: false
```

```json
PUT ext-supply-chain-alerts
```

### Final Filebeat configuration

```yaml
filebeat.inputs:
  - type: filestream
    id: ext-supply-chain-alerts
    paths:
      - /watched/alerts/*.json
    parsers:
      - ndjson:
          target: ""
          overwrite_keys: true

output.elasticsearch:
  hosts: ["https://<deployment>.es.<region>.gcp.elastic.cloud:443"]
  api_key: "id:api_key"
  index: "ext-supply-chain-alerts"

setup.template.enabled: false
setup.ilm.enabled: false
```

---

## Phase 5: Filebeat’s three silent failures

Getting the alert from disk into Elasticsearch took three debugging cycles. Each problem produced zero error output.

**Problem 1: Twenty-two documents instead of one.** The script wrote pretty-printed JSON (`indent=2`). Filebeat’s NDJSON parser treats every newline as a document boundary, so each line became its own Elasticsearch document. Fix: `json.dumps(alert)` - single-line output.

**Problem 2: Filebeat ignored the new file.** After fixing the format and regenerating, nothing appeared. Filebeat tracks files by inode - the new file reused the same inode as the deleted one, so Filebeat believed it had already been processed. Fix: wipe the registry and restart.

**Problem 3: The missing byte.** Still nothing. `xxd` inspection revealed no trailing `0a` - no newline at end of file. Filebeat’s NDJSON parser requires a newline to mark the end of a record. Without it, the line sits in a buffer indefinitely. No error, no warning, no timeout. Fix: `path.write_text(json.dumps(alert) + "\\n")`.

*Three trivial details - JSON formatting, file identity semantics, and a single newline character - each caused a complete silent failure. In production, any one of these would mean alerts never reach the SIEM with nothing in the logs to explain why.*

---

## Phase 6: SIEM detection rule

The detection rule was first created with a `*` query against `ext-supply-chain-alerts`. During the Filebeat debugging above, the 22 malformed line-by-line documents each matched the rule independently, producing **over 100 false alerts**. Documents like `{"message": "{"}` were being treated as security findings.

Tightened the rule to `matched_rules: *` - only properly structured alert documents with a `matched_rules` field trigger the rule. After cleaning the malformed data, the rule fired exactly once on the valid alert.

---

## Phase 7: Testing

### False positive baseline

Two production extensions downloaded from the Chrome Web Store, submitted to Assemblyline, and compared against themselves:

| Extension | Size | Assemblyline verdict | Script result |
| --- | --- | --- | --- |
| uBlock Origin | 4.4 MB | Informative | ✔ `[OK]` |
| Bitwarden | 19.8 MB | Informative | ✔ `[OK]` |

Both are complex extensions with extensive JavaScript, multiple content scripts, and network references. Neither triggered any detection rule.

### Synthetic tampering test

A deliberately-tampered extension was built for end-to-end pipeline validation: a trivial baseline `.crx` containing only `manifest.json` and `worker.js`, and a modified version adding a `steal.js` content script, a new `evil-c2.example.com` reference in the worker, and a manifest update.

**Script output:**

```
[ALERT] Test Extension -- rules fired:
  ['NEW-DOMAIN-NEW-OR-UPDATED-BACKGROUND-SCRIPT',
   'NEW-DOMAIN-UPDATED-BACKGROUND-SCRIPT-AND-UPDATED-OR-ADDED-CONTENT-SCRIPT',
   'UPDATED-BACKGROUND-SCRIPT-AND-UPDATED-OR-ADDED-CONTENT-SCRIPT']
        New domains: ['evil-c2.example.com']
        New scripts: ['steal.js']
```

Three rules fired as expected. Alert JSON written to disk, ingested by Filebeat, indexed in Elasticsearch, rule fired in the SIEM - **full pipeline confirmation**.

### Cyberhaven supply chain simulation

The actual malicious Cyberhaven extension (v24.10.4) was pulled from the Chrome Web Store in late 2024 and is no longer available. A simulation was built using the current legitimate Cyberhaven extension, modified to match the documented IOCs from the [Red Canary report](https://redcanary.com/blog/threat-detection/assemblyline-browser-extensions/):

1. **Added `js/content.js`** — obfuscated content script using `atob()`, `eval()`, `XMLHttpRequest`, and `document.cookie` access
2. **Modified `js/worker.js`** — appended `fetch()` to `cyberhavenext.pro/api/beacon` (the actual C2 domain)
3. **Updated `manifest.json`** — added `content.js` matching `<all_urls>`, bumped version

**Script output:**

```
[ALERT] Cyberhaven Security Extension V3 -- rule fired:
  ['SCRIPT-UPDATES-WITH-ANOMALOUS-CHARACTERISTICS']
```

**Assemblyline detections (absent from clean version):** `Suspicious Activity Detected`, `Network Traffic Detected`, `Long One-Liner` (JsJaws); `Base64_Decoded` (FrankenStrings); `Phishing` (URLCreator) - seven new detections total. C2 domain `cyberhavenext.pro` identified in `new_domains`. Score jumped from 0 to 303.

The Cyberhaven simulation fired fewer structural rules than the synthetic test because the attacker's pattern - reusing an existing file (`js/worker.js`) rather than clearly-new scripts - evades the co-occurrence logic that the synthetic test was designed to trigger. The entropy anomaly and the seven new Assemblyline detections are what carried the detection in this case.

The Assemblyline signatures that fired on this simulation overlap directly with those documented in the Red Canary report (JsJaws, FrankenStrings, URLCreator), confirming the pipeline identifies the same behavioral patterns Red Canary validated across their 2,850 extension comparisons.

### Combined results

| Test | Type | Rules fired | Key signals |
| --- | --- | --- | --- |
| uBlock Origin (self) | FP baseline | — | `[OK]` No suspicious delta detected. |
| Bitwarden (self) | FP baseline | — | `[OK]` No suspicious delta detected. |
| Synthetic tampered ext | TP controlled | 3 | `evil-c2.example.com`, `steal.js`, worker changed |
| Cyberhaven simulation | TP realistic | 1 + 7 AL detections | `cyberhavenext.pro`, `content.js`, Base64, score 0→303 |

**False positive rate:** 0/2. **True positive rate:** 2/2.

---

## What this validation demonstrates

The pipeline catches both controlled tampering and a realistic supply-chain simulation end-to-end, with no false positives against two complex production extensions.

The infrastructure problems encountered along the way - the silent Assemblyline bootstrap failure, the Elastic Serverless documentation gaps, the three independent Filebeat failure modes that each produced zero error output - are the kind of engineering friction that only appears when you actually build and run something. They’re documented here because the gap between “detection designed” and “detection working” usually lives in details like these, and because each one would be a production incident with no diagnostic path if it happened in an unfamiliar environment.

The detection logic itself, designed in [investigation.md](./investigation.md), held up: every rule that should have fired did fire, in the combinations predicted by Red Canary’s original validation across 2,850 extension comparisons.

---

## Adjustments made during validation

1. **Filebeat output format** - single-line NDJSON with trailing newline.
2. **SIEM rule tightening** - `matched_rules: *` instead of * to prevent matches against malformed data.
3. **Elastic Serverless configuration** - port 443, `id:api_key` format, disabled template/ILM, manual index creation.

---

## Detection pipeline limitations

- Static analysis only - runtime-only behavior (time-delayed C2, conditional execution) is not detected
- Domain extraction uses regex over result sections and file content - heavily obfuscated URLs may be missed
- No baseline for first-version extensions - entropy comparison requires a prior version
- Pipeline is not real-time - minutes of latency across submission, analysis, comparison, ingestion, and rule execution
- Testing used a simulated malicious Cyberhaven extension based on documented IOCs, not the original v24.10.4 package (removed from distribution)

---

## Future improvements

This pipeline was validated manually. For production several things could be added:

- **Inventory monitoring** - scheduled script detecting extension version changes, triggering submissions automatically
- **Submission orchestration** - `run_comparison.sh` handling the full cycle from submission through alert generation
- **Broader FP testing** - validating against a larger set of legitimate updates to establish noise levels per rule
- **Additional malicious samples** - Trust Wallet, PaperPanda, QuickLens, Color Picker Tool if packages become available
- **Alerting connectors** - email/Slack/ticket integration for SOC visibility
- **Dashboard** - Kibana visualization of alert trends and extension coverage

For a home lab, the manual pipeline with end-to-end validation against both legitimate and simulated malicious extensions was more than enough to demonstrate the detection concept and the engineering involved.

---

## Final pipeline

```
Extension update detected (inventory monitoring)
    ↓
Both .crx versions submitted to Assemblyline (manual or API)
    ↓
Assemblyline returns JSON reports
    (Extract, JsJaws, URLCreator, FrankenStrings, Characterize)
    ↓
compare_extension.py
    ↓  Rules fire → single-line NDJSON + newline to /watched/alerts/
    ↓
Filebeat (filestream input, NDJSON parser)
    ↓  Ingests to ext-supply-chain-alerts index
    ↓
Elastic Security detection rule
    ↓  Custom query: matched_rules: *
    ↓  Every 5 min, Severity: High
    ↓
SOC triage
```

*Validated April 15–16, 2026. Synthetic supply chain compromise and realistic Cyberhaven-style attack both detected end-to-end. Zero false positives against production extensions.*
