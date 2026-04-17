# compare_extension.py (adapted for real Assemblyline report format)
# Input:  Assemblyline full submission JSON reports for old and new extension versions + metadata file.
# Output: If alert conditions are met, writes alert .json to /watched/alerts/
# Usage: python compare_extension.py old_report.json new_report.json –meta meta.json

import json
import hashlib
import argparse
import re
from datetime import datetime, timezone
from pathlib import Path

ALERT_OUTPUT_DIR = Path(”/watched/alerts”)

def extract_api_response(report: dict) -> dict:
“”“Unwrap api_response if present.”””
return report.get(“api_response”, report)

def get_file_names(report: dict) -> dict:
“”“Return {filename: sha256} from file_tree children.”””
result = {}
tree = report.get(“file_tree”, {})
for root_sha, root_info in tree.items():
for child_sha, child_info in root_info.get(“children”, {}).items():
for name in child_info.get(“name”, []):
result[name] = child_sha
return result

def get_file_entropy(report: dict) -> dict:
“”“Return {filename: entropy} from file_infos + file_tree name mapping.”””
names = get_file_names(report)
infos = report.get(“file_infos”, {})
result = {}
for name, sha in names.items():
if sha in infos:
result[name] = infos[sha].get(“entropy”, 0)
return result

def get_domains_from_results(report: dict) -> set:
“”“Extract domains from result sections (URLs, tags, body text).”””
domains = set()
domain_pattern = re.compile(
r’https?://([a-zA-Z0-9-]+(?:.[a-zA-Z0-9-]+)+)’
)
results = report.get(“results”, {})
for key, result in results.items():
sections = result.get(“result”, {}).get(“sections”, [])
for section in sections:
body = section.get(“body”, {})
# Check body text/data for URLs
if isinstance(body, str):
domains.update(domain_pattern.findall(body))
elif isinstance(body, dict):
data = body.get(“data”, “”)
if isinstance(data, str):
domains.update(domain_pattern.findall(data))
# Check tags
tags = section.get(“tags”, {})
for tag_type, tag_values in tags.items():
if “domain” in tag_type or “uri” in tag_type or “url” in tag_type:
if isinstance(tag_values, list):
for v in tag_values:
domains.update(domain_pattern.findall(str(v)))
# Also add raw value if it looks like a domain
if “.” in str(v) and “/” not in str(v):
domains.add(str(v))
# Check heuristics
heuristic = section.get(“heuristic”, {})
if heuristic:
# Score-bearing heuristics might reference domains
pass
# Also check file_infos ascii/hex for URLs
for sha, info in report.get(“file_infos”, {}).items():
ascii_content = info.get(“ascii”, “”)
domains.update(domain_pattern.findall(ascii_content))
return domains

def get_scores(report: dict) -> dict:
“”“Return {result_key: score} for all results.”””
scores = {}
results = report.get(“results”, {})
for key, result in results.items():
score = result.get(“result”, {}).get(“score”, 0)
if score > 0:
scores[key] = score
return scores

def get_heuristics(report: dict) -> set:
“”“Extract heuristic names/IDs from result sections.”””
heuristics = set()
results = report.get(“results”, {})
for key, result in results.items():
sections = result.get(“result”, {}).get(“sections”, [])
for section in sections:
h = section.get(“heuristic”, {})
if h:
heur_id = h.get(“heur_id”, “”)
name = h.get(“name”, “”)
if heur_id:
heuristics.add(f”{heur_id}:{name}”)
return heuristics

def compare(old_raw: dict, new_raw: dict, meta: dict) -> dict | None:
old = extract_api_response(old_raw)
new = extract_api_response(new_raw)

```
matched_rules = []
notes = []

# Signal 1: New domains in new version
old_domains = get_domains_from_results(old)
new_domains = get_domains_from_results(new)
added_domains = new_domains - old_domains

# Signal 2: worker.js changed (hash diff)
old_files = get_file_names(old)
new_files = get_file_names(new)
old_worker_hash = old_files.get("worker.js")
new_worker_hash = new_files.get("worker.js")
worker_updated = bool(old_worker_hash and new_worker_hash and old_worker_hash != new_worker_hash)

# Signal 3: New content scripts (files in new but not in old)
old_file_set = set(old_files.keys())
new_file_set = set(new_files.keys())
new_content_scripts = new_file_set - old_file_set
# Remove manifest.json from consideration
new_content_scripts.discard("manifest.json")

# Signal 4: New heuristics/detections
old_heuristics = get_heuristics(old)
new_heuristics = get_heuristics(new)
new_detections = new_heuristics - old_heuristics

# Signal 5: Entropy anomaly
old_entropy = get_file_entropy(old)
new_entropy = get_file_entropy(new)
anomalous_scripts = []
for script, new_ent in new_entropy.items():
    old_ent = old_entropy.get(script, new_ent)
    if old_ent > 0:
        delta_pct = abs(new_ent - old_ent) / old_ent * 100
    else:
        delta_pct = 100 if new_ent > 0 else 0
    # Flag if entropy is high or changed significantly
    if new_ent > 6.0 or delta_pct > 50:
        anomalous_scripts.append({
            "script": script,
            "old_entropy": round(old_ent, 3),
            "new_entropy": round(new_ent, 3),
            "delta_pct": round(delta_pct, 1)
        })
        notes.append(f"{script}: entropy {old_ent:.2f} → {new_ent:.2f} ({delta_pct:.1f}% change)")

# Signal 6: Score increase
old_max_score = old.get("max_score", 0)
new_max_score = new.get("max_score", 0)
score_increased = new_max_score > old_max_score

if score_increased:
    notes.append(f"Max score increased: {old_max_score} → {new_max_score}")

# Rule matching

# Broadest: new domain + updated background script
if added_domains and worker_updated:
    matched_rules.append("NEW-DOMAIN-NEW-OR-UPDATED-BACKGROUND-SCRIPT")

# New domain + updated worker + new content script
if added_domains and worker_updated and new_content_scripts:
    matched_rules.append("NEW-DOMAIN-UPDATED-BACKGROUND-SCRIPT-AND-UPDATED-OR-ADDED-CONTENT-SCRIPT")

# Updated worker + new content script
if worker_updated and new_content_scripts:
    matched_rules.append("UPDATED-BACKGROUND-SCRIPT-AND-UPDATED-OR-ADDED-CONTENT-SCRIPT")

# Entropy anomaly
if anomalous_scripts:
    matched_rules.append("SCRIPT-UPDATES-WITH-ANOMALOUS-CHARACTERISTICS")

# New detections + domain + worker + content script
if added_domains and new_detections and worker_updated and new_content_scripts:
    matched_rules.append(
        "NEW-DOMAIN-NEW-ASSEMBLYLINE-DETECTIONS-UPDATED-BACKGROUND-SCRIPT-AND-CONTENT-SCRIPT"
    )

# Additional: score increase + new files
if score_increased and new_content_scripts:
    matched_rules.append("SCORE-INCREASE-WITH-NEW-CONTENT-SCRIPTS")

if not matched_rules:
    return None

return {
    "@timestamp":           datetime.now(timezone.utc).isoformat(),
    "extension_id":         meta["id"],
    "extension_name":       meta["name"],
    "old_version":          meta["old_version"],
    "new_version":          meta["new_version"],
    "matched_rules":        matched_rules,
    "new_domains":          list(added_domains),
    "new_content_scripts":  list(new_content_scripts),
    "new_detections":       list(new_detections),
    "anomalous_scripts":    anomalous_scripts,
    "old_max_score":        old_max_score,
    "new_max_score":        new_max_score,
    "notes":                notes,
}
```

def main():
parser = argparse.ArgumentParser()
parser.add_argument(“old_report”, type=Path)
parser.add_argument(“new_report”, type=Path)
parser.add_argument(”–meta”, type=Path, required=True)
args = parser.parse_args()

```
old = json.loads(args.old_report.read_text())
new = json.loads(args.new_report.read_text())
meta = json.loads(args.meta.read_text())

alert = compare(old, new, meta)

if alert:
    ALERT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    uid = hashlib.md5(f"{meta['id']}-{meta['new_version']}".encode()).hexdigest()[:8]
    path = ALERT_OUTPUT_DIR / f"ext-alert-{uid}.json"
    path.write_text(json.dumps(alert, indent=2))
    print(f"[ALERT] {alert['extension_name']} — rules fired: {alert['matched_rules']}")
    print(f"        New domains: {alert['new_domains']}")
    print(f"        New scripts: {alert['new_content_scripts']}")
    print(f"        Score: {alert['old_max_score']} → {alert['new_max_score']}")
    print(f"        Written to {path}")
else:
    print("[OK] No suspicious delta detected.")
```

if **name** == “**main**”:
main()
