# Detection Validation: Scarlet Goldfinch / ClickFix Paste-and-Run

**Based on [Original Conceptual Detection](./investigation.md#detection-plan) (Scarlet Goldfinch case)*


---

## What we’re building and why

Most threat actors change over time. What makes Scarlet Goldfinch worth careful study is the speed of its adaptation: seven distinct epochs of initial-access implementation across 2025, each one breaking the prior epoch’s detection logic. A defender writing rules against specific command-line strings would ship the rule, watch it succeed for weeks, watch it silently fail when the next epoch rolled out, rewrite for the new pattern, and repeat. The labor-per-detection stays high. The detection’s shelf life stays short. The adversary wins the asymmetry.

This pipeline was designed to test whether a behavioral chain detection (anchored in process lineage rather than command-line strings) can survive that arms race. What follows is the full build: the decisions behind each component, what broke during testing, how each issue was resolved, and how the detection performed against three simulated Scarlet Goldfinch epochs.

The first idea was to write a single three-stage EQL sequence in Elastic Security: Run-dialog-spawned interpreter, that interpreter spawning a LOLBin, that LOLBin reaching external infrastructure. One rule, three stages, joined by `process.entity_id`. Clean, single artifact, easy to triage. That instinct was right conceptually, but wrong for this specific Elastic deployment, for reasons that took several hours of debugging to surface.

What eventually succeeded during the testing was a two-rule architecture. Rule 1 catches the process chain. Rule 2 catches the LOLBin egress. Both anchor on the same behavioral invariants the investigation build on. The split is implementation friction, not a weakening of the logic.

### Environment used:

- Windows 10 Pro VM running on Oracle VirtualBox (4 vCPUs, 8 GB RAM)
- Sysmon v15.15 with SwiftOnSecurity community config
- Elastic Cloud Serverless (Security project, GCP us-east4)
- Elastic Agent enrolled via Fleet, Elastic Defend integration enabled, Windows integration with Sysmon Operational data stream enabled
- Test HTTP target: `http://example.com/` (resolves to Cloudflare IPv4 and IPv6, non-RFC1918, suitable for external egress validation)

The lab uses both Elastic Defend and Sysmon. Defend provides the richer process and network telemetry the rules query against, and Sysmon was kept enabled to verify whether sequence joins behaved differently across the two telemetry sources. They behaved differently in practice, documented below.

---

# Building the Pipeline

## Phase 1: Initial deployment and the silent miss

The detection was first deployed as a single three-stage EQL sequence joining process events to a network event by `process.entity_id`. The rule compiled cleanly, deployed without errors, and showed “succeeded” in the Rule Run History on every five-minute schedule.

It just didn’t fire on confirmed test executions.

The first Epoch 1 simulation (`cmd /c curl -o %tmp%\\sgtest.html <http://example.com/>`) produced the expected lineage in Discover: `explorer.exe → cmd.exe → curl.exe → (network egress)`. All three events were present. The entity_ids were consistent. The rule was enabled, scheduled, and processing the right time window. No alert.

---

## Phase 2: Cross-data-stream debugging

The diagnostic process was systematic narrowing. Strip the rule down until something fires, then add complexity back.

**Step 1: confirm the events exist.** Direct Discover queries for `process.name: "curl.exe" and event.action: "start"` returned the expected events. The `connection_attempted` network events also existed, with the same `process.entity_id` as the curl process start event.

**Step 2: confirm the join key works.** Side-by-side comparison of the curl proc  in ess event and the curl network event showed identical `process.entity_id` values (e.g., `O3wNOln4IlaJjthFEbbEBA`). The events were correctly tied to the same process.

**Step 3: simplify to two stages.** The original rule had three stages. Removing the network stage and testing with just the cmd → curl process chain produced an immediate fire. The first two stages worked.

**Step 4: re-add the network stage minimally.** Adding back the network stage with only `process.name == "curl.exe"` (no event.action filter, no IP filter) caused the rule to silently produce no results. Even with everything else stripped to its minimum.

**Step 5: test cross-data-stream join in isolation.** A two-stage rule pairing the curl process event with the curl network event by entity_id (skipping the explorer.exe lineage entirely) also produced no results.

That last test was the answer. Elastic Defend writes process events to `endpoint.events.process` and network events to `endpoint.events.network`. EQL sequences in this deployment did not correlate events across these two data streams, despite both being under the same `logs-*` index pattern and despite the entity_id values matching exactly.

*Worth noting: this is environment-specific behavior. Different Elastic deployments, different versions, and different configurations may handle cross-data-stream sequences correctly. The honest scope is: in this lab, with this deployment, sequences across `endpoint.events.process` and `endpoint.events.network` did not fire.*

---

## Phase 3: The two-rule architecture

Rather than fight the constraint, the detection was restructured into two correlated rules. The behavioral invariants from the investigation - paste-and-run process lineage, LOLBin external egress - both still get caught. They just get caught by separate rules that triage logic correlates afterward.

**Rule 1 (Process chain):** EQL sequence within `endpoint.events.process` only, catching `explorer.exe → command interpreter → LOLBin` lineage. Full rule in [detection.eql](./detection.eql)

**Rule 2 (LOLBin egress):** KQL custom query on `endpoint.events.network`, catching LOLBin external connections regardless of process lineage. Full rule in [detection-lolbin.kql](./detection-lolbin.kql)

Triage correlation: when both rules fire on the same `host.name` within two minutes, that is the high-confidence indicator. Either rule firing alone is medium confidence and warrants investigation but does not by itself confirm Scarlet Goldfinch activity.

### The entity_id join correction

A second adjustment surfaced during the same debugging cycle. The original Rule 1 used `sequence by process.entity_id` for both stages, joining on the same field. That works in some telemetry sources (notably Sysmon, where related processes can share GUID context) but not in Elastic Defend.

In Defend, each process has its own unique `process.entity_id`. Parent-child relationships are expressed through `process.parent.entity_id` on the child event. A correct join between two consecutive process stages links the parent’s `entity_id` in stage 1 to the child’s `parent.entity_id` in stage 2:

```
[stage 1: cmd.exe with parent explorer.exe] by process.entity_id
[stage 2: curl.exe with parent cmd.exe] by process.parent.entity_id
```

After both adjustments (split into two rules + corrected entity_id join), Rule 1 fired correctly on the first Epoch 1 test.

---

## Phase 4: Testing

### True positive tests: epoch simulations

Each simulation reproduces the structural shape of the corresponding Scarlet Goldfinch epoch using a benign payload (download from [example.com](http://example.com/)). Real malware was not detonated. The detection target is the process lineage and network egress, not the payload.

**Epoch 1 (direct curl):**

```batch
cmd /c curl -o %tmp%\\sgtest.html <http://example.com/> && notepad %tmp%\\sgtest.html
```

Pasted into Run dialog. Observed lineage: `explorer.exe → cmd.exe → curl.exe → (network egress to example.com IPv6)`. Both rules fired within seconds of each other.

This confirms baseline behavior. Direct curl invocation through Run dialog produces the lineage the rules expect, and both detection layers catch it.

**Epoch 3 (forfiles intermediate parent):**

```batch
forfiles /p c:\\windows\\system32 /m notepad.exe /c "cmd /c curl -o %tmp%\\sgtest3.html <http://example.com/>"
```

Pasted into Run dialog. Observed lineage: `explorer.exe → forfiles.exe → cmd.exe → curl.exe → (network egress)`. Rule 1 did not fire. Rule 2 fired.

This is a meaningful finding. Rule 1’s stage 1 requires the command interpreter to be a direct child of `explorer.exe`. The `forfiles.exe` process inserted itself between the two, breaking that match. The behavioral pattern is still present in the telemetry, but Rule 1 as written is anchored too tightly on the direct parent relationship.

This is a documented limitation, though, not a defect. The layered architecture means Epoch 3 is still detected, just at the network egress layer rather than at the lineage layer. Rule 1 stays anchored to the cleanest paste-and-run signature; Rule 2 provides defense in depth.

**Epoch 7 (substring obfuscation):**

Reproducing Epoch 7 in the lab required adaptation. The original Scarlet Goldfinch syntax uses `cmd.exe /v:on` with delayed environment variable expansion (`!l:~1,1!` style). Pasted directly into Run dialog through a `cmd /v:on /c "..."` invocation, the substring expansion did not execute reliably. The outer cmd appears to consume the exclamation marks before the inner cmd can use them for delayed expansion. cmd.exe completed without spawning curl.

The functional equivalent that did execute reliably uses standard variable substitution (`%l:~1,1%`) inside a batch file invoked from Run dialog:

```
@echo off
set l=ycyyruyly
%l:~1,1%%l:~5,1%%l:~4,1%%l:~7,1% -o %tmp%\\sgtest7.html <http://example.com/>
```

Run dialog invocation:

```batch
cmd /c C:\\Users\\vboxuser\\Desktop\\test7.bat
```

This is structurally the same obfuscation technique. The `curl` keyword is constructed at runtime from substring extraction of a benign-looking variable, just using non-delayed expansion, which is more shell-portable.

Observed lineage: `explorer.exe → cmd.exe → curl.exe → (network egress)`. The cmd.exe `process.command_line` contained the obfuscated string `ycyyruyly` and substring indexing operators. The curl.exe `process.command_line` showed the resolved arguments after expansion. Both rules fired.

This is the test that validates the core thesis. The command-line arguments to cmd.exe are visibly obfuscated. A string-matching rule looking for `curl` in the cmd.exe command line would not have fired. The behavioral chain detection fired anyway because the resolved process is still `curl.exe` with `cmd.exe` as parent and `explorer.exe` as grandparent. Process names survive command-line obfuscation, and the rule anchors on process names.

*Worth mentioning: the lab reproduced the technique rather than the exact recorded syntax. Real attackers debug their commands against real victim environments. Lab reproductions sometimes need small adjustments to run in different shell contexts. The idea is that the detection logic does not depend on which expansion syntax is used, it depends on what processes spawn. Both forms produce the same downstream process telemetry.*

### False positive tests

**Administrator Run-dialog curl** (`cmd /c curl <http://example.com/>` pasted into Run): both rules fired. This is the known false positive class documented in the investigation. The behavioral pattern matches because the rules cannot distinguish attacker-induced pastes from admin-induced pastes from telemetry alone.

**Browser-launched download and open**: an image file was downloaded through Microsoft Edge and opened from Downloads, launching the default image viewer (Photos.exe). Observed lineage: `msedge.exe` created the file, then `explorer.exe → Photos.exe` when opened. No LOLBins involved. Neither rule fired. Expected outcome.

**Scheduled task running curl**: a scheduled task invoked `cmd.exe /c curl <http://example.com/`> once. Observed lineage: `svchost.exe → cmd.exe → curl.exe → (network egress)`. The parent of cmd.exe was svchost.exe (Task Scheduler service host), not explorer.exe. Rule 1 did not fire (parent mismatch). Rule 2 did fire (curl made an external connection regardless of how it was launched).

This is also worth noting. Rule 2 will fire on legitimate scheduled task egress in environments where curl is used in scheduled administrative scripts. In production deployments where this pattern exists, Rule 2 either needs scoping to non-svchost ancestry or needs to be paired with Rule 1 as a stricter co-occurrence requirement.

### Combined results

| Test | Type | Rule 1 | Rule 2 | Notes |
| --- | --- | --- | --- | --- |
| Epoch 1 (direct curl) | TP | ✔ | ✔ | Both detection layers triggered |
| Epoch 3 (forfiles variant) | TP | ✘ | ✔ | Documented limitation: intermediate parent breaks Rule 1 stage 1 |
| Epoch 7 (substring obfuscation) | TP | ✔ | ✔ | Behavioral invariance confirmed despite command-line obfuscation |
| Admin Run-dialog curl | Known FP | ✔ | ✔ | Acknowledged FP class for both rules |
| Browser download and open | Benign | ✘ | ✘ | No LOLBin involved, no command interpreter from explorer.exe |
| Scheduled task curl | Benign | ✘ | ✔ | Rule 2 noise source documented |

**True positive coverage:** all three tested epochs caught by at least one rule. Epochs 1 and 7 fire both rules. Epoch 3 fires only Rule 2.

**False positive surface:** Rule 1 cleanly avoids browser and scheduled-task patterns but does fire on admin Run-dialog use. Rule 2 fires on all curl egress regardless of context, which is a known noise source needing tuning in production.

---

## What this validation demonstrates

The two-rule detection catches all three tested Scarlet Goldfinch epochs at the layer the investigation argued for. The Epoch 7 result is the most interesting one: command-line obfuscation that would defeat string-matching rules does not affect detection rules anchored in process names and lineage. Process names survive the decode step, regardless of how the recipe to reach them is scrambled.

The Epoch 3 result is also informative. Rule 1 missed it because of an intermediate process between explorer.exe and the command interpreter. The rule could be broadened to allow intermediate LOLBin parents at the cost of more false positives, or kept tight at the cost of relying on Rule 2 for that variant. The chosen position (keep Rule 1 tight, rely on layered architecture) is intentional and documented above.

The cross-data-stream EQL constraint is the engineering finding worth naming. Single-rule three-stage sequences across `endpoint.events.process` and `endpoint.events.network` did not fire in this deployment despite identical entity_ids. The two-rule architecture is the workaround that produced reliable detection. In a different Elastic environment - newer version, different configuration - a single-rule design might work and would be operationally simpler. Worth revisiting after future deployments.

---

## Adjustments made during validation

1. **Split into two correlated rules** instead of single three-stage EQL sequence, due to cross-data-stream join behavior in this deployment.
2. **Corrected entity_id join shape** in Rule 1 from `sequence by process.entity_id` (assumes shared entity_id across processes) to parent-child join (`process.entity_id` linked to next stage’s `process.parent.entity_id`).
3. **Epoch 7 reproduction adapted** from `!l:~1,1!` delayed expansion to `%l:~1,1%` direct expansion in a batch file, because the original syntax did not reliably execute through Run dialog. Detection logic unchanged, only the test command form differs.

---

## Detection pipeline limitations

- **Intermediate parent processes break Rule 1** (Epoch 3 pattern). Rule 2 catches these at the egress layer but Rule 1 misses them. Documented limitation, not a bug.
- **Process-tree-breaking techniques bypass Rule 1 entirely.** Scarlet Goldfinch’s Epoch 5 used `Invoke-CimMethod` to launch processes through WMI, reparenting under `WmiPrvSE.exe`. A companion rule targeting that pattern is needed for full coverage.
- **FileFix variants** (paste-into-File-Explorer-address-bar) produce different process lineage and require separate coverage.
- **Renamed binaries depend on `process.pe.original_file_name` capture.** If the endpoint sensor does not populate this field, the renamed-LOLBin fallback in Rule 1 stage 2 is inactive.
- **Administrator paste-and-run workflows fire both rules** as a known FP class. Production deployments need either user-context scoping or a paired user-activity signal.
- **Three FP scenarios is statistically meaningless** for production noise estimation. Real noise levels need broader testing against diverse user populations and longer time windows.

---

## Future improvements

This pipeline was validated against three Scarlet Goldfinch epochs and three FP scenarios in a controlled lab. For production, several extensions are worth considering:

- **Companion rule for Invoke-CimMethod variants** targeting WMI-spawned children whose grandparent ancestry traces back to a browser or explorer.exe, covering Epoch 5
- **FileFix coverage** by extending Rule 1 or writing a third rule for paste-into-address-bar lineages
- **Broader FP baseline** against historical production telemetry to establish real noise levels per rule
- **User-context scoping** to reduce FP rate from administrator workflows where appropriate
- **Cross-data-stream sequence retest** when this Elastic deployment is upgraded - newer versions may handle sequences across `endpoint.events.process` and `endpoint.events.network` correctly, allowing consolidation back into a single three-stage rule

For a home lab, the manual two-rule pipeline with end-to-end validation against three documented Scarlet Goldfinch epochs was more than enough to check the detection concept and the engineering involved.

---

## Final pipeline

```
User pastes command into Run dialog (or scheduled lure delivery)
    ↓
Process chain: explorer.exe → cmd/pwsh/wscript → LOLBin
    ↓
Elastic Defend captures process events (endpoint.events.process)
    ↓
LOLBin makes outbound network connection
    ↓
Elastic Defend captures network event (endpoint.events.network)
    ↓
Rule 1 (EQL sequence) fires on process chain pattern
Rule 2 (KQL query) fires on LOLBin external egress
    ↓
SOC triage: co-occurrence within 2m on same host = high confidence
```

*Validated April 24, 2026. Three Scarlet Goldfinch epoch simulations and three FP scenarios tested end-to-end. All three TP epochs caught by at least one rule, Epoch 1 and Epoch 7 caught by both.*
