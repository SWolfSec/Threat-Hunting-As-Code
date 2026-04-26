---
# High-level campaign umbrella — not a hunt artifact.
# Individual hunts link here via `campaign_slug` in their frontmatter.

title: "Replace with campaign display title"
campaign_slug: "replace-with-kebab-case-slug"

threat_actor_type: "unknown"
threat_actor_name: "Unknown"

start_date: "YYYY-MM-DD"
# Omit or set to null if ongoing / unknown end.
end_date: null

description: "One-paragraph umbrella summary for dashboards and triage."

mitre_tactics:
  - "TA0000"

mitre_techniques:
  - "T0000"

# Suggested values: draft | active | completed | archived
status: "draft"
---

> [!CAUTION]
> **This file is high-level only.** Do not duplicate low-level hunt details here — they belong in individual hunt files under `hunts/` and will be linked below once the parser wires them in.

# 🗂️ Campaign: Replace with Title

| Field | Value |
| --- | --- |
| **Slug** | `replace-with-kebab-case-slug` |
| **Status** | `draft` |
| **Window** | `YYYY-MM-DD` → _ongoing or end date_ |
| **Primary actor** | `Unknown` (`unknown`) |

---

## 📋 Campaign Overview

Summarize the **campaign umbrella** in plain language: what threat activity or narrative this grouping represents, why it exists as a container, and what time horizon or business context applies.

- **Narrative (2–4 sentences)**:
- **Scope boundaries** (what is intentionally *out* of this umbrella):
- **Relationship to intelligence** (public reporting, IR themes, sector trends — no paste of classified or sensitive operational detail):

---

## 🎭 Threat Actor Context

High-level attribution and motivation only — not hunt hypotheses.

| Topic | Notes |
| --- | --- |
| **Actor name / cluster** | |
| **Actor type** | |
| **Confidence** | low / medium / high (qualitative) |
| **Known TTP themes** | bullet list at narrative level only |

---

## 🎯 High-level Objectives

What this **umbrella** should achieve for the program (not per-hunt execution steps).

| Objective | Success signal (umbrella-level) |
| --- | --- |
| Example: align hunt backlog to campaign TTPs | Backlog items tagged with this `campaign_slug` |
| Example: improve leadership visibility | Quarterly rollup references this campaign |

---

## 🔗 Linked Hunts

> **Auto-populated region.** The metrics parser will replace content between the markers below with linked hunt files, titles, and summary stats. **Do not hand-edit** between markers after automation is enabled.

<!-- auto:linked-hunts:start -->
| Hunt ID | Title | Status | Link |
| --- | --- | --- | --- |
| _pending_ | _Parser will populate this table_ | — | — |
<!-- auto:linked-hunts:end -->

---

## 📊 Aggregated outcomes

> **Auto-populated region.** Rollups across **child hunts** linked to this `campaign_slug` (e.g. detection/prevention/visibility counts). **Do not hand-edit** between markers after automation is enabled.

<!-- auto:aggregated-outcomes:start -->
| Metric | Value |
| --- | ---: |
| Child hunts linked | _TBD_ |
| Total detections (rollup) | _TBD_ |
| Total preventions (rollup) | _TBD_ |
| Visibility gains (rollup) | _TBD_ |
<!-- auto:aggregated-outcomes:end -->

---

## 📚 References

Stable links, report titles, or internal ticket IDs (one per line). Prefer public URLs when sharing outside the team.

- 
