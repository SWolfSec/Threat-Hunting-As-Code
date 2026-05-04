---
title: "Lumma Stealer SaaS Session Hijacking Campaign Q3 2026"
campaign_slug: "lumma-stealer-saas-session-hijack-2026-q3"
threat_actor_type: "cybercrime"
threat_actor_name: "Lumma-affiliated crimeware operators"
start_date: "2026-07-01"
end_date: null
description: "Track and reduce session hijacking activity tied to Lumma-style infostealer infections that target browser tokens and SaaS authentication artifacts. This umbrella coordinates hunts across endpoint, identity, and SaaS telemetry, then rolls findings into measurable improvements in detection coverage, response speed, and executive reporting."
mitre_tactics:
  - "TA0001"
  - "TA0006"
  - "TA0005"
  - "TA0011"
mitre_techniques:
  - "T1059.001"
  - "T1555"
  - "T1539"
  - "T1078"
  - "T1528"
status: "draft"
---

> [!CAUTION]
> [!IMPORTANT] **Draft campaign umbrella (bootstrap)**
> 
> **Prefilled from intake** (issue form → YAML frontmatter above, plus **Campaign overview** if imported):
> - umbrella metadata for reporting and hunt linkage
> - objectives table, references, and MITRE themes row when the form had that text
> 
> **You still need to complete** (high-level only — no hunt queries here):
> - Threat actor context (confidence, narrative themes beyond IDs)
> - tighten success signals on objective rows if you used the intake bullet list
> 
> _Generated from GitHub issue #8. Remove this callout when the umbrella is ready for formal review._

> **This file is high-level only.** Do not duplicate low-level hunt details here — they belong in individual hunt files under `hunts/` and will be linked below once the parser wires them in.

# 🗂️ Campaign: Lumma Stealer SaaS Session Hijacking Campaign Q3 2026

| Field | Value |
| --- | --- |
| **Slug** | `lumma-stealer-saas-session-hijack-2026-q3` |
| **Status** | `draft` |
| **Window** | `2026-07-01` → _ongoing_ |
| **Primary actor** | `Lumma-affiliated crimeware operators` (`cybercrime`) |

---

## 📋 Campaign Overview

> **Prefilled from issue form** (issue #8). Expand/refine scope and sourcing notes below as the umbrella matures.

```markdown
## Context
Commodity infostealer crews continue to harvest browser credentials, cookies, and session tokens, enabling downstream access to cloud and SaaS services without obvious brute-force behavior. Recent reporting and internal telemetry suggest overlap with Lumma-style tradecraft.

## Scope
Focus on employee endpoints and identity workflows where stolen artifacts can be replayed into Microsoft 365, Google Workspace, and key internal SaaS applications. Include pre-access malware signals and post-access account/session anomalies. Exclude ransomware post-exploitation for this umbrella (tracked separately).

## Intelligence / sourcing
- Vendor threat reports on Lumma malware delivery and token theft behavior
- Internal SOC cases involving suspicious impossible-travel and token reuse
- Identity provider detections for abnormal session patterns
- SaaS audit findings from recent incident reviews

## Notes for hunters
- Prioritize detections that correlate endpoint infostealer behavior with identity/session anomalies.
- Treat suspicious “clean login” events after malware alerts as high-risk.
- Capture reusable pivot logic for token replay investigations.
- Document telemetry blind spots and compensating controls.
```

---

## 🎭 Threat Actor Context

<!-- HUNTER TODO: complete this umbrella section (high-level only) -->


High-level attribution and motivation only — not hunt hypotheses.

| Topic | Notes |
| --- | --- |
| **Actor name / cluster** | Lumma-affiliated crimeware operators |
| **Actor type** | cybercrime |
| **Confidence** | low / medium / high (qualitative) |
| **Known TTP themes** | TA0001, TA0006, TA0005, TA0011, T1059.001, T1555, T1539, T1078, T1528 |

---

## 🎯 High-level Objectives

<!-- HUNTER TODO: complete this umbrella section (high-level only) -->


What this **umbrella** should achieve for the program (not per-hunt execution steps).

| Objective | Success signal (umbrella-level) |
| --- | --- |
| Prioritized hunt backlog linked to lumma-stealer-saas-session-hijack-2026-q3 | _(define a measurable success signal)_ |
| Improved visibility into endpoint-to-identity kill chain transitions | _(define a measurable success signal)_ |
| Detection content for suspicious token/session reuse | _(define a measurable success signal)_ |
| Reduced triage time for account takeover investigations | _(define a measurable success signal)_ |
| Leadership rollup showing campaign-linked hunt progress and outcomes | _(define a measurable success signal)_ |

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

<!-- HUNTER TODO: complete this umbrella section (high-level only) -->


Stable links, report titles, or internal ticket IDs (one per line). Prefer public URLs when sharing outside the team.

- https://attack.mitre.org/
- Vendor report: Lumma stealer campaign update (Q3 2026)
- Internal ticket: TH-2418
- Internal incident review: IR-2026-117