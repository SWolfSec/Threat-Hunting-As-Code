---
title: "Scattered Spider MFA Fatigue & Helpdesk Social Engineering Campaign Q2 2026"
campaign_slug: "scattered-spider-mfa-fatigue-2026"
threat_actor_type: "cybercrime"
threat_actor_name: "Scattered Spider (UNC3944)"
start_date: "2026-03-01"
end_date: null
description: "Ongoing Scattered Spider campaign using MFA push bombing, MFA fatigue, and social engineering of helpdesk staff to bypass MFA and gain initial access to corporate environments. Targets include Okta, Entra ID, and SaaS applications. Goal is credential access followed by ransomware deployment or data exfiltration."
mitre_tactics:
  - "TA0001"
  - "TA0006"
  - "TA0008"
mitre_techniques:
  - "T1556.004"
  - "T1621"
  - "T1199"
  - "T1566.002"
status: "draft"
---

> [!CAUTION]
> **This file is high-level only.** Do not duplicate low-level hunt details here — they belong in individual hunt files under `hunts/` and will be linked below once the parser wires them in.

# 🗂️ Campaign: Scattered Spider MFA Fatigue & Helpdesk Social Engineering Campaign Q2 2026

| Field | Value |
| --- | --- |
| **Slug** | `scattered-spider-mfa-fatigue-2026` |
| **Status** | `draft` |
| **Window** | `2026-03-01` → _ongoing_ |
| **Primary actor** | `Scattered Spider (UNC3944)` (`cybercrime`) |

---

## 📋 Campaign Overview

## Context

Scattered Spider (UNC3944) is a financially motivated threat group known for aggressive social engineering and living-off-the-land techniques. As of April 2026 they remain one of the most active initial-access brokers feeding ransomware operations.

## Scope
This campaign focuses on MFA fatigue / push bombing against contractor and employee accounts, followed by helpdesk social engineering to reset or approve access. Primary targets are Ok ta, Microsoft Entra ID, and downstream SaaS platforms. Does not currently include post-compromise ransomware deployment (tracked separately).

## Intelligence / Sourcing
- CrowdStrike Global Threat Report Q1 2026 
- Okta Threat Intelligence Blog – “MFA Fatigue Attacks Surge” (April 2026) 
- Microsoft Threat Intelligence – UNC3944 TTP update (March 2026) 
- Internal incident reports from two peer organizations (shared via ISAC)

## Notes for hunters
- Look for patterns of 8+ MFA pushes in <5 minutes followed by a helpdesk call within 10 minutes. 
- Always verify caller identity with a secondary channel (e.g. known phone number or manager confirmation). 
- Pay special attention to contractor/vendor accounts — they are the current sweet spot. 
- Document any new helpdesk scripts or verification steps created as a result of hunts.


---

## 🎭 Threat Actor Context

High-level attribution and motivation only — not hunt hypotheses.

| Topic | Notes |
| --- | --- |
| **Actor name / cluster** | Scattered Spider (UNC3944) |
| **Actor type** | cybercrime |
| **Confidence** | low / medium / high (qualitative) |
| **Known TTP themes** | TA0001, TA0006, TA0008, T1556.004, T1621, T1199, T1566.002 |

---

## 🎯 High-level Objectives

What this **umbrella** should achieve for the program (not per-hunt execution steps).

| Objective | Success signal (umbrella-level) |
| --- | --- |
| Ongoing Scattered Spider MFA fatigue and helpdesk social engineering tracked under this umbrella (identity and SaaS abuse). | _(define a measurable success signal)_ |
| Align hunt backlog and telemetry to campaign TTPs (MFA abuse, helpdesk bypass, initial access). | Backlog items tagged with this `campaign_slug` |
| Leadership-ready reporting on campaign-linked hunt progress and coverage. | Quarterly rollup references this campaign |

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

- CrowdStrike Global Threat Report Q1 2026
- Okta Threat Intelligence Blog – “MFA Fatigue Attacks Surge” (April 2026)
- Microsoft Threat Intelligence – UNC3944 TTP update (March 2026)
- Internal incident reports from two peer organizations (shared via ISAC)

