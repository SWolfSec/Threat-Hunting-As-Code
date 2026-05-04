---
title: "MFA push fatigue and helpdesk-assisted bypass (OKTA / Entra) under Scattered Spider umbrella"
hunt_id: "HUNT-YYYY-XXXX"
author: "jane.doe"
created_date: "2026-04-27"
updated_date: "2026-04-27"
hunt_type: "Hypothesis-driven"
status: "draft"
mitre_techniques:
  - "T1621"
  - "T1566.002"
  - "T1556.004"
  - "T1199"
mitre_tactics:
  - "TA0006"
  - "TA0001"
threat_actors:
  - name: "Scattered Spider (UNC3944)"
    type: "cybercrime"
campaigns:
  - "Scattered Spider MFA Fatigue & Helpdesk Social Engineering Campaign Q2 2026"
  - "scattered-spider-mfa-fatigue-2026"
campaign_slugs:
  - "scattered-spider-mfa-fatigue-2026"
data_sources:
  - "[ ] endpoint_process"
  - "[ ] endpoint_file"
  - "[ ] endpoint_registry"
  - "[ ] endpoint_network"
  - "edr_alerts"
  - "[ ] dns_logs"
  - "[ ] proxy_logs"
  - "[ ] firewall_logs"
  - "identity_auth"
  - "email_security"
  - "[ ] cloud_audit"
  - "saas_activity"
  - "_No response_"
data_source_locations:
  - "SIEM"
  - "EDR platform"
  - "[ ] Data lake / warehouse"
  - "[ ] NDR platform"
  - "[ ] SOAR case system"
  - "[ ] Cloud provider logs"
  - "SaaS security platform"
  - "[ ] Endpoint local logs (manual collection)"
  - "[ ] Server local logs (manual collection)"
  - "Identity provider console"
  - "_No response_"
query_languages:
  - "KQL"
  - "SPL"
  - "SQL"
  - "[ ] EQL"
  - "[ ] YARA-L"
  - "[ ] Sigma"
  - "[ ] Python"
  - "[ ] Bash"
  - "[ ] PowerShell"
  - "[ ] Velociraptor VQL"
  - "[ ] XQL"
  - "_No response_"
outcomes:
  - "expected: identify accounts with MFA push bursts followed by successful MFA or session without matching legitimate user intent"
  - "expected: flag helpdesk tickets that align in time with suspicious MFA sequences for manual review"
  - "observed: (fill in after first run)"
  - "action: tune threshold / playbook; open detection engineering ticket if pattern recurs"
---

# 🔎 Threat Hunt: MFA push fatigue and helpdesk-assisted bypass (OKTA / Entra) under Scattered Spider umbrella
> [!IMPORTANT] **Draft hunt (bootstrap)**
> 
> **Prefilled from intake** (issue form → YAML frontmatter above, plus any **Imported Intake Narrative** section below):
> - metadata fields used for dashboards and linking
> - Hunt Snapshot, ABLE table, Success Criteria (outcomes), and Execution Plan bullets where the form had answers
> 
> **You still need to complete** (this template body is mostly guidance until you replace it):
> - PEAK sections with real operational detail
> - at least one working `threat-hunt-query` block (replace the example placeholder if needed)
> - `threat-hunt-ioc` blocks when indicators exist
> - validation notes, findings, and outcomes as the hunt progresses
> 
> _Generated from GitHub issue #4. Remove this callout when the hunt is ready for formal review._


> [!TIP]
> Keep this artifact evidence-driven and reusable. If someone new joins the team, they should be able to run this hunt from this document alone.

## 📌 Hunt Snapshot

| Field | Value |
| --- | --- |
| Hunt ID | `HUNT-YYYY-XXXX` |
| Hunt Type | `Hypothesis-driven` |
| Status | `draft` |
| Author | `jane.doe` |
| Last Updated | `2026-04-27` |

## 🧭 PEAK Workflow

Use this structure for all hunts:

- **P - Prepare**: define scope, assumptions, prerequisites, and success criteria.
- **E - Execute**: run hunt logic, validate results, and capture evidence.
- **A - Act**: document findings, triage, and response/detection actions.
- **K - Knowledge**: preserve lessons, reusable logic, and improvement opportunities.

---

## 🟦 Prepare

<!-- HUNTER TODO: replace placeholder guidance with real hunt content -->


### 1) Hunt Objective

Describe what this hunt is trying to prove or disprove.

### 2) Scope

- **Environment(s)**:
- **Asset/User scope**:
- **Time range**:
- **Out of scope**:

### 3) Assumptions & Prerequisites

- **Telemetry assumptions**:
- **Access prerequisites**:
- **Known blind spots**:

### 4) Success Criteria

> From issue **outcomes** (tighten into criteria below).

- - expected: identify accounts with MFA push bursts followed by successful MFA or session without matching legitimate user intent
- - expected: flag helpdesk tickets that align in time with suspicious MFA sequences for manual review
- - observed: (fill in after first run)
- - action: tune threshold / playbook; open detection engineering ticket if pattern recurs

- What constitutes a meaningful signal?
- What evidence is needed to confirm/refute?
- What thresholds make this actionable?

### 5) Hunt-Type Guidance

#### Hypothesis-driven

- Start with a testable attacker behavior statement.
- Use ABLE framework below to make hypothesis explicit.

#### Baseline/EDA

- Define what "normal" looks like before looking for anomalies.
- State baseline period and anomaly criteria.

#### Model-Assisted/M-ATH

- Document model/tool inputs, confidence caveats, and analyst validation plan.
- Explain how model outputs are verified before operational decisions.

### 6) ABLE (Required for Hypothesis-driven Hunts)

> If this is not a Hypothesis-driven hunt, set fields to `N/A`.

| ABLE Element | What to Capture | Example |
| --- | --- | --- |
| **Actor** | Who performs behavior (group, insider, malware, unknown) | `Name: Scattered Spider (UNC3944) Type: cybercrime` |
| **Behavior** | Specific suspicious action to validate | `Contractor or employee accounts receive a burst of MFA push notifications (OKTA verify / Entra Authenticator) within minutes, followed by helpdesk contact (phone or chat) to "approve" access or reset MFA. Attacker goal is to successful MFA approval or credential / session abuse for SaaS and VPN.` |
| **Location** | Where behavior appears (hosts, identities, environment, logs) | `Okta  and Microsoft Entra ID sign-in and MFA logs; helpdesk ticketing (SOC/SOAR or ITSM); optional EDR on managed devices for session origin correlation.` |
| **Evidence** | Observable artifacts confirming/refuting hypothesis | `Correlated timeline: repeated prompt/push MFA events, eventual SUCCESS after many DENY or user fatigue; helpdesk ticket opened within a short window of the MFA burst; unusual source ASN / geo for session; optional overlap with known Scattered Spider TTPs from campaign intel.` |

**ABLE Notes**
- **Actor**:
- **Behavior**:
- **Location**:
- **Evidence**:

---

## 🟨 Execute

<!-- HUNTER TODO: replace placeholder guidance with real hunt content -->


### 1) Execution Plan

- **Data sources selected**: [ ] endpoint_process, [ ] endpoint_file, [ ] endpoint_registry, [ ] endpoint_network, edr_alerts, [ ] dns_logs, [ ] proxy_logs, [ ] firewall_logs, identity_auth, email_security, [ ] cloud_audit, saas_activity, _No response_
- **Data source locations**: SIEM, EDR platform, [ ] Data lake / warehouse, [ ] NDR platform, [ ] SOAR case system, [ ] Cloud provider logs, SaaS security platform, [ ] Endpoint local logs (manual collection), [ ] Server local logs (manual collection), Identity provider console, _No response_
- **Query languages/tools**: KQL, SPL, SQL, [ ] EQL, [ ] YARA-L, [ ] Sigma, [ ] Python, [ ] Bash, [ ] PowerShell, [ ] Velociraptor VQL, [ ] XQL, _No response_
- **MITRE tactics (intake)**: TA0006, TA0001
- **MITRE techniques (intake)**: T1621, T1566.002, T1556.004, T1199
- **Campaigns (intake)**: Scattered Spider MFA Fatigue & Helpdesk Social Engineering Campaign Q2 2026, scattered-spider-mfa-fatigue-2026
- **Threat actors (intake)**: Scattered Spider (UNC3944) (cybercrime)
- **Execution sequence**: _(ordering and cadence; expand in PEAK narrative or here)_

### 2) Queries (Parser-Extractable)

<!-- HUNTER TODO: replace example query blocks with real hunt queries -->


Use one or more blocks exactly like this so automation can extract them.

```threat-hunt-query
# name: suspicious_office_to_powershell
# purpose: Identify Office -> PowerShell encoded command chains
# datasource: endpoint_process
# language: KQL
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("WINWORD.EXE", "EXCEL.EXE", "OUTLOOK.EXE")
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

```threat-hunt-query
# name: placeholder_second_query
# purpose: Replace with your objective
# datasource: dns_logs
# language: SQL
-- Replace with real query
SELECT *
FROM dns_events
WHERE event_time >= NOW() - INTERVAL '7 days';
```

### 3) IOCs (Parser-Extractable)

<!-- HUNTER TODO: add IOC blocks when applicable (or note none observed) -->


Capture any indicators observed or investigated.

```threat-hunt-ioc
type: domain
value: suspicious-example-domain.tld
context: observed in DNS query after encoded command execution
confidence: medium
```

```threat-hunt-ioc
type: hash_sha256
value: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
context: payload dropped in user temp directory
confidence: high
```

### 4) Validation Notes

- **False-positive checks**:
- **Cross-source correlation performed**:
- **Analyst review notes**:

---

## 🟥 Act

<!-- HUNTER TODO: replace placeholder guidance with real hunt content -->


### 1) Findings Summary

- **Finding status**: confirmed suspicious / benign / inconclusive
- **Impact summary**:
- **Affected entities**:

### 2) Response Actions

| Action | Owner | Priority | Status |
| --- | --- | --- | --- |
| Create/update detection rule | Detection Engineering | High | Planned |
| Scope related activity | SOC | Medium | In Progress |
| Containment/hardening action | Incident Response | High | Pending |

### 3) Outcome Classification

- **True Positive(s)**:
- **Benign True Positive(s)**:
- **False Positive(s)**:
- **Detection Gap(s)**:

---

## 🟩 Knowledge

<!-- HUNTER TODO: replace placeholder guidance with real hunt content -->


### 1) Lessons Learned

- What worked well?
- What failed or caused noise?
- What assumptions changed?

### 2) Reusable Content

- **Reusable queries**:
- **Reusable IOC patterns**:
- **Reusable triage logic**:

### 3) Follow-on Hunt Ideas

- Next hypothesis to test
- Additional data sources that would improve confidence
- Related ATT&CK techniques/tactics to cover

---

## 🤖 Future Improvements / AI Suggestions (Optional)

Use this section for model-assisted ideas that still require analyst review.

- Candidate query optimizations:
- Additional enrichment opportunities:
- Suggested detection engineering backlog items:
- Potential automation opportunities:

---

## ✅ Completion Checklist

- [ ] Frontmatter is complete and valid.
- [ ] PEAK sections are fully documented.
- [ ] ABLE is completed (or set to `N/A` when not Hypothesis-driven).
- [ ] At least one `threat-hunt-query` block is included.
- [ ] IOC block(s) added when indicators are present.
- [ ] Outcomes and response actions are clearly documented.


---

## Imported Intake Narrative

> **Prefilled from issue form** (issue #4). Treat as raw intake; refine into PEAK sections above as the hunt matures.

```markdown
## Prepare 
Scope: enterprise Okta and Entra MFA + helpdesk channels for contractor heavy OUs. Hypothesis: Scattered Spider-style operators abuse MFA fatigue and social engineering to clear MFA or obtain resets. Assumptions: Idp admin audit logs and MFA challenge logs retained >= 30 days; helpdesk timestamps in ITSM. Success: repeatable query or dashboard slice that surfaces high-risk sequences with manageable false positives. 

## Execute
Pull MFA challenge outcomes and sign-ins for accoutns with >= N pushes in T minutes; join to helpdesk tickets by user and time window; enrich with geo/ASN and device trust where available. Validate against known benign patterns (travel, device change).

## Act
Triage true positives: reset session, revoke tokens, enforce step-up; document helpdesk procedures gaps. Escalate to IR if active compromise indicators.

## Knowledge
Document threshold N/T, data gaps (e.g. missing helpdesk API.), and handoff to campaign `scattered-spider-mfa-fatigue-2026` rollup
```