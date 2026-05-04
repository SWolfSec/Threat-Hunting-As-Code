---
title: "Suspicious SaaS session replay after Lumma-style infostealer activity"
hunt_id: "HUNT-2026-LUMMA-0001"
author: "SwolfSec"
created_date: "2026-08-04"
updated_date: "2026-08-04"
hunt_type: "Hypothesis-driven"
status: "draft"
mitre_techniques:
  - "T1555"
  - "T1539"
  - "T1078"
  - "T1528"
  - "T1059.001"
mitre_tactics:
  - "TA0006"
  - "TA0001"
  - "TA0005"
  - "TA0011"
threat_actors:
  - name: "Lumma-affiliated crimeware operators"
    type: "cybercrime"
campaigns:
  - "Lumma Stealer SaaS Session Hijacking Campaign Q3 2026"
  - "lumma-stealer-saas-session-hijack-2026-q3"
campaign_slugs:
  - "lumma-stealer-saas-session-hijack-2026-q3"
data_sources:
  - "endpoint_process"
  - "endpoint_file"
  - "[ ] endpoint_registry"
  - "[ ] endpoint_network"
  - "edr_alerts"
  - "[ ] dns_logs"
  - "proxy_logs"
  - "[ ] firewall_logs"
  - "identity_auth"
  - "[ ] email_security"
  - "cloud_audit"
  - "saas_activity"
  - "_No response_"
data_source_locations:
  - "SIEM"
  - "EDR platform"
  - "Data lake / warehouse"
  - "[ ] NDR platform"
  - "[ ] SOAR case system"
  - "Cloud provider logs"
  - "SaaS security platform"
  - "[ ] Endpoint local logs (manual collection)"
  - "[ ] Server local logs (manual collection)"
  - "Identity provider console"
  - "_No response_"
query_languages:
  - "KQL"
  - "SPL"
  - "[ ] SQL"
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
  - "expected: detect endpoint-to-identity/session takeover chains indicative of stolen session replay"
  - "expected: identify accounts requiring token revocation and conditional access hardening"
  - "observed: TBD after first execution cycle"
  - "action: create/tune detections for suspicious token reuse and impossible session transitions"
---

# 🔎 Threat Hunt: Suspicious SaaS session replay after Lumma-style infostealer activity
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
> _Generated from GitHub issue #10. Remove this callout when the hunt is ready for formal review._


> [!TIP]
> Keep this artifact evidence-driven and reusable. If someone new joins the team, they should be able to run this hunt from this document alone.

## 📌 Hunt Snapshot

| Field | Value |
| --- | --- |
| Hunt ID | `HUNT-2026-LUMMA-0001` |
| Hunt Type | `Hypothesis-driven` |
| Status | `draft` |
| Author | `SwolfSec` |
| Last Updated | `2026-08-04` |

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

- - expected: detect endpoint-to-identity/session takeover chains indicative of stolen session replay
- - expected: identify accounts requiring token revocation and conditional access hardening
- - observed: TBD after first execution cycle
- - action: create/tune detections for suspicious token reuse and impossible session transitions

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
| **Actor** | Who performs behavior (group, insider, malware, unknown) | `- Name: Lumma-affiliated crimeware operators - Type: cybercrime` |
| **Behavior** | Specific suspicious action to validate | `Adversaries steal browser session artifacts from an infostealer-infected endpoint, then replay tokens/sessions into SaaS and identity platforms to bypass normal credential-entry patterns.` |
| **Location** | Where behavior appears (hosts, identities, environment, logs) | `Managed Windows endpoints (process/file telemetry), identity provider sign-in + session logs, and SaaS audit logs for Microsoft 365 / Google Workspace / core business apps.` |
| **Evidence** | Observable artifacts confirming/refuting hypothesis | `Endpoint infostealer indicators (suspicious archive/exfil/process chain) followed by high-risk SaaS or IdP session events for the same user within a short window, including unusual ASN/geo/device context and no normal interactive login sequence.` |

**ABLE Notes**
- **Actor**:
- **Behavior**:
- **Location**:
- **Evidence**:

---

## 🟨 Execute

<!-- HUNTER TODO: replace placeholder guidance with real hunt content -->


### 1) Execution Plan

- **Data sources selected**: endpoint_process, endpoint_file, [ ] endpoint_registry, [ ] endpoint_network, edr_alerts, [ ] dns_logs, proxy_logs, [ ] firewall_logs, identity_auth, [ ] email_security, cloud_audit, saas_activity, _No response_
- **Data source locations**: SIEM, EDR platform, Data lake / warehouse, [ ] NDR platform, [ ] SOAR case system, Cloud provider logs, SaaS security platform, [ ] Endpoint local logs (manual collection), [ ] Server local logs (manual collection), Identity provider console, _No response_
- **Query languages/tools**: KQL, SPL, [ ] SQL, [ ] EQL, [ ] YARA-L, [ ] Sigma, [ ] Python, [ ] Bash, [ ] PowerShell, [ ] Velociraptor VQL, [ ] XQL, _No response_
- **MITRE tactics (intake)**: TA0006, TA0001, TA0005, TA0011
- **MITRE techniques (intake)**: T1555, T1539, T1078, T1528, T1059.001
- **Campaigns (intake)**: Lumma Stealer SaaS Session Hijacking Campaign Q3 2026, lumma-stealer-saas-session-hijack-2026-q3
- **Threat actors (intake)**: Lumma-affiliated crimeware operators (cybercrime)
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

> **Prefilled from issue form** (issue #10). Treat as raw intake; refine into PEAK sections above as the hunt matures.

```markdown
## Prepare
Hypothesis: Lumma-style infostealer infections lead to stolen browser/session artifacts that are replayed into SaaS and IdP environments.  
Scope: corporate managed endpoints plus M365/Google Workspace identity and session telemetry.  
Assumptions: endpoint process/file telemetry and IdP/SaaS audit logs are retained for at least 30 days.  
Success criteria: produce correlated leads where endpoint malware evidence and suspicious session behavior align per user/entity.

## Execute
1. Identify candidate infostealer activity on endpoints (known process/file patterns, suspicious script execution, archive staging, possible exfil clues).
2. Pivot by user/account into IdP and SaaS logs for session anomalies within ±24h.
3. Flag suspicious signals: unusual ASN/geo, new device fingerprint, token/session reuse patterns, and sign-ins lacking expected interactive flow.
4. Suppress known benign patterns (travel exceptions, VPN egress changes, approved admin tooling).

## Act
- Triage high-confidence chains with SOC/IR.
- Revoke sessions/tokens for impacted accounts.
- Enforce or tighten conditional access controls where gaps are found.
- Open detection engineering tasks for repeatable patterns.

## Knowledge
- Capture reusable correlation logic and thresholds.
- Document top false-positive causes and suppression rules.
- Propose follow-on hunts for adjacent techniques (credential theft, OAuth abuse, lateral SaaS movement).
```