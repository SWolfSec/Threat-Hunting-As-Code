---
# =========================
# Required Metadata Fields
# =========================

# Human-readable hunt title
title: "Replace with hunt title"

# Unique hunt identifier (example: HUNT-2026-0001)
hunt_id: "HUNT-YYYY-XXXX"

# Primary hunt author/owner
author: "replace.with.handle"

# Dates in ISO format (YYYY-MM-DD)
created_date: "YYYY-MM-DD"
updated_date: "YYYY-MM-DD"

# Allowed values:
# - Hypothesis-driven
# - Baseline/EDA
# - Model-Assisted/M-ATH
hunt_type: "Hypothesis-driven"

# Allowed values (example set):
# draft | triaged | in_progress | validated | completed | archived | cancelled | on_hold
status: "draft"

# MITRE ATT&CK technique IDs
mitre_techniques:
  - "T0000"

# MITRE ATT&CK tactic IDs (TAxxxx)
mitre_tactics:
  - "TA0000"

# Threat actors as list of maps (name + type)
threat_actors:
  - name: "Unknown"
    type: "unknown"

# Campaign names related to this hunt (or "none")
campaigns:
  - "none"

# Optional: link to umbrella campaign(s) by canonical slug (must match campaigns/*.md frontmatter).
# Preferred for metrics rollups. Omit entirely for standalone hunts.
# campaign_slugs:
#   - "your-campaign-slug"

# Controlled data source categories used in this hunt
data_sources:
  - "edr_alerts"

# Where data is hosted/queried/collected
data_source_locations:
  - "EDR platform"

# Query languages/tools used
query_languages:
  - "KQL"

# Hunt outcome entries (list form helps parser + metrics)
outcomes:
  - "expected: Replace with expected outcome"
  - "observed: Replace with observed outcome"
  - "action: Replace with follow-up action"
---

# 🔎 Threat Hunt: Replace with Hunt Title

> [!TIP]
> Keep this artifact evidence-driven and reusable. If someone new joins the team, they should be able to run this hunt from this document alone.

## 📌 Hunt Snapshot

| Field | Value |
| --- | --- |
| Hunt ID | `HUNT-YYYY-XXXX` |
| Hunt Type | `Hypothesis-driven / Baseline/EDA / Model-Assisted/M-ATH` |
| Status | `draft` |
| Author | `replace.with.handle` |
| Last Updated | `YYYY-MM-DD` |

## 🧭 PEAK Workflow

Use this structure for all hunts:

- **P - Prepare**: define scope, assumptions, prerequisites, and success criteria.
- **E - Execute**: run hunt logic, validate results, and capture evidence.
- **A - Act**: document findings, triage, and response/detection actions.
- **K - Knowledge**: preserve lessons, reusable logic, and improvement opportunities.

---

## 🟦 Prepare

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
| **Actor** | Who performs behavior (group, insider, malware, unknown) | `APT29 (nation_state)` |
| **Behavior** | Specific suspicious action to validate | `Encoded PowerShell from Office parent process` |
| **Location** | Where behavior appears (hosts, identities, environment, logs) | `Finance endpoints, EDR process telemetry` |
| **Evidence** | Observable artifacts confirming/refuting hypothesis | `Process tree + command line + child network activity` |

**ABLE Notes**
- **Actor**:
- **Behavior**:
- **Location**:
- **Evidence**:

---

## 🟨 Execute

### 1) Execution Plan

- **Data sources selected**:
- **Data source locations**:
- **Query languages/tools**:
- **Execution sequence**:

### 2) Queries (Parser-Extractable)

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
