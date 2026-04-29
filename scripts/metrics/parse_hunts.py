#!/usr/bin/env python3
"""
Parse hunt and campaign markdown, validate, write metrics JSON, update campaign stubs.

CI calls this to scan hunts/ and campaigns/, write hunt_metrics_summary.json,
optionally rewrite the auto tables in campaign markdown (between HTML comment
markers), then run generate_dashboard.py.

Outcome keywords are regex heuristics for dashboards, not a formal taxonomy.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import yaml

# --- Shared constants ---

# MITRE ATT&CK Enterprise tactic IDs (used for % tactic coverage).
KNOWN_MITRE_TACTICS = {
    "TA0043",  # Reconnaissance
    "TA0042",  # Resource Development
    "TA0001",  # Initial Access
    "TA0002",  # Execution
    "TA0003",  # Persistence
    "TA0004",  # Privilege Escalation
    "TA0005",  # Defense Evasion
    "TA0006",  # Credential Access
    "TA0007",  # Discovery
    "TA0008",  # Lateral Movement
    "TA0009",  # Collection
    "TA0011",  # Command and Control
    "TA0010",  # Exfiltration
    "TA0040",  # Impact
}

FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?", re.DOTALL)
QUERY_BLOCK_RE = re.compile(
    r"```threat-hunt-query\s*\n(.*?)\n```", re.DOTALL | re.IGNORECASE
)
IOC_BLOCK_RE = re.compile(r"```threat-hunt-ioc\s*\n(.*?)\n```", re.DOTALL | re.IGNORECASE)

KEBAB_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

AUTO_LINKED_START = "<!-- auto:linked-hunts:start -->"
AUTO_LINKED_END = "<!-- auto:linked-hunts:end -->"
AUTO_OUTCOMES_START = "<!-- auto:aggregated-outcomes:start -->"
AUTO_OUTCOMES_END = "<!-- auto:aggregated-outcomes:end -->"

# Outcome keyword patterns (shared hunt-level metrics + campaign child rollups).
DETECTION_RE = re.compile(r"\bdetect(ion|ed|s)?\b", re.IGNORECASE)
PREVENTION_RE = re.compile(r"\bprevent(ion|ed|s)?\b", re.IGNORECASE)
VISIBILITY_RE = re.compile(
    r"\bvisibility\b|\btelemetry (added|created|improved)\b", re.IGNORECASE
)

# --- Hunt ---

REQUIRED_HUNT_FIELDS = [
    "title",
    "hunt_id",
    "author",
    "created_date",
    "updated_date",
    "hunt_type",
    "status",
    "mitre_techniques",
    "mitre_tactics",
    "threat_actors",
    "campaigns",
    "data_sources",
    "data_source_locations",
    "query_languages",
    "outcomes",
]

ALLOWED_HUNT_TYPES = {"Hypothesis-driven", "Baseline/EDA", "Model-Assisted/M-ATH"}


@dataclass
class HuntRecord:
    path: str
    frontmatter: dict[str, Any] = field(default_factory=dict)
    queries: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    linked_campaign_slugs: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return not self.errors


# --- Campaign ---

REQUIRED_CAMPAIGN_FIELDS = [
    "title",
    "campaign_slug",
    "threat_actor_type",
    "threat_actor_name",
    "start_date",
    "description",
    "mitre_tactics",
    "mitre_techniques",
    "status",
]


@dataclass
class CampaignRecord:
    path: str
    frontmatter: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return not self.errors

    @property
    def slug(self) -> str:
        return str(self.frontmatter.get("campaign_slug", "")).strip()


# --- IO helpers ---

def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def find_markdown_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(
        [p for p in root.rglob("*.md") if p.is_file()],
        key=lambda p: str(p),
    )


def parse_frontmatter(content: str, path: Path) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    match = FRONTMATTER_RE.search(content)
    if not match:
        errors.append(
            f"{path}: missing YAML frontmatter. Expected content to start with '---' block."
        )
        return {}, errors

    raw_frontmatter = match.group(1)
    try:
        data = yaml.safe_load(raw_frontmatter) or {}
    except yaml.YAMLError as exc:
        errors.append(f"{path}: invalid YAML frontmatter: {exc}")
        return {}, errors

    if not isinstance(data, dict):
        errors.append(f"{path}: YAML frontmatter must parse to a mapping/object.")
        return {}, errors

    return data, errors


def extract_blocks(content: str) -> tuple[list[str], list[str]]:
    queries = [m.strip() for m in QUERY_BLOCK_RE.findall(content) if m.strip()]
    iocs = [m.strip() for m in IOC_BLOCK_RE.findall(content) if m.strip()]
    return queries, iocs


def normalize_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _github_empty_field_marker(value: Any) -> bool:
    # Issue forms write this when an optional answer is left blank.
    return isinstance(value, str) and value.strip().lower() in {"_no response_", "_n/a_"}


def parse_iso_date(value: Any, field_name: str, path: str, errors: list[str]) -> date | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{path}: `{field_name}` must be a non-empty ISO date string (YYYY-MM-DD).")
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        errors.append(f"{path}: `{field_name}`='{value}' is not valid ISO format YYYY-MM-DD.")
        return None


def quarter_key(d: date) -> str:
    quarter = ((d.month - 1) // 3) + 1
    return f"{d.year}-Q{quarter}"


def hunt_date_for_activity(fm: dict[str, Any]) -> date | None:
    """Date for rollups: updated_date if valid, else created_date."""
    for key in ("updated_date", "created_date"):
        v = fm.get(key)
        if isinstance(v, str) and v.strip():
            try:
                return date.fromisoformat(v.strip())
            except ValueError:
                continue
    return None


def count_outcome_matches(outcomes: list[str]) -> tuple[int, int, int]:
    d = p = v = 0
    for line in outcomes:
        if DETECTION_RE.search(line):
            d += 1
        if PREVENTION_RE.search(line):
            p += 1
        if VISIBILITY_RE.search(line):
            v += 1
    return d, p, v


def hunt_has_outcome_flag(outcomes: list[str], pattern: re.Pattern[str]) -> bool:
    return any(pattern.search(line) for line in outcomes)


# --- Hunt validation ---

def validate_hunt(record: HuntRecord) -> None:
    fm = record.frontmatter
    path = record.path

    for field_name in REQUIRED_HUNT_FIELDS:
        if field_name not in fm:
            record.errors.append(f"{path}: missing required field `{field_name}` in frontmatter.")

    hunt_type = fm.get("hunt_type")
    if hunt_type is not None and hunt_type not in ALLOWED_HUNT_TYPES:
        record.errors.append(
            f"{path}: `hunt_type` must be one of {sorted(ALLOWED_HUNT_TYPES)}, got '{hunt_type}'."
        )

    parse_iso_date(fm.get("created_date"), "created_date", path, record.errors)
    parse_iso_date(fm.get("updated_date"), "updated_date", path, record.errors)

    for list_field in (
        "mitre_techniques",
        "mitre_tactics",
        "campaigns",
        "data_sources",
        "data_source_locations",
        "query_languages",
        "outcomes",
    ):
        if list_field in fm and not isinstance(fm.get(list_field), list):
            record.errors.append(f"{path}: `{list_field}` must be a YAML list.")

    if "campaign_slugs" in fm and fm.get("campaign_slugs") is not None:
        if not isinstance(fm.get("campaign_slugs"), list):
            record.errors.append(f"{path}: `campaign_slugs` must be a YAML list when present.")

    if "threat_actors" in fm:
        actors = fm.get("threat_actors")
        if not isinstance(actors, list):
            record.errors.append(f"{path}: `threat_actors` must be a YAML list.")
        else:
            for idx, actor in enumerate(actors):
                if not isinstance(actor, dict):
                    record.errors.append(
                        f"{path}: `threat_actors[{idx}]` must be a map/object with `name` and `type`."
                    )
                    continue
                if not actor.get("name"):
                    record.errors.append(f"{path}: `threat_actors[{idx}].name` is required.")
                if not actor.get("type"):
                    record.errors.append(f"{path}: `threat_actors[{idx}].type` is required.")

    if not record.queries:
        record.errors.append(
            f"{path}: missing `threat-hunt-query` block. Include at least one query block."
        )


def collect_hunt_campaign_slug_refs(
    record: HuntRecord, known_slugs: set[str]
) -> None:
    """Link hunts to campaigns and record errors for bad slugs.

    Uses campaign_slugs in frontmatter, plus kebab-case entries in the legacy
    campaigns list. Legacy entries only count if they match a real campaign_slug.
    """
    fm = record.frontmatter
    path = record.path
    linked: set[str] = set()

    for s in normalize_list(fm.get("campaign_slugs", [])):
        slug = str(s).strip()
        if not slug:
            continue
        if slug not in known_slugs:
            record.errors.append(
                f"{path}: `campaign_slugs` references unknown `campaign_slug` `{slug}`. "
                f"Define it under campaigns/ or remove the reference."
            )
        else:
            linked.add(slug)

    for c in normalize_list(fm.get("campaigns", [])):
        entry = str(c).strip()
        if not entry or entry.lower() == "none":
            continue
        if KEBAB_SLUG_RE.match(entry):
            if entry not in known_slugs:
                record.errors.append(
                    f"{path}: `campaigns` entry `{entry}` looks like a `campaign_slug` "
                    f"(kebab-case) but no campaign file defines it."
                )
            else:
                linked.add(entry)

    record.linked_campaign_slugs = sorted(linked)


# --- Campaign validation ---

def validate_campaign(record: CampaignRecord) -> None:
    fm = record.frontmatter
    path = record.path

    for field_name in REQUIRED_CAMPAIGN_FIELDS:
        if field_name not in fm:
            record.errors.append(f"{path}: missing required field `{field_name}` in frontmatter.")

    slug = str(fm.get("campaign_slug", "")).strip() if "campaign_slug" in fm else ""
    if slug and not KEBAB_SLUG_RE.match(slug):
        record.errors.append(
            f"{path}: `campaign_slug` must be kebab-case (lowercase letters, digits, hyphens): `{slug}`."
        )

    parse_iso_date(fm.get("start_date"), "start_date", path, record.errors)
    if (
        "end_date" in fm
        and fm.get("end_date") not in (None, "")
        and not _github_empty_field_marker(fm.get("end_date"))
    ):
        parse_iso_date(fm.get("end_date"), "end_date", path, record.errors)

    for list_field in ("mitre_tactics", "mitre_techniques"):
        if list_field in fm and not isinstance(fm.get(list_field), list):
            record.errors.append(f"{path}: `{list_field}` must be a YAML list.")


def parse_hunt_file(path: Path) -> HuntRecord:
    content = read_text(path)
    frontmatter, fm_errors = parse_frontmatter(content, path)
    queries, iocs = extract_blocks(content)

    record = HuntRecord(
        path=str(path),
        frontmatter=frontmatter,
        queries=queries,
        iocs=iocs,
        errors=fm_errors.copy(),
    )
    validate_hunt(record)
    return record


def parse_campaign_file(path: Path) -> CampaignRecord:
    content = read_text(path)
    frontmatter, fm_errors = parse_frontmatter(content, path)
    record = CampaignRecord(path=str(path), frontmatter=frontmatter, errors=fm_errors.copy())
    validate_campaign(record)
    return record


# --- Campaign markdown auto-update ---

def replace_autogen_region(content: str, start_marker: str, end_marker: str, inner: str) -> str:
    # If markers are missing, leave the file unchanged.
    if start_marker not in content or end_marker not in content:
        return content
    before, rest = content.split(start_marker, 1)
    _, after = rest.split(end_marker, 1)
    inner_block = "\n" + inner.rstrip() + "\n"
    return before + start_marker + inner_block + end_marker + after


def build_linked_hunts_markdown(repo_root: Path, campaign_path: Path, hunts: list[HuntRecord]) -> str:
    lines = [
        "| Hunt ID | Title | Status | Link |",
        "| --- | --- | --- | --- |",
    ]
    if not hunts:
        lines.append("| — | _No linked hunts yet_ | — | — |")
        return "\n".join(lines)

    camp = Path(campaign_path)
    for h in sorted(hunts, key=lambda x: str(x.frontmatter.get("hunt_id", ""))):
        fm = h.frontmatter
        hid = str(fm.get("hunt_id", "n/a"))
        title = str(fm.get("title", "n/a")).replace("|", "\\|")
        status = str(fm.get("status", "n/a"))
        hunt_abs = Path(h.path)
        rel = Path(os.path.relpath(hunt_abs, camp.parent)).as_posix()
        link = f"[{hid}]({rel})"
        lines.append(f"| `{hid}` | {title} | {status} | {link} |")
    return "\n".join(lines)


def build_aggregated_outcomes_markdown(stats: dict[str, Any]) -> str:
    return "\n".join(
        [
            "| Metric | Value |",
            "| --- | ---: |",
            f"| Child hunts linked | {stats.get('linked_hunt_count', 0)} |",
            f"| Detection opportunities (outcome lines) | {stats.get('detection_opportunity_count', 0)} |",
            f"| Prevention opportunities (outcome lines) | {stats.get('prevention_opportunity_count', 0)} |",
            f"| Visibility opportunities (outcome lines) | {stats.get('visibility_opportunity_count', 0)} |",
            f"| Hunts with ≥1 detection signal | {stats.get('hunts_with_detection', 0)} |",
            f"| Hunts with ≥1 prevention signal | {stats.get('hunts_with_prevention', 0)} |",
            f"| Hunts with ≥1 visibility signal | {stats.get('hunts_with_visibility', 0)} |",
            f"| Last child activity (max updated/created) | {stats.get('last_activity_date', '—')} |",
        ]
    )


def update_campaign_file(repo_root: Path, campaign: CampaignRecord, linked_hunts: list[HuntRecord], stats: dict[str, Any]) -> bool:
    path = Path(campaign.path)
    content = read_text(path)
    new_content = content
    new_content = replace_autogen_region(
        new_content,
        AUTO_LINKED_START,
        AUTO_LINKED_END,
        build_linked_hunts_markdown(repo_root, path, linked_hunts),
    )
    new_content = replace_autogen_region(
        new_content,
        AUTO_OUTCOMES_START,
        AUTO_OUTCOMES_END,
        build_aggregated_outcomes_markdown(stats),
    )
    if new_content != content:
        write_text(path, new_content)
        return True
    return False


# --- Hunt metrics for the dashboard JSON ---

def compute_metrics(valid_records: list[HuntRecord]) -> dict[str, Any]:
    """Aggregate hunt-level counters and totals."""
    total_hunts = len(valid_records)

    hunts_by_quarter: Counter[str] = Counter()
    hunt_type_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    mitre_tactic_counts: Counter[str] = Counter()
    mitre_technique_counts: Counter[str] = Counter()
    threat_actor_type_counts: Counter[str] = Counter()
    threat_actor_name_counts: Counter[str] = Counter()
    campaign_counts: Counter[str] = Counter()
    data_source_counts: Counter[str] = Counter()
    data_source_location_counts: Counter[str] = Counter()
    query_language_counts: Counter[str] = Counter()
    outcome_category_counts: Counter[str] = Counter()

    hunts_with_mitre = 0
    hunts_with_threat_actors = 0
    hunts_with_campaigns = 0
    hunts_with_detections = 0
    hunts_with_preventions = 0
    hunts_with_visibility_created = 0

    total_query_blocks = 0
    total_ioc_blocks = 0

    for record in valid_records:
        fm = record.frontmatter
        created_date = date.fromisoformat(str(fm["created_date"]))
        hunts_by_quarter[quarter_key(created_date)] += 1
        hunt_type_counts[str(fm.get("hunt_type", "unknown"))] += 1
        status_counts[str(fm.get("status", "unknown"))] += 1

        techniques = [str(v).strip() for v in normalize_list(fm.get("mitre_techniques")) if str(v).strip()]
        tactics = [str(v).strip().upper() for v in normalize_list(fm.get("mitre_tactics")) if str(v).strip()]
        actors = normalize_list(fm.get("threat_actors"))
        campaigns = [str(v).strip() for v in normalize_list(fm.get("campaigns")) if str(v).strip()]
        data_sources = [str(v).strip() for v in normalize_list(fm.get("data_sources")) if str(v).strip()]
        locations = [str(v).strip() for v in normalize_list(fm.get("data_source_locations")) if str(v).strip()]
        query_languages = [str(v).strip() for v in normalize_list(fm.get("query_languages")) if str(v).strip()]
        outcomes = [str(v).strip() for v in normalize_list(fm.get("outcomes")) if str(v).strip()]

        if techniques or tactics:
            hunts_with_mitre += 1
        if actors:
            hunts_with_threat_actors += 1
        if campaigns and not (len(campaigns) == 1 and campaigns[0].lower() == "none"):
            hunts_with_campaigns += 1

        mitre_technique_counts.update(techniques)
        mitre_tactic_counts.update(tactics)
        campaign_counts.update(campaigns)
        data_source_counts.update(data_sources)
        data_source_location_counts.update(locations)
        query_language_counts.update(query_languages)

        for actor in actors:
            if not isinstance(actor, dict):
                continue
            actor_name = str(actor.get("name", "")).strip()
            actor_type = str(actor.get("type", "")).strip()
            if actor_name:
                threat_actor_name_counts[actor_name] += 1
            if actor_type:
                threat_actor_type_counts[actor_type] += 1

        hunt_has_detection = False
        hunt_has_prevention = False
        hunt_has_visibility = False
        for out in outcomes:
            # One hunt can increment line counts several times, hunt flags are once per hunt.
            if DETECTION_RE.search(out):
                outcome_category_counts["detections"] += 1
                hunt_has_detection = True
            if PREVENTION_RE.search(out):
                outcome_category_counts["preventions"] += 1
                hunt_has_prevention = True
            if VISIBILITY_RE.search(out):
                outcome_category_counts["visibility_created"] += 1
                hunt_has_visibility = True

        hunts_with_detections += int(hunt_has_detection)
        hunts_with_preventions += int(hunt_has_prevention)
        hunts_with_visibility_created += int(hunt_has_visibility)

        total_query_blocks += len(record.queries)
        total_ioc_blocks += len(record.iocs)

    unique_tactics = set(mitre_tactic_counts.keys())
    mitre_tactic_coverage_percent = (
        round((len(unique_tactics & KNOWN_MITRE_TACTICS) / len(KNOWN_MITRE_TACTICS)) * 100, 2)
        if KNOWN_MITRE_TACTICS
        else 0.0
    )

    mitre_hunt_mapping_percent = round((hunts_with_mitre / total_hunts) * 100, 2) if total_hunts else 0.0
    threat_actor_coverage_percent = (
        round((hunts_with_threat_actors / total_hunts) * 100, 2) if total_hunts else 0.0
    )
    campaign_coverage_percent = round((hunts_with_campaigns / total_hunts) * 100, 2) if total_hunts else 0.0

    return {
        "totals": {
            "hunts_total": total_hunts,
            "query_blocks_total": total_query_blocks,
            "ioc_blocks_total": total_ioc_blocks,
        },
        "hunts_by_quarter": dict(sorted(hunts_by_quarter.items())),
        "distribution": {
            "hunt_type_counts": dict(hunt_type_counts),
            "status_counts": dict(status_counts),
            "data_source_counts": dict(data_source_counts),
            "data_source_location_counts": dict(data_source_location_counts),
            "query_language_counts": dict(query_language_counts),
        },
        "mitre": {
            "technique_counts": dict(mitre_technique_counts),
            "tactic_counts": dict(mitre_tactic_counts),
            "coverage_percent_of_known_tactics": mitre_tactic_coverage_percent,
            "coverage_percent_hunts_with_mitre_mapping": mitre_hunt_mapping_percent,
        },
        "threat_actors": {
            "name_counts": dict(threat_actor_name_counts),
            "type_counts": dict(threat_actor_type_counts),
            "coverage_percent_hunts_with_threat_actors": threat_actor_coverage_percent,
        },
        "campaigns": {
            "campaign_counts": dict(campaign_counts),
            "coverage_percent_hunts_with_campaigns": campaign_coverage_percent,
        },
        "outcomes": {
            "category_counts": {
                "detections": outcome_category_counts.get("detections", 0),
                "preventions": outcome_category_counts.get("preventions", 0),
                "visibility_created": outcome_category_counts.get("visibility_created", 0),
            },
            "hunt_level_counts": {
                "hunts_with_detections": hunts_with_detections,
                "hunts_with_preventions": hunts_with_preventions,
                "hunts_with_visibility_created": hunts_with_visibility_created,
            },
        },
    }


def aggregate_campaign_stats(linked: list[HuntRecord]) -> dict[str, Any]:
    """Aggregate metrics from hunts linked to one campaign."""
    all_tactics: set[str] = set()
    all_techniques: set[str] = set()
    last_dates: list[date] = []

    det_lines = prev_lines = vis_lines = 0
    hunts_with_detection = hunts_with_prevention = hunts_with_visibility = 0

    for h in linked:
        fm = h.frontmatter
        for t in normalize_list(fm.get("mitre_tactics")):
            s = str(t).strip().upper()
            if s:
                all_tactics.add(s)
        for t in normalize_list(fm.get("mitre_techniques")):
            s = str(t).strip()
            if s:
                all_techniques.add(s)

        outcomes = [str(v).strip() for v in normalize_list(fm.get("outcomes")) if str(v).strip()]
        d, p, v = count_outcome_matches(outcomes)
        det_lines += d
        prev_lines += p
        vis_lines += v
        if hunt_has_outcome_flag(outcomes, DETECTION_RE):
            hunts_with_detection += 1
        if hunt_has_outcome_flag(outcomes, PREVENTION_RE):
            hunts_with_prevention += 1
        if hunt_has_outcome_flag(outcomes, VISIBILITY_RE):
            hunts_with_visibility += 1

        ad = hunt_date_for_activity(fm)
        if ad:
            last_dates.append(ad)

    cov = (
        round((len(all_tactics & KNOWN_MITRE_TACTICS) / len(KNOWN_MITRE_TACTICS)) * 100, 2)
        if KNOWN_MITRE_TACTICS
        else 0.0
    )
    last_activity = max(last_dates).isoformat() if last_dates else None

    return {
        "linked_hunt_count": len(linked),
        "mitre_from_children": {
            "unique_tactics": sorted(all_tactics),
            "unique_techniques": sorted(all_techniques),
            "coverage_percent_of_known_tactics": cov,
        },
        "aggregated_outcomes": {
            "detection_opportunity_count": det_lines,
            "prevention_opportunity_count": prev_lines,
            "visibility_opportunity_count": vis_lines,
            "hunts_with_detection": hunts_with_detection,
            "hunts_with_prevention": hunts_with_prevention,
            "hunts_with_visibility": hunts_with_visibility,
        },
        "last_activity_date": last_activity,
    }


def build_campaign_summary_json(
    repo_root: Path,
    campaigns: list[CampaignRecord],
    slug_to_hunts: dict[str, list[HuntRecord]],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for c in sorted(campaigns, key=lambda x: x.slug):
        if not c.is_valid:
            continue
        fm = c.frontmatter
        slug = c.slug
        linked = slug_to_hunts.get(slug, [])
        stats = aggregate_campaign_stats(linked)
        ao = stats["aggregated_outcomes"]
        rel_path = Path(c.path).relative_to(repo_root).as_posix()
        out.append(
            {
                "campaign_slug": slug,
                "title": fm.get("title"),
                "status": fm.get("status"),
                "path": rel_path,
                "threat_actor_name": fm.get("threat_actor_name"),
                "threat_actor_type": fm.get("threat_actor_type"),
                "linked_hunt_count": stats["linked_hunt_count"],
                "linked_hunt_ids": [str(h.frontmatter.get("hunt_id")) for h in linked],
                "mitre_from_children": stats["mitre_from_children"],
                "aggregated_outcomes": ao,
                "last_activity_date": stats["last_activity_date"],
            }
        )
    return out


def hunt_summary_row(repo_root: Path, h: HuntRecord) -> dict[str, Any]:
    fm = h.frontmatter
    p = Path(h.path).relative_to(repo_root).as_posix()
    return {
        "hunt_id": fm.get("hunt_id"),
        "title": fm.get("title"),
        "hunt_type": fm.get("hunt_type"),
        "status": fm.get("status"),
        "created_date": fm.get("created_date"),
        "updated_date": fm.get("updated_date"),
        "path": p,
        "linked_campaign_slugs": list(h.linked_campaign_slugs),
    }


def build_report(
    hunt_records: list[HuntRecord],
    campaign_records: list[CampaignRecord],
    campaigns_summary: list[dict[str, Any]],
    hunt_summaries: list[dict[str, Any]],
) -> dict[str, Any]:
    valid_hunts = [r for r in hunt_records if r.is_valid]
    invalid_hunts = [r for r in hunt_records if not r.is_valid]
    valid_campaigns = [r for r in campaign_records if r.is_valid]
    invalid_campaigns = [r for r in campaign_records if not r.is_valid]

    all_errors = []
    for rec in sorted(invalid_hunts, key=lambda r: r.path):
        all_errors.append({"path": rec.path, "errors": rec.errors})
    for rec in sorted(invalid_campaigns, key=lambda r: r.path):
        all_errors.append({"path": rec.path, "errors": rec.errors})

    metrics = compute_metrics(valid_hunts)

    return {
        "meta": {
            "generated_by": "scripts/metrics/parse_hunts.py",
            "hunts_scanned": len(hunt_records),
            "hunts_valid": len(valid_hunts),
            "hunts_invalid": len(invalid_hunts),
            "campaigns_scanned": len(campaign_records),
            "campaigns_valid": len(valid_campaigns),
            "campaigns_invalid": len(invalid_campaigns),
        },
        "hunts": hunt_summaries,
        "campaigns_summary": campaigns_summary,
        "validation": {"errors": all_errors},
        "metrics": metrics,
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_dashboard_generator(script_path: Path, summary_json_path: Path, strict: bool) -> None:
    # Dashboard is a separate script, it reads the same JSON.
    if not script_path.exists():
        message = f"Dashboard generator not found: {script_path}"
        if strict:
            raise FileNotFoundError(message)
        print(f"[WARN] {message}", file=sys.stderr)
        return

    cmd = [sys.executable, str(script_path), "--input", str(summary_json_path)]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        details = stderr or stdout or "No error output captured."
        message = f"generate_dashboard.py failed (exit={result.returncode}): {details}"
        if strict:
            raise RuntimeError(message)
        print(f"[WARN] {message}", file=sys.stderr)
        return

    if result.stdout.strip():
        print(result.stdout.strip())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Parse hunts and campaigns, validate, write metrics JSON, refresh campaign auto sections."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="Repository root path (default: inferred from script location).",
    )
    parser.add_argument(
        "--hunts-dir",
        type=Path,
        default=None,
        help="Path to hunts directory (default: <repo-root>/hunts).",
    )
    parser.add_argument(
        "--campaigns-dir",
        type=Path,
        default=None,
        help="Path to campaigns directory (default: <repo-root>/campaigns).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output JSON path (default: <repo-root>/scripts/metrics/hunt_metrics_summary.json).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail with non-zero exit code if validation errors exist or dashboard generation fails.",
    )
    parser.add_argument(
        "--no-campaign-file-updates",
        action="store_true",
        help="Do not rewrite auto-regions inside campaign markdown files.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    hunts_dir = (args.hunts_dir or (repo_root / "hunts")).resolve()
    campaigns_dir = (args.campaigns_dir or (repo_root / "campaigns")).resolve()
    output_json = (args.output or (repo_root / "scripts" / "metrics" / "hunt_metrics_summary.json")).resolve()
    dashboard_script = (repo_root / "scripts" / "metrics" / "generate_dashboard.py").resolve()

    # Parse campaigns first so hunt campaign_slugs can be checked against real slugs.
    campaign_files = find_markdown_files(campaigns_dir)
    campaign_records = [parse_campaign_file(p) for p in campaign_files]

    # Invalid campaigns do not register a slug, so hunts cannot link to them.
    slug_to_campaign: dict[str, CampaignRecord] = {}
    for c in sorted(campaign_records, key=lambda x: x.path):
        if not c.slug or not c.is_valid:
            continue
        if c.slug in slug_to_campaign:
            c.errors.append(
                f"{c.path}: duplicate `campaign_slug` `{c.slug}` "
                f"(also defined in {slug_to_campaign[c.slug].path})."
            )
        else:
            slug_to_campaign[c.slug] = c

    known_slugs = set(slug_to_campaign.keys())

    hunt_files = find_markdown_files(hunts_dir) if hunts_dir.exists() else []
    hunt_records = [parse_hunt_file(p) for p in hunt_files]

    for h in hunt_records:
        collect_hunt_campaign_slug_refs(h, known_slugs)

    slug_to_hunts: dict[str, list[HuntRecord]] = defaultdict(list)
    for h in hunt_records:
        if not h.is_valid:
            continue
        for s in h.linked_campaign_slugs:
            slug_to_hunts[s].append(h)

    campaigns_summary = build_campaign_summary_json(repo_root, campaign_records, slug_to_hunts)

    if not args.no_campaign_file_updates:
        for slug, c in slug_to_campaign.items():
            if not c.is_valid:
                continue
            linked = slug_to_hunts.get(slug, [])
            stats = aggregate_campaign_stats(linked)
            flat_stats = {
                "linked_hunt_count": stats["linked_hunt_count"],
                **stats["aggregated_outcomes"],
                "last_activity_date": stats["last_activity_date"] or "—",
            }
            update_campaign_file(repo_root, c, linked, flat_stats)

    hunt_summaries = []
    for h in sorted(hunt_records, key=lambda x: str(x.path)):
        if h.is_valid:
            hunt_summaries.append(hunt_summary_row(repo_root, h))

    report = build_report(hunt_records, campaign_records, campaigns_summary, hunt_summaries)
    write_json(output_json, report)

    invalid_total = len(report["validation"]["errors"])
    print(
        f"Parsed {report['meta']['hunts_scanned']} hunt(s), "
        f"{report['meta']['campaigns_scanned']} campaign(s); "
        f"{invalid_total} file(s) with validation errors."
    )
    print(f"Wrote summary JSON: {output_json}")

    if invalid_total:
        print("\nValidation errors:", file=sys.stderr)
        for err in report["validation"]["errors"]:
            print(f"- {err['path']}", file=sys.stderr)
            for line in err["errors"]:
                print(f"  - {line}", file=sys.stderr)
        if args.strict:
            # JSON is already written. Try dashboard with strict off so you still get a file.
            run_dashboard_generator(dashboard_script, output_json, strict=False)
            return 1

    run_dashboard_generator(dashboard_script, output_json, strict=args.strict)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
