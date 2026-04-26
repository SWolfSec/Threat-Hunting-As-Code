#!/usr/bin/env python3
"""
Parse hunt markdown files and compute program metrics.

Behavior:
- Recursively scan `/hunts` for markdown files
- Parse YAML frontmatter from each hunt
- Extract parser-friendly markdown blocks:
  - ```threat-hunt-query
  - ```threat-hunt-ioc
- Validate required frontmatter fields
- Compute summary metrics for dashboards/reporting
- Write metrics JSON output
- Invoke `generate_dashboard.py` as a follow-on step

Dependencies: stdlib + PyYAML only.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import yaml


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

REQUIRED_FIELDS = [
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

FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?", re.DOTALL)
QUERY_BLOCK_RE = re.compile(
    r"```threat-hunt-query\s*\n(.*?)\n```", re.DOTALL | re.IGNORECASE
)
IOC_BLOCK_RE = re.compile(r"```threat-hunt-ioc\s*\n(.*?)\n```", re.DOTALL | re.IGNORECASE)


@dataclass
class HuntRecord:
    path: str
    frontmatter: dict[str, Any] = field(default_factory=dict)
    queries: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return not self.errors


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="replace")


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


def parse_iso_date(value: Any, field_name: str, path: str, errors: list[str]) -> date | None:
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


def validate_hunt(record: HuntRecord) -> None:
    fm = record.frontmatter
    path = record.path

    for field_name in REQUIRED_FIELDS:
        if field_name not in fm:
            record.errors.append(f"{path}: missing required field `{field_name}` in frontmatter.")

    # If base requirements are missing, keep validating what exists for best feedback.
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

    # threat_actors must be list of maps with name+type.
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


def compute_metrics(valid_records: list[HuntRecord]) -> dict[str, Any]:
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

    # Hunt-level coverage counters
    hunts_with_mitre = 0
    hunts_with_threat_actors = 0
    hunts_with_campaigns = 0
    hunts_with_detections = 0
    hunts_with_preventions = 0
    hunts_with_visibility_created = 0

    total_query_blocks = 0
    total_ioc_blocks = 0

    # Explicit keyword patterns for outcome rollups.
    detection_re = re.compile(r"\bdetect(ion|ed|s)?\b", re.IGNORECASE)
    prevention_re = re.compile(r"\bprevent(ion|ed|s)?\b", re.IGNORECASE)
    visibility_re = re.compile(r"\bvisibility\b|\btelemetry (added|created|improved)\b", re.IGNORECASE)

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

        # Outcome category rollups (hunt-level + aggregate-level).
        hunt_has_detection = False
        hunt_has_prevention = False
        hunt_has_visibility = False
        for out in outcomes:
            if detection_re.search(out):
                outcome_category_counts["detections"] += 1
                hunt_has_detection = True
            if prevention_re.search(out):
                outcome_category_counts["preventions"] += 1
                hunt_has_prevention = True
            if visibility_re.search(out):
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

    # % hunts with at least one MITRE mapping.
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


def build_report(records: list[HuntRecord]) -> dict[str, Any]:
    valid = [r for r in records if r.is_valid]
    invalid = [r for r in records if not r.is_valid]

    metrics = compute_metrics(valid_records=valid)
    return {
        "meta": {
            "generated_by": "scripts/metrics/parse_hunts.py",
            "hunts_scanned": len(records),
            "hunts_valid": len(valid),
            "hunts_invalid": len(invalid),
        },
        "validation": {
            "errors": [
                {"path": rec.path, "errors": rec.errors}
                for rec in sorted(invalid, key=lambda r: r.path)
            ],
        },
        "metrics": metrics,
    }


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


def find_hunt_files(hunts_dir: Path) -> list[Path]:
    return sorted(
        [p for p in hunts_dir.rglob("*.md") if p.is_file()],
        key=lambda p: str(p),
    )


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_dashboard_generator(script_path: Path, summary_json_path: Path, strict: bool) -> None:
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
        description="Parse hunt markdown files, validate metadata, and emit metrics JSON."
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
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    hunts_dir = (args.hunts_dir or (repo_root / "hunts")).resolve()
    output_json = (args.output or (repo_root / "scripts" / "metrics" / "hunt_metrics_summary.json")).resolve()
    dashboard_script = (repo_root / "scripts" / "metrics" / "generate_dashboard.py").resolve()

    if not hunts_dir.exists():
        print(f"[WARN] Hunts directory does not exist: {hunts_dir}", file=sys.stderr)
        # Still emit a valid empty report for deterministic downstream behavior.
        empty_report = {
            "meta": {
                "generated_by": "scripts/metrics/parse_hunts.py",
                "hunts_scanned": 0,
                "hunts_valid": 0,
                "hunts_invalid": 0,
            },
            "validation": {"errors": []},
            "metrics": compute_metrics([]),
        }
        write_json(output_json, empty_report)
        run_dashboard_generator(dashboard_script, output_json, strict=False)
        return 1 if args.strict else 0

    hunt_files = find_hunt_files(hunts_dir)
    records = [parse_hunt_file(path) for path in hunt_files]
    report = build_report(records)
    write_json(output_json, report)

    invalid_count = report["meta"]["hunts_invalid"]
    print(
        f"Parsed {report['meta']['hunts_scanned']} hunt file(s): "
        f"{report['meta']['hunts_valid']} valid, {invalid_count} invalid."
    )
    print(f"Wrote summary JSON: {output_json}")

    if invalid_count:
        print("\nValidation errors:", file=sys.stderr)
        for err in report["validation"]["errors"]:
            print(f"- {err['path']}", file=sys.stderr)
            for line in err["errors"]:
                print(f"  - {line}", file=sys.stderr)
        if args.strict:
            return 1

    run_dashboard_generator(dashboard_script, output_json, strict=args.strict)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
