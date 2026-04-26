#!/usr/bin/env python3
"""
Generate a markdown dashboard from hunt metrics JSON.

Input JSON is expected to match the structure emitted by
`scripts/metrics/parse_hunts.py`.

Output:
- Markdown report at `docs/dashboard.md` by default
- Mermaid charts embedded as fenced markdown blocks

Dependencies: Python stdlib only.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate docs/dashboard.md from parsed hunt metrics JSON."
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Path to metrics summary JSON from parse_hunts.py.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Path to output markdown file (default: <repo-root>/docs/dashboard.md).",
    )
    return parser.parse_args()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def pct(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round((numerator / denominator) * 100, 2)


def to_sorted_items(counter_like: dict[str, Any]) -> list[tuple[str, int]]:
    normalized = [(str(k), int(v)) for k, v in counter_like.items()]
    # Sort by count desc, then key asc for deterministic output.
    return sorted(normalized, key=lambda t: (-t[1], t[0]))


def mermaid_pie(title: str, items: list[tuple[str, int]]) -> str:
    if not items:
        items = [("none", 1)]
    lines = ["```mermaid", "pie showData", f'    title {title}']
    for label, value in items:
        safe_label = label.replace('"', "'")
        lines.append(f'    "{safe_label}" : {value}')
    lines.append("```")
    return "\n".join(lines)


def mermaid_bar(title: str, items: list[tuple[str, int]]) -> str:
    if not items:
        items = [("none", 0)]
    x_labels = [label for label, _ in items]
    y_vals = [value for _, value in items]

    # xychart-beta is widely supported by Mermaid renderers in markdown.
    quoted_labels = ", ".join(f'"{x}"' for x in x_labels)

    return "\n".join(
        [
            "```mermaid",
            "xychart-beta",
            f'    title "{title}"',
            f"    x-axis [{quoted_labels}]",
            '    y-axis "Count" 0 --> ' + str(max(y_vals) if y_vals else 1),
            f"    bar [{', '.join(str(v) for v in y_vals)}]",
            "```",
        ]
    )


def build_summary_section(metrics: dict[str, Any], meta: dict[str, Any]) -> str:
    totals = metrics.get("totals", {})
    outcome_hunt_level = metrics.get("outcomes", {}).get("hunt_level_counts", {})

    hunts_total = int(totals.get("hunts_total", 0))
    hunts_valid = int(meta.get("hunts_valid", 0))
    hunts_invalid = int(meta.get("hunts_invalid", 0))
    campaigns_valid = int(meta.get("campaigns_valid", 0))
    campaigns_invalid = int(meta.get("campaigns_invalid", 0))
    queries_total = int(totals.get("query_blocks_total", 0))
    iocs_total = int(totals.get("ioc_blocks_total", 0))

    hunts_with_detection = int(outcome_hunt_level.get("hunts_with_detections", 0))
    hunts_with_prevention = int(outcome_hunt_level.get("hunts_with_preventions", 0))
    hunts_with_visibility = int(outcome_hunt_level.get("hunts_with_visibility_created", 0))

    return "\n".join(
        [
            "## Summary Stats",
            "",
            "| Metric | Value |",
            "| --- | ---: |",
            f"| Hunts scanned | {int(meta.get('hunts_scanned', 0))} |",
            f"| Hunts valid | {hunts_valid} |",
            f"| Hunts invalid | {hunts_invalid} |",
            f"| Campaigns valid | {campaigns_valid} |",
            f"| Campaigns invalid | {campaigns_invalid} |",
            f"| Hunts total (metrics scope) | {hunts_total} |",
            f"| Query blocks extracted | {queries_total} |",
            f"| IOC blocks extracted | {iocs_total} |",
            f"| Hunts with detections | {hunts_with_detection} ({pct(hunts_with_detection, hunts_total)}%) |",
            f"| Hunts with preventions | {hunts_with_prevention} ({pct(hunts_with_prevention, hunts_total)}%) |",
            f"| Hunts with visibility created | {hunts_with_visibility} ({pct(hunts_with_visibility, hunts_total)}%) |",
        ]
    )


def _short_label(slug: str, max_len: int = 14) -> str:
    s = str(slug)
    if len(s) <= max_len:
        return s
    return s[: max_len - 1] + "…"


def build_active_campaigns_section(payload: dict[str, Any]) -> str:
    rows = payload.get("campaigns_summary", [])
    if not isinstance(rows, list) or not rows:
        return "\n".join(
            [
                "## Active Campaigns",
                "",
                "> No campaign files found under `campaigns/`, or none passed validation.",
                "",
            ]
        )

    sorted_rows = sorted(
        rows,
        key=lambda r: (-int(r.get("linked_hunt_count", 0) or 0), str(r.get("campaign_slug", ""))),
    )

    bar_items = [
        (_short_label(str(r.get("campaign_slug", "unknown"))), int(r.get("linked_hunt_count", 0) or 0))
        for r in sorted_rows
    ]

    lines = [
        "## Active Campaigns",
        "",
        "Campaigns with linked hunts (from `campaigns/*.md` and hunt `campaign_slugs` / kebab `campaigns` entries).",
        "",
        mermaid_bar("Linked hunts per campaign (count)", bar_items),
        "",
        "| Campaign | Threat actor | # Linked hunts | MITRE % covered (children) | Detections created (hunts) | Last activity | Campaign file |",
        "| --- | --- | ---: | ---: | ---: | --- | --- |",
    ]

    for r in sorted_rows:
        title = str(r.get("title", "n/a")).replace("|", "\\|")
        slug = str(r.get("campaign_slug", "n/a"))
        an = str(r.get("threat_actor_name", "n/a"))
        at = str(r.get("threat_actor_type", "n/a"))
        actor = f"{an} ({at})".replace("|", "\\|")
        nlink = int(r.get("linked_hunt_count", 0) or 0)
        mitre_pct = r.get("mitre_from_children", {}).get("coverage_percent_of_known_tactics", 0)
        det_hunts = int(r.get("aggregated_outcomes", {}).get("hunts_with_detection", 0) or 0)
        last = str(r.get("last_activity_date") or "—")
        path = str(r.get("path", ""))
        link = f"[Open]({path})" if path else "—"
        lines.append(
            f"| {title} | {actor} | {nlink} | {mitre_pct} | {det_hunts} | {last} | {link} |"
        )

    lines.append("")
    return "\n".join(lines)


def build_recent_hunts_table(payload: dict[str, Any]) -> str:
    """
    Build recent hunts table.

    parse_hunts.py currently does not guarantee detailed per-hunt rows in JSON.
    This section gracefully handles both:
    - payload["hunts"] as list of dicts (if present in future)
    - no hunt rows available (renders placeholder guidance)
    """
    hunts = payload.get("hunts", [])
    if isinstance(hunts, list) and hunts:
        # Try common keys and keep table concise.
        rows = []
        for h in hunts[:10]:
            if not isinstance(h, dict):
                continue
            rows.append(
                (
                    str(h.get("hunt_id", "n/a")),
                    str(h.get("title", "n/a")),
                    str(h.get("hunt_type", "n/a")),
                    str(h.get("status", "n/a")),
                    str(h.get("updated_date", h.get("created_date", "n/a"))),
                )
            )
        if rows:
            lines = [
                "## Recent Hunts",
                "",
                "| Hunt ID | Title | Type | Status | Last Updated |",
                "| --- | --- | --- | --- | --- |",
            ]
            for r in rows:
                lines.append(f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} |")
            return "\n".join(lines)

    return "\n".join(
        [
            "## Recent Hunts",
            "",
            "> [!NOTE]",
            "> No hunt rows in JSON (expected when no valid hunts are parsed).",
            "",
            "| Hunt ID | Title | Type | Status | Last Updated |",
            "| --- | --- | --- | --- | --- |",
            "| n/a | No hunt detail rows in JSON yet | n/a | n/a | n/a |",
        ]
    )


def mitre_heat_band(count: int) -> str:
    if count <= 0:
        return "⬜ None"
    if count == 1:
        return "🟨 Low"
    if count <= 3:
        return "🟧 Medium"
    return "🟥 High"


def build_mitre_heatmap_table(metrics: dict[str, Any]) -> str:
    mitre = metrics.get("mitre", {})
    tactic_counts = mitre.get("tactic_counts", {}) or {}
    technique_counts = mitre.get("technique_counts", {}) or {}

    rows = to_sorted_items(tactic_counts)
    if not rows:
        rows = [("none", 0)]

    top_techniques = to_sorted_items(technique_counts)[:5]
    top_technique_text = ", ".join(f"{name} ({count})" for name, count in top_techniques) or "n/a"

    lines = [
        "## MITRE Coverage Heat Map",
        "",
        "| MITRE Tactic ID | Hunts Tagged | Coverage Band |",
        "| --- | ---: | --- |",
    ]
    for tactic_id, count in rows:
        lines.append(f"| `{tactic_id}` | {count} | {mitre_heat_band(count)} |")

    lines.extend(
        [
            "",
            f"**Known ATT&CK tactic coverage:** {mitre.get('coverage_percent_of_known_tactics', 0)}%",
            "",
            f"**Top techniques:** {top_technique_text}",
        ]
    )
    return "\n".join(lines)


def build_mermaid_charts(metrics: dict[str, Any]) -> str:
    distribution = metrics.get("distribution", {})
    mitre = metrics.get("mitre", {})
    threat_actor = metrics.get("threat_actors", {})

    hunt_type_counts = to_sorted_items(distribution.get("hunt_type_counts", {}))
    threat_actor_type_counts = to_sorted_items(threat_actor.get("type_counts", {}))

    known_cov = float(mitre.get("coverage_percent_of_known_tactics", 0.0))
    unknown_cov = round(max(0.0, 100.0 - known_cov), 2)
    mitre_cov_items = [("covered_known_tactics_%", int(round(known_cov))), ("uncovered_%", int(round(unknown_cov)))]

    return "\n".join(
        [
            "## Visuals",
            "",
            "### Hunt Types",
            "",
            mermaid_pie("Hunt Types Distribution", hunt_type_counts),
            "",
            "### MITRE Coverage",
            "",
            mermaid_bar("MITRE Known Tactic Coverage (%)", mitre_cov_items),
            "",
            "### Threat Actor Types",
            "",
            mermaid_pie("Threat Actor Type Distribution", threat_actor_type_counts),
        ]
    )


def build_export_note(metrics: dict[str, Any]) -> str:
    totals = metrics.get("totals", {})
    mitre = metrics.get("mitre", {})
    threat_actor = metrics.get("threat_actors", {})
    campaigns = metrics.get("campaigns", {})
    outcomes = metrics.get("outcomes", {})

    hunts_total = int(totals.get("hunts_total", 0))
    mitre_cov = mitre.get("coverage_percent_of_known_tactics", 0)
    actor_cov = threat_actor.get("coverage_percent_hunts_with_threat_actors", 0)
    campaign_cov = campaigns.get("coverage_percent_hunts_with_campaigns", 0)
    outcome_counts = outcomes.get("hunt_level_counts", {})

    return "\n".join(
        [
            "## Leadership Export Note",
            "",
            "> This dashboard summarizes current threat hunting program output and coverage posture from version-controlled hunt artifacts.",
            "",
            "- **Program scale:** "
            f"{hunts_total} hunts in current validated metrics scope.",
            "- **ATT&CK alignment:** "
            f"{mitre_cov}% known tactic coverage represented by hunts.",
            "- **Attribution context:** "
            f"{actor_cov}% of hunts include named/type threat actor attribution.",
            "- **Campaign intelligence linkage:** "
            f"{campaign_cov}% of hunts mapped to campaign context.",
            "- **Operational outcomes:** "
            f"detections={outcome_counts.get('hunts_with_detections', 0)}, "
            f"preventions={outcome_counts.get('hunts_with_preventions', 0)}, "
            f"visibility_created={outcome_counts.get('hunts_with_visibility_created', 0)}.",
        ]
    )


def build_dashboard(payload: dict[str, Any]) -> str:
    meta = payload.get("meta", {})
    metrics = payload.get("metrics", {})
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    parts = [
        "# Threat Hunt Dashboard",
        "",
        f"_Generated: {generated_at}_",
        "",
        build_active_campaigns_section(payload),
        "",
        build_summary_section(metrics, meta),
        "",
        build_mermaid_charts(metrics),
        "",
        build_recent_hunts_table(payload),
        "",
        build_mitre_heatmap_table(metrics),
        "",
        build_export_note(metrics),
        "",
    ]
    return "\n".join(parts).rstrip() + "\n"


def main() -> int:
    args = parse_args()
    input_path = args.input.resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"Input JSON not found: {input_path}")

    payload = read_json(input_path)
    repo_root = Path(__file__).resolve().parents[2]
    output_path = (args.output or (repo_root / "docs" / "dashboard.md")).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    markdown = build_dashboard(payload)
    output_path.write_text(markdown, encoding="utf-8")
    print(f"Wrote dashboard: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
