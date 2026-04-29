#!/usr/bin/env python3
"""Bootstrap hunt/campaign markdown from a GitHub Issues event.

Intended to run in Actions: read $GITHUB_EVENT_PATH, pull answers out of the
issue body (issue forms render as markdown with ### headings), then write a
new file under hunts/ or campaigns/ from the repo templates.

Not a general-purpose issue parser as it only needs to match our own forms.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


# Issue forms dump each answer under a ### label line to split on.
HEADING_RE = re.compile(r"^###\s+(.*)\s*$")
KEBAB_RE = re.compile(r"[^a-z0-9]+")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Bootstrap hunt/campaign markdown from issue form.")
    p.add_argument("--event-path", type=Path, required=True)
    p.add_argument("--repo-root", type=Path, required=True)
    p.add_argument("--output-file", type=Path, required=False)
    return p.parse_args()


def slugify(text: str) -> str:
    # Safe filename stem same rules we use for campaign_slug in the parser.
    s = KEBAB_RE.sub("-", text.strip().lower()).strip("-")
    return s or "draft"


def parse_form_sections(body: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for raw in body.splitlines():
        m = HEADING_RE.match(raw)
        if m:
            current = m.group(1).strip()
            sections[current] = []
            continue
        if current is not None:
            sections[current].append(raw)
    return {k: "\n".join(v).strip() for k, v in sections.items()}


def parse_checkbox_values(text: str) -> list[str]:
    # Checkbox answers show up as `- [x] label` when checked but keep a fallback for plain bullets.
    vals: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        m = re.match(r"^- \[x\]\s+(.*)$", s, re.IGNORECASE)
        if m:
            vals.append(m.group(1).strip())
            continue
        m2 = re.match(r"^-+\s+(.*)$", s)
        if m2:
            vals.append(m2.group(1).strip())
            continue
        vals.append(s)
    return [v for v in vals if v]


def parse_line_values(text: str) -> list[str]:
    out: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("- "):
            s = s[2:].strip()
        out.append(s)
    return out


def parse_threat_actor_maps(text: str) -> list[dict[str, str]]:
    # Loose parser for the YAML-ish block hunters paste in the form. Good enough for drafts.
    actors: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("- "):
            if current:
                actors.append(current)
            current = {}
            s = s[2:].strip()
        if ":" in s and current is not None:
            k, v = s.split(":", 1)
            key = k.strip().lower()
            val = v.strip()
            if key in {"name", "type"} and val:
                current[key] = val
    if current:
        actors.append(current)
    actors = [a for a in actors if a.get("name") or a.get("type")]
    if not actors:
        return [{"name": "Unknown", "type": "unknown"}]
    for a in actors:
        a.setdefault("name", "Unknown")
        a.setdefault("type", "unknown")
    return actors


def split_frontmatter(template: str) -> tuple[str, str]:
    parts = template.split("---", 2)
    if len(parts) < 3:
        raise ValueError("Template missing frontmatter markers.")
    return parts[1].strip(), parts[2].lstrip("\n")


def yaml_quote(value: str) -> str:
    # Double-quoted scalars only this keeps the script free of a yaml emitter dependency.
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def emit_yaml_list(values: list[str], indent: int = 0) -> str:
    pad = " " * indent
    if not values:
        return f"{pad}- \"none\""
    return "\n".join(f"{pad}- {yaml_quote(v)}" for v in values)


def render_hunt_frontmatter(fields: dict[str, str], issue_num: int) -> str:
    title = fields.get("title") or f"Issue {issue_num} Hunt Draft"
    campaigns = parse_line_values(fields.get("campaigns", "none")) or ["none"]
    # If they put a kebab slug in `campaigns`, mirror it into campaign_slugs for metrics linking.
    campaign_slugs = [c for c in campaigns if re.match(r"^[a-z0-9]+(?:-[a-z0-9]+)*$", c)]
    data_sources = parse_checkbox_values(fields.get("data_sources", ""))
    data_sources += parse_line_values(fields.get("data_sources_other (optional)", ""))
    locations = parse_checkbox_values(fields.get("data_source_locations", ""))
    locations += parse_line_values(fields.get("data_source_locations_other (optional)", ""))
    langs = parse_checkbox_values(fields.get("query_languages", ""))
    langs += parse_line_values(fields.get("query_languages_other (optional)", ""))
    outcomes = parse_line_values(fields.get("outcomes", "")) or ["expected: TBD"]
    tactics = [v.upper() for v in parse_line_values(fields.get("mitre_tactics", ""))]
    techniques = parse_line_values(fields.get("mitre_techniques", ""))
    actors = parse_threat_actor_maps(fields.get("threat_actors (name + type list)", ""))

    lines = [
        "---",
        f'title: {yaml_quote(title)}',
        f'hunt_id: {yaml_quote(fields.get("hunt_id", f"HUNT-{issue_num}"))}',
        f'author: {yaml_quote(fields.get("author", "unknown"))}',
        f'created_date: {yaml_quote(fields.get("created_date", "YYYY-MM-DD"))}',
        f'updated_date: {yaml_quote(fields.get("updated_date", "YYYY-MM-DD"))}',
        f'hunt_type: {yaml_quote(fields.get("hunt_type", "Hypothesis-driven"))}',
        f'status: {yaml_quote(fields.get("status", "draft"))}',
        "mitre_techniques:",
        emit_yaml_list(techniques, indent=2),
        "mitre_tactics:",
        emit_yaml_list(tactics, indent=2),
        "threat_actors:",
    ]
    for actor in actors:
        lines.append(f'  - name: {yaml_quote(actor.get("name", "Unknown"))}')
        lines.append(f'    type: {yaml_quote(actor.get("type", "unknown"))}')
    lines.extend(
        [
            "campaigns:",
            emit_yaml_list(campaigns, indent=2),
        ]
    )
    if campaign_slugs:
        lines.extend(["campaign_slugs:", emit_yaml_list(campaign_slugs, indent=2)])
    lines.extend(
        [
            "data_sources:",
            emit_yaml_list(data_sources or ["edr_alerts"], indent=2),
            "data_source_locations:",
            emit_yaml_list(locations or ["EDR platform"], indent=2),
            "query_languages:",
            emit_yaml_list(langs or ["KQL"], indent=2),
            "outcomes:",
            emit_yaml_list(outcomes, indent=2),
            "---",
        ]
    )
    return "\n".join(lines) + "\n"


def render_campaign_frontmatter(fields: dict[str, str], issue_num: int) -> str:
    title = fields.get("title") or f"Issue {issue_num} Campaign Draft"
    slug = slugify(
        fields.get("campaign_slug (canonical)")
        or fields.get("campaign_slug (suggested)")
        or title
    )
    all_mitre = parse_line_values(fields.get("overall_mitre_tactics_and_techniques", ""))
    # Form mixes TA and T in one box.. split so frontmatter matches campaign-template shape.
    tactics = [v.upper() for v in all_mitre if v.upper().startswith("TA")]
    techniques = [v for v in all_mitre if v.upper().startswith("T") and not v.upper().startswith("TA")]
    lines = [
        "---",
        f'title: {yaml_quote(title)}',
        f'campaign_slug: {yaml_quote(slug)}',
        f'threat_actor_type: {yaml_quote(fields.get("threat_actor_type", "unknown"))}',
        f'threat_actor_name: {yaml_quote(fields.get("threat_actor_name", "Unknown"))}',
        f'start_date: {yaml_quote(fields.get("start_date", "YYYY-MM-DD"))}',
    ]
    end_date = fields.get("end_date (optional)", "").strip()
    lines.append(f'end_date: {yaml_quote(end_date)}' if end_date else "end_date: null")
    lines.extend(
        [
            f'description: {yaml_quote(fields.get("description / objectives (summary)", ""))}',
            "mitre_tactics:",
            emit_yaml_list(tactics or ["TA0000"], indent=2),
            "mitre_techniques:",
            emit_yaml_list(techniques or ["T0000"], indent=2),
            'status: "draft"',
            "---",
        ]
    )
    return "\n".join(lines) + "\n"


def write_outputs(out_path: Path | None, **kwargs: str) -> None:
    # GITHUB_OUTPUT is key=value lines, workflow steps read these as outputs.
    if out_path is None:
        return
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("a", encoding="utf-8") as fh:
        for k, v in kwargs.items():
            fh.write(f"{k}={v}\n")


def has_required_fields(form: dict[str, str], required: list[str]) -> bool:
    for key in required:
        if not form.get(key, "").strip():
            return False
    return True


def hunt_draft_banner(issue_num: int) -> str:
    return "\n".join(
        [
            "> [!IMPORTANT] **Draft hunt (bootstrap)**",
            "> ",
            "> **Prefilled from intake** (issue form → YAML frontmatter above, plus any **Imported Intake Narrative** section below):",
            "> - metadata fields used for dashboards and linking",
            "> ",
            "> **You still need to complete** (this template body is mostly guidance until you replace it):",
            "> - PEAK sections with real operational detail",
            "> - at least one working `threat-hunt-query` block (replace the example placeholder if needed)",
            "> - `threat-hunt-ioc` blocks when indicators exist",
            "> - validation notes, findings, and outcomes as the hunt progresses",
            "> ",
            f"> _Generated from GitHub issue #{issue_num}. Remove this callout when the hunt is ready for formal review._",
            "",
        ]
    )


def campaign_draft_banner(issue_num: int) -> str:
    return "\n".join(
        [
            "> [!IMPORTANT] **Draft campaign umbrella (bootstrap)**",
            "> ",
            "> **Prefilled from intake** (issue form → YAML frontmatter above, plus **Campaign overview** if imported):",
            "> - umbrella metadata for reporting and hunt linkage",
            "> ",
            "> **You still need to complete** (high-level only — no hunt queries here):",
            "> - Threat actor context table (confidence, themes)",
            "> - umbrella objectives table (measurable success signals)",
            "> - references list (stable links / ticket IDs)",
            "> ",
            f"> _Generated from GitHub issue #{issue_num}. Remove this callout when the umbrella is ready for formal review._",
            "",
        ]
    )


def annotate_after_heading(markdown: str, heading: str, note: str) -> str:
    # First match only the headings are unique in our templates.
    needle = heading
    if needle not in markdown:
        return markdown
    return markdown.replace(needle, needle + "\n\n" + note.strip() + "\n", 1)


def annotate_hunt_markdown(markdown_body: str, issue_num: int) -> str:
    lines = markdown_body.splitlines()
    if lines:
        insert_at = 1 if len(lines) > 1 else len(lines)
        lines.insert(insert_at, hunt_draft_banner(issue_num))
        markdown_body = "\n".join(lines)

    todo = "<!-- HUNTER TODO: replace placeholder guidance with real hunt content -->"
    markdown_body = annotate_after_heading(markdown_body, "## 🟦 Prepare", todo)
    markdown_body = annotate_after_heading(markdown_body, "## 🟨 Execute", todo)
    markdown_body = annotate_after_heading(markdown_body, "## 🟥 Act", todo)
    markdown_body = annotate_after_heading(markdown_body, "## 🟩 Knowledge", todo)
    markdown_body = annotate_after_heading(
        markdown_body,
        "### 2) Queries (Parser-Extractable)",
        "<!-- HUNTER TODO: replace example query blocks with real hunt queries -->",
    )
    markdown_body = annotate_after_heading(
        markdown_body,
        "### 3) IOCs (Parser-Extractable)",
        "<!-- HUNTER TODO: add IOC blocks when applicable (or note none observed) -->",
    )
    return markdown_body


def annotate_campaign_markdown(markdown_body: str, issue_num: int) -> str:
    lines = markdown_body.splitlines()
    if lines:
        insert_at = 1 if len(lines) > 1 else len(lines)
        lines.insert(insert_at, campaign_draft_banner(issue_num))
        markdown_body = "\n".join(lines)

    todo = "<!-- HUNTER TODO: complete this umbrella section (high-level only) -->"
    markdown_body = annotate_after_heading(markdown_body, "## 🎭 Threat Actor Context", todo)
    markdown_body = annotate_after_heading(markdown_body, "## 🎯 High-level Objectives", todo)
    markdown_body = annotate_after_heading(markdown_body, "## 📚 References", todo)
    return markdown_body


def main() -> int:
    args = parse_args()
    event = json.loads(args.event_path.read_text(encoding="utf-8"))
    issue = event.get("issue", {})
    labels = {l.get("name", "") for l in issue.get("labels", [])}
    issue_body = issue.get("body", "") or ""
    issue_num = int(issue.get("number", 0))

    # Workflow should gate labels, but we still defensively branch here.
    form = parse_form_sections(issue_body)
    repo_root = args.repo_root.resolve()

    has_hunt_label = "hunt" in labels
    has_campaign_label = "campaign" in labels
    if has_hunt_label and has_campaign_label:
        write_outputs(args.output_file, created="false", reason="ambiguous_labels")
        return 0

    if has_hunt_label:
        if not has_required_fields(form, ["title", "hunt_id", "hunt_type"]):
            write_outputs(args.output_file, created="false", reason="invalid_hunt_form")
            return 0
        template_path = repo_root / "templates" / "hunt-template.md"
        template_body = template_path.read_text(encoding="utf-8")
        _, markdown_body = split_frontmatter(template_body)
        fm = render_hunt_frontmatter(form, issue_num)
        title = form.get("title", f"Issue {issue_num} Hunt Draft")
        narrative = form.get("Narrative / Full Documentation", "").strip()
        markdown_body = markdown_body.replace(
            "# 🔎 Threat Hunt: Replace with Hunt Title",
            f"# 🔎 Threat Hunt: {title}",
            1,
        )
        if narrative:
            markdown_body += (
                "\n\n---\n\n## Imported Intake Narrative\n\n"
                f"> **Prefilled from issue form** (issue #{issue_num}). Treat as raw intake; refine into PEAK sections above as the hunt matures.\n\n"
                f"{narrative}\n"
            )
        markdown_body = annotate_hunt_markdown(markdown_body, issue_num)
        hunt_id = form.get("hunt_id", "").strip()
        file_stem = slugify(hunt_id if hunt_id and "YYYY" not in hunt_id else title)
        target = repo_root / "hunts" / f"{file_stem}.md"
    elif has_campaign_label:
        if not has_required_fields(form, ["title", "campaign_slug (canonical)", "start_date"]):
            write_outputs(args.output_file, created="false", reason="invalid_campaign_form")
            return 0
        template_path = repo_root / "templates" / "campaign-template.md"
        template_body = template_path.read_text(encoding="utf-8")
        _, markdown_body = split_frontmatter(template_body)
        fm = render_campaign_frontmatter(form, issue_num)
        title = form.get("title", f"Issue {issue_num} Campaign Draft")
        overview = form.get("Campaign overview (full narrative)", "").strip()
        markdown_body = markdown_body.replace(
            "# 🗂️ Campaign: Replace with Title",
            f"# 🗂️ Campaign: {title}",
            1,
        )
        if overview:
            markdown_body = markdown_body.replace(
                "## 📋 Campaign Overview\n\nSummarize the **campaign umbrella** in plain language: what threat activity or narrative this grouping represents, why it exists as a container, and what time horizon or business context applies.\n\n- **Narrative (2–4 sentences)**:\n- **Scope boundaries** (what is intentionally *out* of this umbrella):\n- **Relationship to intelligence** (public reporting, IR themes, sector trends — no paste of classified or sensitive operational detail):",
                f"## 📋 Campaign Overview\n\n> **Prefilled from issue form** (issue #{issue_num}). Expand/refine scope and sourcing notes below as the umbrella matures.\n\n{overview}",
                1,
            )
        markdown_body = annotate_campaign_markdown(markdown_body, issue_num)
        slug = slugify(form.get("campaign_slug (canonical)", "").strip() or title)
        target = repo_root / "campaigns" / f"{slug}.md"
    else:
        write_outputs(args.output_file, created="false", reason="unsupported_label")
        return 0

    if target.exists():
        write_outputs(args.output_file, created="false", reason="already_exists", file=str(target))
        return 0

    # If this file already exists, stop and don't overwrite what someone already edited.
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(fm + "\n" + markdown_body.lstrip("\n"), encoding="utf-8")
    rel = target.relative_to(repo_root).as_posix()
    write_outputs(
        args.output_file,
        created="true",
        file=rel,
        branch=f"auto/issue-{issue_num}-bootstrap",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
