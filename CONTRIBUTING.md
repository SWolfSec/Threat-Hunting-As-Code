# Contributing to Threat-Hunting-As-Code

This project uses an engineering-style workflow for threat hunting content so hunts are consistent, reviewable, and measurable over time.

## Guiding Principles

All contributions should align to PEAK:

- **Prioritized**: Focus on highest-risk behaviors, systems, and business impact.
- **Evidence-driven**: Base hunts on observable telemetry and explicit assumptions.
- **Actionable**: Produce outputs that improve detection, response, or hardening.
- **Knowledge-sharing**: Leave clear context so other analysts can reuse and improve the work.

## Team Workflow

Use this sequence for all hunt contributions:

1. Submit a new hunt idea through the GitHub **New Hunt** issue template.
2. Triage and scope the issue (owner, priority, data readiness, ATT&CK mapping).
3. Draft the hunt artifact using `templates/hunt-template.md`.
4. Open a pull request with the hunt content and any supporting logic.
5. Complete review, resolve feedback, and merge.
6. Confirm metrics/dashboard outputs are updated by automation.

## Step 1: Open a New Hunt Issue

Create a new issue using `.github/ISSUE_TEMPLATE/new-hunt.yml` and include:

- Hunt hypothesis
- Expected attacker behavior
- Data sources and telemetry requirements
- ATT&CK tactic/technique mapping (when applicable)
- Expected output and response action

Issues are the source of truth for intake and planning.

## Step 2: Triage and Assign

During triage, reviewers should validate:

- Scope is small enough to execute in a sprint
- Required telemetry exists (or gaps are documented)
- Success criteria are testable
- Priority reflects risk and business impact

Assign an owner before implementation begins.

## Step 3: Author the Hunt

Use `templates/hunt-template.md` as the canonical format.

Each hunt should clearly document:

- Objective and hypothesis
- Data sources and query logic
- Tuning assumptions and limitations
- Validation steps
- Outcome classification (true positive, benign, inconclusive, gap identified)

## Step 4: Open a Pull Request

PRs should be focused and include enough context for reviewers.

Recommended PR content:

- Link to the originating hunt issue
- Summary of what changed and why
- Evidence of validation (sample output, screenshots, or test notes)
- Follow-up work items (if any)

## Step 5: Review and Approval

Reviewers evaluate:

- Technical correctness of hunt logic
- Data/telemetry assumptions
- Alignment with PEAK principles
- Reusability and clarity of documentation

CODEOWNERS and maintainers provide final approval where required.

## Step 6: Merge and Metrics

After merge:

- GitHub Actions workflows process hunt metadata and metrics
- Scripts in `scripts/metrics/` update dashboard inputs
- `docs/dashboard.md` reflects current program visibility

If expected dashboard updates do not appear, open a follow-up issue and link the related PR.

## Contribution Standards

- Keep changes scoped to one hunt or one improvement theme per PR.
- Prefer explicit assumptions over implicit analyst knowledge.
- Avoid embedding secrets, credentials, or sensitive data.
- Use consistent naming and ATT&CK terminology.

### Controlled Vocabulary Governance (Simple)

- If a value is not available in a template dropdown/checkbox, use the related `*_other` field.
- If the same `*_other` value is used repeatedly, open a small PR to add it as a standard static option.
- Maintainers review and approve list updates so reporting remains consistent.

## Branch and Commit Guidelines

- Use short, descriptive branch names (example: `hunt/t1059-powershell-suspicious-parent`).
- Write commit messages that explain intent, not just file edits.
- Rebase or merge main regularly to avoid drift.

## Getting Help

- Open an issue for workflow or template questions.
- Tag maintainers or CODEOWNERS when blocked on review.
- Propose improvements to templates and automation through PRs.
