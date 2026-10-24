# VulnScribe — Shared Project Context

This file is a concise repository handoff for contributors and coding assistants. It intentionally excludes personal profile details, local workstation paths/configuration, unrelated projects, and expanded conversation history.

## Project purpose

VulnScribe is an evidence-first vulnerability-analysis MVP for authorized source artifacts and raw HTTP responses. It uses deterministic checks to produce candidate findings with supporting evidence and report output.

## Current MVP scope

As described by the repository README and implementation:

- Static pattern checks for supported source-code inputs.
- Security-header checks against supplied raw HTTP responses.
- FastAPI endpoints and a command-line interface.
- JSON and Markdown reports.

Findings are candidates for human review, not proof of exploitability or confirmed vulnerabilities. Severity estimates and confidence are distinct. CVSS is not assigned automatically in this MVP.

## Safety boundaries

- Analyze only artifacts the operator is authorized to handle.
- The current MVP does not contact live targets, execute submitted source, clone arbitrary repositories, or perform active tests.
- Treat submitted source, filenames, HTTP responses, and scanner output as untrusted data.
- Do not expose the development server publicly. Review `docs/SECURITY.md` before any shared or public deployment; its listed controls are requirements, not claims that they are all implemented.

## Source of truth

Read these repository files before making project changes:

- `AGENTS.md` — working, verification, security, and Git-safety instructions.
- `README.md` — supported MVP entry points and usage.
- `docs/OOAD.md` — design and intended architecture.
- `docs/SECURITY.md` — threat notes and requirements before shared/public deployment.
- Application code and tests — authoritative evidence for implemented behavior.

If documentation, implementation, and test evidence disagree, report the discrepancy rather than silently treating a proposal as implemented.

## Collaboration and verification

- Inspect the current branch, commit, and working-tree status before acting. Preserve existing user changes and untracked files.
- Keep changes within the explicitly authorized scope; follow `AGENTS.md` for approval gates.
- Distinguish verified facts, proposals, assumptions, and unresolved decisions.
- Report the exact checks actually run, their results, and checks not run. Do not claim successful verification without command output.
- Do not publish secrets, private data, sensitive scan artifacts, or machine-specific context in shared project documentation.

## Maintenance

Keep this document short and project-focused. Update it when repository scope or supported behavior changes, and point to canonical repository files instead of copying long histories or private conversation notes. This file does not replace source code, tests, review, or explicit project-owner decisions.
