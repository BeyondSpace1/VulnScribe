# VulnScribe Work Queue

This is the ordered list of candidate tasks. Every item is **PROPOSED** until explicitly approved. Status describes evidence-backed task state; it is not a confidence label or a release declaration.

## Status vocabulary

Use only: `PROPOSED`, `APPROVED`, `IN_PROGRESS`, `IMPLEMENTED`, `VERIFIED`, `RELEASED`, `BLOCKED`, `DEFERRED`.

- **PROPOSED:** awaiting owner approval or prioritization.
- **APPROVED:** scope and acceptance criteria were explicitly approved.
- **IN_PROGRESS:** work has started on the approved task.
- **IMPLEMENTED:** implementation is complete, but not necessarily verified.
- **VERIFIED:** required checks passed and evidence is recorded.
- **RELEASED:** included in an explicitly recorded release.
- **BLOCKED:** cannot proceed; record the blocker.
- **DEFERRED:** intentionally postponed; record why if known.

A status must be supported by a reviewable record or actual check output. Do not mark work VERIFIED merely because it appears implemented or because a related check passed.

## Proposed order

| ID | Task | Status | Acceptance evidence |
|---|---|---|---|
| VS-001 | Verify the merged application baseline | VERIFIED | At `9a5543726353f7cef4ad49561842b25f805e8326`: API tests 16 passed; full applicable suite 16 passed; Ruff and `git diff --check` passed. One Starlette/httpx deprecation warning; no scanner-accuracy tests were present in that baseline. |
| VS-002 | Establish scanner evaluation fixtures and labeling | PROPOSED | Reviewed authorized fixture provenance, expected findings and non-findings, and documented limitations. |
| VS-003 | Build scanner regression and accuracy tests | VERIFIED | 44 focused synthetic scanner regression cases passed; API tests 16 passed; full suite 60 passed; Ruff and whitespace check passed on `test/scanner-regression`. Covers rule candidates, safe controls, language routing, evidence, and known false-positive limitations. This is not a precision/recall or accuracy claim. The repository verification script invocation was blocked by PowerShell execution policy; equivalent direct checks used existing executables. |
| VS-004 | Normalize finding and report behavior | PROPOSED | Agreed output contract and regression tests for evidence, validation state, report escaping, and warnings. |
| VS-005 | Document supported languages/rules and known gaps | PROPOSED | Documentation matches inspected implementation and explicitly describes unsupported cases. |
| VS-006 | Decide intended deployment audience and security gate | PROPOSED | Recorded owner decision, scoped threat model, and verifiable controls for that audience. |
| VS-007 | Define release/support policy before V1.0 | PROPOSED | Owner-approved SemVer, compatibility, support, artifact, and security-fix policy. |
| VS-008 | Make HSTS evaluation depend on explicit transport context | VERIFIED | Verified in commit `24551b80f881e1ec4dd4d3b47aaf17a2daec55e0`: API, CLI, and scanner regression cases covered unknown/HTTP/HTTPS context; 71 tests passed and Ruff passed. |
| VS-009 | Reduce Python eval/exec false positives with AST detection | VERIFIED | Verified in commit `24551b80f881e1ec4dd4d3b47aaf17a2daec55e0`: 71 tests passed, Ruff passed; comment/string false positives suppressed, direct eval/exec candidates retain evidence and locations, malformed Python does not fall back to regex. |
| VS-010 | Deliver a local browser-based scan and report preview | IN_PROGRESS | Local UI supports source/HTTP scans, evidence review, safe DOM rendering, JSON/Markdown downloads, and local-only processing; API/UI tests pass. |
| VS-011 | Add structured bug reporting and alpha-candidate metadata | IN_PROGRESS | GitHub Issue Form warns against sharing secrets; package/API version strings agree; release notes and limitations are documented; no release is claimed before verification. |
| VS-012 | Verify and publish the `0.2.0-alpha.1` preview | PROPOSED | Exact candidate tests, Ruff, packaging/install checks, safe UI journey review, known limitations, and explicit approval completed before creating the tag and GitHub pre-release. |

## Working rules

- Work on one prioritized task at a time; do not start multiple branches for separate assistants.
- Each approved task needs a bounded scope and acceptance criteria before implementation.
- Preserve user data and local-only files; don't publish fixtures or artifacts with unverified provenance.
- Report exact changed files, commands, exit codes, warnings, and checks not run.
- Update task status only when the evidence supports it.
