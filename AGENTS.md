# VulnScribe Development Workflow

## Project scope
- Work only in this repository unless explicitly authorized otherwise.
- Inspect the existing architecture before making changes.
- Prefer small, testable changes over broad refactoring.
- Preserve the evidence-first, human-review purpose described in `docs/PROJECT_CONTEXT.md`.

## Canonical project records
Before meaningful implementation or planning work, inspect these files in order:
1. `docs/PROJECT_CONTEXT.md` for product intent, current scope, and explicit non-goals.
2. `docs/DECISIONS.md` for recorded decisions and unresolved questions.
3. `docs/ROADMAP.md` for milestone intent and approval state.
4. `docs/WORK_QUEUE.md` for current task candidates and statuses.
5. `docs/RELEASES.md` when discussing versions, packaging, support, or releases.
6. Relevant source code, tests, `README.md`, `docs/OOAD.md`, and `docs/SECURITY.md` to verify implementation claims.

At the start of substantive work, identify the repository, branch, and HEAD SHA from actual Git output. Treat repository code and test output as evidence of implementation; proposals in documentation are not implemented features. If records conflict, state the conflict and seek resolution rather than silently inventing a consensus. Keep canonical records concise and do not duplicate lengthy explanations across files.

## Approval-first policy
- Explain the objective, affected files, risks, and verification plan before implementing a task.
- Do not commit, push, publish, deploy, delete project data, or install dependencies without explicit approval.
- Do not perform destructive Git operations or modify Git history.
- Do not access the network or scan external targets without explicit approval.
- Stop and ask if the task expands beyond the approved scope.
- Never claim an action is approval-gated unless the environment actually enforces that requirement.

## Verification
- After implementing an explicitly approved code change, run `.\scripts\verify.ps1` and report its actual results. If a check fails, investigate and report the failure; never claim success without successful command output.
- Use the repository virtual environment:
  - `.\.venv\Scripts\pytest.exe`
  - `.\.venv\Scripts\ruff.exe check .`
- Run focused tests first, then the full test suite and Ruff when appropriate.
- Report actual command results accurately.
- Distinguish warnings from errors.
- Do not claim tests, security checks, or release validation were performed unless they were actually run and passed.

## Git safety
- Inspect `git status --short` before editing.
- Preserve unrelated user changes and all existing untracked files.
- Review tracked and untracked changes after editing.
- Run `git diff --check`.
- Never commit unless explicitly authorized.
- Report every changed, added, and deleted file.
- Prefer `main` plus one short-lived task branch at a time. Do not create permanent branches for individual assistants or workflow stages without a concrete need. Reuse the current task branch; after a reviewed change is merged, return to current `main` for the next task.

## Security
- Treat VulnScribe as security-sensitive software.
- Use safe, local test fixtures.
- Never expose secrets, credentials, tokens, or sensitive findings in logs or reports.
- Never weaken security checks merely to make tests pass.
- The MVP analyzes authorized supplied artifacts; do not introduce live-target contact, arbitrary repository cloning, uploaded-code execution, or active tests as a side effect of an unrelated task.

## Task execution
- Implement only the approved scope.
- If checks fail, diagnose the issue and propose a minimal fix.
- Finish with a concise summary of changes, verification results, and limitations.
