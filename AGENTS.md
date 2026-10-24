# VulnScribe Development Workflow

## Project scope
- Work only in this repository unless explicitly authorized otherwise.
- Inspect the existing architecture before making changes.
- Prefer small, testable changes over broad refactoring.

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

## Git safety
- Inspect `git status --short` before editing.
- Preserve unrelated user changes.
- Review tracked and untracked changes after editing.
- Run `git diff --check`.
- Never commit unless explicitly authorized.
- Report every changed, added, and deleted file.

## Security
- Treat VulnScribe as security-sensitive software.
- Use safe, local test fixtures.
- Never expose secrets, credentials, tokens, or sensitive findings in logs or reports.
- Never weaken security checks merely to make tests pass.

## Task execution
- Implement only the approved scope.
- If checks fail, diagnose the issue and propose a minimal fix.
- Finish with a concise summary of changes, verification results, and limitations.
