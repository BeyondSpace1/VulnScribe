# ChatGPT Project Context — VulnScribe

**Purpose:** Durable handoff context for ChatGPT and Codex.  
**Status:** Draft for user review; not yet reconciled against the complete local working tree.  
**Last updated:** 2026-10-23

## 1. Why this file exists

The user wants ChatGPT and Codex to work from a common, durable project context rather than requiring the user to relay instructions and summaries between separate sessions.

This file records the project context currently available to ChatGPT. It is a handoff document, not proof that GitHub contains the latest local source. The user must review it and approve, reject, or suggest changes before it becomes authoritative.

## 2. Project purpose

VulnScribe is a vulnerability-analysis MVP intended to produce evidence-first candidate findings from authorized source artifacts and raw HTTP responses, for human review.

Core principles:
- Findings are candidates for review, not proof of exploitability.
- Ground findings in observable evidence and explain the reasoning.
- Do not assign automatic CVSS scores without a defensible basis.
- Prefer deterministic, reproducible analysis.
- Handle untrusted inputs safely and avoid exposing secrets.
- Keep the human reviewer in control.

## 3. Architecture and capabilities (historical context; verify locally)

The previously described implementation uses Python 3.11+ and has included:
- vulnscribe/models.py
- vulnscribe/core.py
- vulnscribe/scanners/
- vulnscribe/api/
- vulnscribe/cli/
- vulnscribe/reporting.py
- tests, a FastAPI API, a CLI, JSON/Markdown reports, optional PDF output, and Docker support.

Previously described source-code checks cover PHP, Python, JavaScript/TypeScript, and Go. HTTP response-header checks are also in scope.

**Important:** These details come from earlier project context and have not been verified against the current GitHub branch or current local checkout. Reconcile them with the real files before relying on them.

## 4. Safety boundaries

Default behavior should be passive and evidence-first:
- Analyze only artifacts and targets the user is authorized to assess.
- Do not execute analyzed source code.
- Do not contact live targets or perform active testing by default.
- Do not clone arbitrary repositories or run active checks without explicit approval.
- Treat input artifacts and findings as untrusted data.
- Do not install or upgrade dependencies, access the network, change permissions, stage, commit, push, deploy, or perform destructive Git operations unless explicitly authorized.
- Before public or shared deployment, review authentication/authorization, rate limits, resource controls, security documentation, and exposure of sensitive data.

## 5. Known local-workspace context (reported, not independently verified here)

The user reported a Windows working tree at:

    F:\Projects\vulnscribe-mvp\vulnscribe

The reported branch and baseline at the time of the earlier context were:
- Branch: master
- Last recorded commit: 4c8b5d3 Initial VulnScribe MVP baseline

These may have changed. Always inspect the current branch, commit, and status before acting.

Six files were previously reported as untracked:
- .codex/AGENTS.md
- AGENTS.md
- docs/AI_CONTEXT.md
- scripts/verify.ps1
- tests/fixtures/scanner_accuracy.json
- tests/test_scanner_accuracy.py

Later, three operating records were reported as added:
- docs/DECISIONS.md
- docs/PROJECT_OPERATING_MODEL.md
- docs/WORK_QUEUE.md

A previous report said the final local Git status listed nine untracked files. This status is historical and must be checked again before any changes. Preserve existing user work; do not assume untracked files are disposable.

## 6. Verification and the unresolved instruction-file issue

The intended verification rule is to run the PowerShell command:

    .\scripts\verify.ps1

after implementing an explicitly approved code change, then report actual results. If a check fails, investigate and report the failure; never claim success without successful command output.

A previous recovery report stated:
- AGENTS.md was corrected by removing one extra space from the inline verification command and was byte-compared with its backup.
- .codex/AGENTS.md was byte-identical to its backup and still lacked the rule.
- Attempts to write .codex/AGENTS.md failed because the available local sandbox denied writes to that path.
- No permissions were changed and no alternate write method was attempted.
- The documentation-only work did not run the full verification suite.
- A historical earlier verification run reported 45 tests passed and Ruff passed, but that result was not rerun after the later documentation changes.

All of these are historical reports, not current verification. Check actual files and command output before asserting current state.

## 7. Shared operating model

### Roles
- **User:** Product owner and final approver for consequential decisions.
- **Codex:** Local implementation agent. Inspects the working tree, makes scoped changes, runs permitted checks, and updates project records.
- **ChatGPT:** Planning, review, reasoning, research when requested, and independent critique based on the repository records and any files actually accessible in the current session.

### Task lifecycle
1. Read the project context, operating model, decision log, work queue, and relevant instructions before starting.
2. Inspect current Git status and relevant files; preserve existing user work.
3. State the intended scope and acceptance criteria in the work queue or task record.
4. Implement only within the approved scope.
5. Run the checks required by project instructions and report actual output.
6. Update context, decisions, and work queue to reflect what actually happened.
7. Report exact files changed, checks performed, results, blockers, and any approval needed.

### Autonomy and approvals
Routine read-only inspection, planning, and in-scope documentation maintenance can proceed autonomously when already authorized.

Pause for user approval before:
- Expanding the task scope materially.
- Destructive or irreversible changes.
- Dependency installation or upgrades.
- Network access, external target testing, or actions that could affect third parties.
- Permission/security-control changes.
- Material security, architecture, product, or privacy decisions with meaningful trade-offs.
- Staging, committing, pushing, merging, deploying, or publishing changes unless the user has explicitly authorized that specific action or workflow.

If an unexpected failure or permission barrier occurs, stop that action, preserve evidence, and report it. Do not improvise a workaround that changes the risk or scope.

## 8. Disagreements and decision records

Keep three categories distinct:
- **Accepted decisions:** Explicitly approved and recorded with rationale.
- **Proposals:** Suggested changes awaiting review; not yet authoritative.
- **Disagreements / unresolved questions:** Record each position, evidence, trade-offs, and the decision needed from the user. Do not silently reconcile conflicting instructions.

The user can respond with:
- **APPROVE:** accept the specified proposal.
- **REJECT:** do not apply it; record the reason if supplied.
- **AMEND:** revise the proposal according to the user's notes.
- **CONTINUE:** proceed with the next already-approved task.
- **HOLD:** pause work on the specified issue.

Codex should update docs/DECISIONS.md and docs/WORK_QUEUE.md when those files exist locally and the change is within the authorized scope.

## 9. GitHub sharing limitations

This file was created to establish a shared handoff point. Repository records can provide common durable context, but they do not automatically synchronize private conversation history or every local uncommitted edit.

Before treating this file as the canonical project context:
1. The user reviews and approves/amends it.
2. The local checkout is reconciled with the intended GitHub branch.
3. The existing local untracked files are reviewed and preserved.
4. The local operating documents are reconciled with this file so there is one clear source of truth.
5. Any private data, credentials, tokens, local configuration, and sensitive scan artifacts are excluded from publication.

## 10. Immediate next steps

1. User reviews this context file and approves, rejects, or requests amendments.
2. Inspect the local checkout's current Git status and compare local project files with GitHub.
3. Reconcile the operating records without overwriting or discarding existing local work.
4. Resolve the .codex/AGENTS.md verification-rule blocker through a user-approved, safe method.
5. Continue the highest-priority task from the verified work queue only after context and status are reconciled.

---

**Authority note:** Until the user approves this draft and it is reconciled with the local working tree, this document is a proposal and handoff snapshot—not a replacement for verified source code, local instructions, or explicit user decisions.
