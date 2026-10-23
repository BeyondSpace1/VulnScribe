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


## 11. Expanded conversation history and project intent

This section captures the broader conversation context available to ChatGPT. It is intentionally explicit about what is a user goal, what is historical reporting, and what remains unverified. It is not a verbatim transcript of every chat message; the original chat remains the source for exact wording.

### 11.1 The user's core workflow problem

The user objected to repeatedly acting as a courier between ChatGPT and Codex: ChatGPT gives instructions, the user pastes them into Codex, Codex returns a report, and the user pastes the report back. The user wants:
- One durable project context accessible to both assistants.
- Codex to work locally and carry out approved project tasks end-to-end.
- ChatGPT to review, steer, challenge assumptions, and help plan from the same current records.
- Decisions and disagreements recorded separately rather than silently resolved.
- A clear approval/decline/suggest-changes workflow.
- Less repetitive manual handoff, while retaining user control over consequential actions.

The intended operating principle is: **autonomy within a clearly approved scope; explicit approval at consequential boundaries; transparent records of evidence and actual results.**

Do not promise real-time synchronization merely because GitHub is connected. A shared repository is durable shared state; private conversation histories and local uncommitted edits do not automatically sync. ChatGPT should use the GitHub connector when available and state exactly which branch/files it could read. Codex should read and update local repository records. If GitHub and local state disagree, treat that as a reconciliation task rather than assuming either is current.

### 11.2 Review protocol the user wants

The intended loop is:
1. ChatGPT proposes or records a concrete plan/context update.
2. The proposal is written to the repository in a reviewable form.
3. The user reviews locally and responds with approval, rejection, or suggested changes.
4. ChatGPT/Codex proceeds only within the approved scope.
5. Work results, test evidence, changed files, and unresolved issues are written back to the repository.
6. The next assistant reads the latest shared records before proceeding.

Use concise explicit review statuses, such as **PROPOSED**, **APPROVED**, **REJECTED**, **AMENDED**, **BLOCKED**, and **DONE**. A proposal must not be described as an accepted decision until the user approves it. Record disagreements with each position, evidence, trade-offs, and the specific question requiring user decision.

### 11.3 Reverse-engineering experiment context (related learning interest, not automatically VulnScribe scope)

The user previously explored a project/repository called REA at https://github.com/morluto/rea and asked what the hype was about and whether they could reverse engineer “anything.” They wanted an ambitious, practical reverse-engineering experiment on Windows to explore multiple target types, rebuild features, or create an alternative, with a coding agent possibly assisting.

The user explicitly wanted:
- A concrete Windows setup.
- Suitable tools and exact commands.
- A safe target.
- A testable success criterion.
- An end-to-end experiment, not only theory.
- Ways to minimize legal risk, system damage, or compromised/shadow-hijacked systems.

Important boundaries from that discussion:
- Reverse engineering is not permission to bypass access controls, violate licenses, access private data, or test systems without authorization.
- Prefer a self-authored toy program, open-source project with a compatible license, or intentionally vulnerable local lab artifact whose use is authorized.
- Begin with static inspection and controlled, offline experiments; do not run unknown binaries with elevated privileges.
- Keep original artifacts and hashes, use backups, and record reproducible steps.
- Do not expand this exploratory REA work into VulnScribe implementation unless the user explicitly makes that connection.

### 11.4 User's computing constraints relevant to local experiments

Previously reported environment:
- Windows 10 was mentioned in the reverse-engineering discussion; Windows 11 was mentioned elsewhere. Confirm the currently active OS before giving OS-specific commands.
- Linux Mint is installed as a dual boot alongside Windows.
- A Linux subsystem/WSL-like environment was noticed on Windows, but its exact configuration was not established in the available conversation.
- The user reported 8 GB RAM and 128 GB SSD space available. Windows reportedly consumed roughly 40–55% of RAM, leaving limited headroom for a virtual machine.
- An earlier hardware report mentioned an NVIDIA RTX 3050 with 6 GB VRAM; another laptop model detail was HP-15_di2001tx / HP-15-di2xx, with Intel UHD 620 and NVIDIA MX110 mentioned in an earlier context. These hardware descriptions may refer to different machines or may conflict; verify before relying on them.
- The user has asked whether Linux Mint or the existing subsystem would be better than a VM. The practical constraint is to avoid recommending a heavy VM by default; a native Linux dual boot or a lightweight existing subsystem may be more practical, depending on the target tools and current setup.
- Do not assume virtualization, WSL version, GPU availability, free disk capacity, or exact OS version without current evidence.

These hardware notes are personal environment context, not a VulnScribe requirement. Use only when the current task concerns local tooling or reverse engineering.

### 11.5 Safety and reliability priorities

The user raised concerns about:
- Lawsuit/legal exposure.
- Damaging or compromising the host computer.
- Shadow-hijacked or malicious environments.
- Running a virtual machine with insufficient RAM.
- Whether an experiment can be made safe and its outcome tested.

For security-related work, explain the trust boundary and side effects before commands that execute code, access networks, alter permissions, install packages, or modify boot/system configuration. Prefer low-risk, reversible, offline operations. Ask for approval before materially increasing risk. Do not imply that a sandbox, VM, WSL, or dual boot guarantees safety.

### 11.6 VulnScribe product direction and security posture

The current product context is an evidence-first vulnerability-analysis MVP. The user values practical implementation and a complete, testable workflow rather than unsupported claims. The system should help reviewers understand why a candidate finding was emitted and what evidence supports it.

The following are intended guardrails, not claims that every one is implemented:
- Separate detection logic, data models, API/CLI interfaces, and report generation.
- Preserve source evidence and make outputs reproducible.
- Avoid treating heuristic matches as confirmed vulnerabilities.
- Do not automatically execute source artifacts or probe live targets.
- Keep secrets out of reports, logs, fixtures, and Git history.
- Validate and bound untrusted input sizes and resource consumption.
- Review authentication, authorization, rate limits, resource limits, and security documentation before shared/public deployment.

Do not infer product requirements from the user's unrelated projects or interests. Add new VulnScribe features only when supported by the current work queue or an explicit user request.

### 11.7 Repository and GitHub state observed in this conversation

The GitHub integration was successfully used to list repositories and identify:
- Repository: BeyondSpace1/VulnScribe
- Owner: BeyondSpace1
- Default branch reported by GitHub: main
- Visibility: public
- The repository was reported by GitHub as empty before the context file was created.
- ChatGPT then created docs/CHATGPT_PROJECT_CONTEXT.md directly through the GitHub contents API, with commit SHA fc363f9629a80e4fc675dc190067b8d97106a916.
- ChatGPT fetched the file back from main and verified that the content was readable.

The repository's local checkout was historically reported to use branch master and commit 4c8b5d3. This is not necessarily inconsistent with GitHub's main branch; it means the local checkout and remote may be separate or unsynchronized. Do not assume they are aligned. Confirm the remotes, branches, commit ancestry, and status before merging or pushing.

**Do not push the local working tree wholesale merely to synchronize it.** First inspect and compare files, branches, untracked files, and secrets. The user has specifically emphasized preserving six pre-existing untracked files and later reported three new operating records. These need local inspection before any bulk publishing.

### 11.8 Exact reported instruction-file recovery sequence

The user approved a narrowly scoped edit to two local files:
- In root AGENTS.md, correct one extra space inside the inline verification command.
- In .codex/AGENTS.md, add the same verification rule directly below the Verification heading.

The requested process included immediate preflight checks, refusing to write if assumptions did not match, non-overwriting byte-preserving backups outside the repository, minimal encoding/line-ending-preserving edits, post-edit readback, byte/diff comparison against backups, and a final git status. The user explicitly prohibited unrelated edits, staging, commits, dependency installs, network access, and full test runs for this documentation-only task.

The reported outcome:
- Preflight passed.
- Backups were created and byte-verified:
  - C:\Users\ksoj1\AppData\Local\Temp\VulnScribe-AGENTS.md.pre-verify-rule.bak
  - C:\Users\ksoj1\AppData\Local\Temp\VulnScribe-codex-AGENTS.md.pre-verify-rule.bak
- Root AGENTS.md was changed, and a later byte comparison reportedly showed only the authorized whitespace correction.
- The write to .codex/AGENTS.md failed with access denied; no alternate write method or permission change was attempted.
- A later read-only inspection reportedly confirmed .codex/AGENTS.md remained byte-identical to its backup.
- The earlier patch helper had also reported a reparse-point-related error even though PowerShell metadata did not show a reparse point. That error remains unexplained.
- The setup work added docs/PROJECT_OPERATING_MODEL.md, docs/DECISIONS.md, and docs/WORK_QUEUE.md and refreshed docs/AI_CONTEXT.md.
- The reported final local status listed nine untracked files, preserving the original six plus three new operating records.
- git diff --check returned exit code 0, but because the files were untracked, this alone did not validate their full content.
- The verification suite was intentionally not run for the documentation-only change.
- An older run, before later documentation updates, reported 45 tests passed and Ruff passed. This is historical evidence only.

Do not try to write .codex/AGENTS.md through another method, change permissions, or restore a backup without a fresh, explicit scope/authorization and inspection of the current local state. The current GitHub connector can read and write GitHub files, but it cannot directly alter the user's local Windows working tree.

### 11.9 User expectations for assistant behavior

- Be direct and technically precise; do not make the user repeatedly ferry routine summaries.
- Do not claim access to local files or tools that are not actually available.
- Prefer reading the shared repository context before asking the user to repeat information.
- Keep a clear distinction between observed facts, historical reports, assumptions, recommendations, and unverified state.
- Give commands that are appropriate for the user's real environment and constraints.
- For multi-step work, execute the steps that are already approved instead of repeatedly asking permission for routine substeps.
- Stop only at real approval boundaries, unexpected failures, or material risk changes.
- Report exact changed files, actual verification output, blockers, and next actions.
- Never claim a test, comparison, or write succeeded unless the corresponding tool output confirms it.

## 12. Context maintenance policy

When new reliable project information arrives:
1. Update the relevant section rather than repeatedly appending duplicate summaries.
2. Include an "as of" date for mutable state.
3. Distinguish facts confirmed from repository/tool output from user-reported history.
4. Link or reference the relevant decision/work item when practical.
5. Do not put credentials, private tokens, sensitive personal information, or scan secrets in this file.
6. Keep this document useful as a project handoff; do not treat it as a verbatim transcript or a substitute for code, tests, issue history, or explicit decisions.
