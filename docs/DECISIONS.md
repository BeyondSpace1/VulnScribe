# VulnScribe Decision Log

This file separates documented baseline choices from proposals and unresolved questions. “Documented baseline” means a choice is reflected in current project materials or code; it does not imply a separate approval event unless one is recorded.

## Documented baseline

### D-001 — Evidence-first candidate findings

**Status:** DOCUMENTED BASELINE

**Decision:** Scanner output is a candidate for human review, not proof of exploitability.

**Basis:** `README.md`, `docs/OOAD.md`, and current result/warning behavior.

**Consequence:** Preserve evidence and limitations; do not automatically confirm findings.

### D-002 — Narrow, passive MVP inputs

**Status:** DOCUMENTED BASELINE

**Decision:** Current inputs are authorized source artifacts and supplied raw HTTP responses.

**Basis:** README and current API/CLI/scanner implementation.

**Consequence:** Live-target contact, arbitrary repository cloning, submitted-code execution, and active testing are outside the current MVP.

### D-003 — No automatic CVSS assignment

**Status:** DOCUMENTED BASELINE

**Decision:** CVSS score/vector remain unset unless a validated vector and scoring implementation are introduced.

**Basis:** README, design, and finding model.

**Consequence:** Do not infer a CVSS score from heuristic severity.

### D-004 — AI is optional and non-authoritative

**Status:** DOCUMENTED BASELINE

**Decision:** The current deterministic MVP does not require AI. Any future AI should assist, not override evidence or human validation.

**Basis:** README, OOAD, and security notes.

**Consequence:** AI work remains proposed until the evidence baseline, user value, and security controls are reviewed.

### D-005 — Shared/public deployment requires a separate security gate

**Status:** DOCUMENTED BASELINE

**Decision:** The development MVP must not be represented as hardened for shared/public exposure.

**Basis:** README and `docs/SECURITY.md`.

**Consequence:** Required controls must be implemented and verified for a specified deployment audience before exposure.

## Open decisions

### Q-001 — Original product brief and detailed success criteria

**Status:** OPEN

The canonical context captures the intent supported by the current repository materials. If the original ideation contained additional concrete requirements, incorporate only after locating/reviewing those source notes.

**Decision needed:** Confirm whether any essential product goal is missing; do not fill this gap with assumptions.

### Q-002 — Scanner evaluation and fixture provenance

**Status:** OPEN

The project needs a defensible evaluation set, clear fixture provenance, and criteria for handling credential-shaped examples.

**Decision needed:** Approve the data source, labeling/review method, and acceptable evaluation claims before publishing accuracy numbers.

### Q-003 — Deployment audience

**Status:** OPEN

The intended first deployment audience (local individual use, controlled team, or public service) has not been established in the reviewed baseline.

**Decision needed:** Select the intended audience before choosing deployment architecture and security acceptance gates.

### Q-004 — Release support policy

**Status:** OPEN

The release support window, compatibility promises, and security-fix policy are not established.

**Decision needed:** Define these before V1.0, rather than inventing them now.

### Q-005 — Historic privacy material

**Status:** OPEN

The current `docs/CHATGPT_PROJECT_CONTEXT.md` is a concise project-only handoff after PR #3. Earlier versions may remain in Git history.

**Decision needed:** Decide separately whether history rewriting is warranted after assessing exposure, repository consumers, and disruption. Do not rewrite history without explicit authorization.

## Recording new decisions

Add a dated entry only when the date and decision are known. Each entry should include status, decision/question, rationale/evidence, consequences, and the approving authority where approval occurred. Distinguish PROPOSED from APPROVED; never invent approval dates or consensus.
