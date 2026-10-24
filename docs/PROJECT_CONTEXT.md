# VulnScribe — Canonical Project Context

**Purpose of this file:** preserve the product's intent and make project context usable by both human contributors and coding assistants without relying on private chat history.

**Implementation baseline reviewed:** `ea3bf18a914392b08fa6fb4cbec228a68ca16a09` (merged repository `main` state before this documentation branch). Re-check the repository and this reference when implementation changes.

## Product intent

VulnScribe is intended to be a modular, evidence-first vulnerability-analysis platform. It helps a developer or security reviewer examine authorized artifacts, understand why a rule emitted a candidate finding, and review that evidence in a reproducible report. The product should support sound human security judgment, not replace it with confident-looking but unsubstantiated conclusions.

The governing product promise is: **make candidate security findings understandable, evidence-backed, and honest about uncertainty.**

This document captures the intent supported by the repository's README, OOAD, security notes, and current implementation. It is not a transcript of every original ideation discussion. If a more specific original requirement is not represented here or in the decision log, record it as an open question rather than inventing a requirement.

## Current implemented MVP scope

The reviewed baseline provides:
- Deterministic pattern checks for supported PHP, Python, JavaScript/TypeScript, and Go source inputs.
- Security-header checks against a user-supplied raw HTTP response.
- FastAPI endpoints and a CLI for those input types.
- JSON and Markdown report output.
- Candidate findings with rule metadata, evidence, remediation guidance, and human-review warnings.

These claims describe the inspected repository baseline, not a guarantee of accuracy or production readiness. The tests and rule coverage still require systematic verification. Check code and tests before asserting that specific behavior remains current.

## Non-negotiable principles

1. **Evidence first:** findings must point to the rule and input evidence that caused them. Preserve provenance where the design supports it.
2. **Candidates, not verdicts:** a pattern match is not proof of exploitability. Human validation remains necessary.
3. **Be explicit about uncertainty:** severity estimates, confidence, and validation state are distinct. Do not assign CVSS automatically without a validated vector and scoring implementation.
4. **Reproducibility:** rule changes and results should be testable with safe, documented fixtures and known limitations.
5. **Modularity:** scanners, normalized findings, interfaces, and report generation should remain separable as the product evolves.
6. **Safety and authorization:** analyze only artifacts the operator is authorized to handle. Treat all supplied content as untrusted data.
7. **Honest capability claims:** label proposals and future work as such; do not describe roadmap ideas as implemented functionality.

## Current safety boundaries and non-goals

The reviewed MVP does not contact live targets, execute submitted source, clone arbitrary repositories, or perform active tests. Do not add these capabilities implicitly. Any future expansion that can affect external systems requires explicit product approval, scope/authorization controls, threat modeling, and a separate security review.

AI is not required for the current deterministic MVP. Any future AI assistance must be optional and non-authoritative: it may explain or prioritize evidence, but must not override deterministic evidence, manufacture proof, or silently promote a candidate to a confirmed vulnerability.

Shared/public deployment is not established as safe. See `docs/SECURITY.md` for required controls; that list is not evidence that the controls already exist.

## Success criteria for the product

These are outcome criteria to guide evaluation, not claims that the baseline already meets them:
- Every emitted finding can be traced to a rule and input evidence.
- Findings have a consistent schema and clearly communicate severity estimate, confidence, and review status.
- Supported inputs produce stable, testable outcomes across regression fixtures.
- Tests measure both expected detections and important non-detections/false positives.
- Reports preserve evidence and limitations without unsafe rendering or accidental secret disclosure.
- Users can understand what the tool checked, what it did not check, and what requires human follow-up.

## How to decide whether work belongs

Before adding a feature, answer:
1. Which user problem tied to the product intent does it solve?
2. What evidence or measurable acceptance criterion will show that it works?
3. Does it preserve the safety boundaries and honest uncertainty?
4. Can it be built and verified without broad, unrelated changes?

If these questions cannot be answered, keep the idea proposed or defer it. Technical novelty alone is not a product requirement.

## Shared source of truth

- `AGENTS.md`: contributor/agent operating rules.
- `docs/DECISIONS.md`: decisions and unresolved questions.
- `docs/ROADMAP.md`: milestone proposals and approval state.
- `docs/WORK_QUEUE.md`: actionable tasks and their status.
- `docs/RELEASES.md`: actual release records and release policy.
- `README.md`, `docs/OOAD.md`, `docs/SECURITY.md`, source code, and tests: user-facing usage, architecture, security requirements, and implementation evidence.

When sources disagree, report the exact discrepancy. Implementation and test evidence determine what currently works; product intent determines whether it is the right thing to build.
