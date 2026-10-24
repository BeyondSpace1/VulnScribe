# VulnScribe Roadmap

All milestones below are **PROPOSED** unless explicitly approved in the decision log. They are outcome gates, not delivery dates, commitments, or declarations of implemented features. Advancement requires evidence from review and verification.

## V0.1 — Reliable MVP baseline (PROPOSED)

**Intent:** make the current narrow MVP reproducible and verifiable before expanding scope.

- Verify the merged baseline with actual API tests, scanner-focused tests, and Ruff.
- Define a safe, provenance-reviewed scanner evaluation fixture set.
- Cover positive detections, important non-detections, malformed inputs, line/evidence handling, and report escaping.
- Record known coverage gaps and expected false-positive/false-negative behavior.
- Confirm that API, CLI, and report outputs communicate candidate status and limitations consistently.

**Exit evidence:** test output tied to an exact commit; documented scanner coverage and limitations; reviewed regression fixtures. A passing linter alone is not sufficient.

## V0.2 — Trustworthy analysis (PROPOSED)

**Intent:** improve evidence quality and calibrate detection behavior.

- Define a transparent rule metadata and evidence contract.
- Measure precision/recall on reviewed, authorized fixtures where a defensible ground truth exists.
- Track false positives and false negatives rather than optimizing only for more findings.
- Make scanner behavior, language support, unsupported syntax, and limitations visible to users.
- Preserve deterministic behavior where practical and test regression changes.

**Exit evidence:** a repeatable evaluation method, reviewed results, and explicit known limitations. Do not present unmeasured accuracy claims.

## V0.3 — Extensible scanner platform (PROPOSED)

**Intent:** make adding and maintaining scanners safe and consistent.

- Formalize the scanner registration contract and normalized result schema.
- Specify rule identifiers, versioning, evidence provenance, deduplication, and error handling.
- Add a new scanner only when the feature serves a documented user need and has tests/fixtures.
- Keep input adapters and report formats separate from detection logic.

**Exit evidence:** a documented extension contract with compatibility and regression tests.

## V0.4 — Optional AI-assisted review (PROPOSED)

**Intent:** assist human interpretation without making AI the source of truth.

- Only consider after deterministic evidence quality and evaluation practices are established.
- Use AI for bounded explanation, evidence summarization, or review prioritization, if user value is demonstrated.
- Treat model output and embedded instructions in artifacts as untrusted.
- Clearly label model-generated hypotheses; preserve deterministic evidence and human validation.
- Never fabricate evidence or automatically confirm findings or assign CVSS.

**Exit evidence:** an explicit threat model, evaluation of groundedness and failure modes, clear controls, and an opt-in design. AI is not a prerequisite for the MVP.

## V0.5 — Controlled shared deployment (PROPOSED)

**Intent:** assess and implement controls required before multi-user or public exposure.

- Authentication, authorization, and secure configuration.
- Input, rate, time, memory, and storage limits.
- Isolation and least privilege for processing untrusted inputs.
- Auditability, retention, deletion, and secret-redaction policies.
- Dependency/container review, reproducible builds, and operational monitoring.
- Documented deployment model and incident/recovery practices.

**Exit evidence:** reviewed threat model, verified control implementation, deployment tests, and explicit approval for the intended audience. A local development server is not a shared deployment.

## V1.0 — Stable supported release (PROPOSED)

**Intent:** make the product's supported behavior and compatibility expectations explicit.

- Stable public interfaces and output schema policy.
- Documented supported inputs, limitations, installation, configuration, and safe operation.
- Reproducible test/build process and release artifact provenance.
- Versioning, compatibility, security-fix, and support policies.
- Reviewed release notes and acceptance evidence.

**Exit evidence:** owner-approved release criteria, complete verification records, and an actual release artifact. A package version string or merge commit alone does not constitute a release.

## Roadmap governance

- Product owner approval is required before a milestone or material scope expansion becomes committed work.
- Update statuses only when the work queue/decision record and actual evidence support the change.
- Preserve the current MVP safety boundaries unless a separate, explicit design and security approval changes them.
