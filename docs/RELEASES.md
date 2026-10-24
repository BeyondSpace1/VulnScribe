# VulnScribe Release Record and Policy

## Current release state

**No actual release is recorded in this file.** The reviewed repository baseline has package metadata version `0.1.0` in `pyproject.toml`; that metadata is not proof of a published release. The merge commit that established the MVP baseline is also not a release by itself. Git tags/releases were not verified as part of this documentation review, so their existence must not be inferred from this statement.

## Proposed release policy

The following policy is **PROPOSED**, not yet an approved support commitment:

- Use Semantic Versioning for actual releases once public compatibility guarantees are defined.
- Increment patch for compatible fixes, minor for backward-compatible capabilities, and major for incompatible public-interface changes.
- Record each release with its exact source commit, version/tag, summary, verification evidence, known limitations, artifact provenance, and security notes where relevant.
- A version string, commit, PR, roadmap milestone, or successful test run is not by itself a release.
- Do not create release tags or publish artifacts without explicit approval and release-specific verification.

Before V1.0, define supported interfaces, compatibility guarantees, support window, security-fix policy, build provenance, and rollback/recovery expectations.

## Release record template

For each actual release, record:

- Version and release date.
- Immutable source commit and tag.
- User-visible changes and compatibility/migration notes.
- Commands and checks run, with actual results.
- Artifact names and provenance, if artifacts are distributed.
- Known issues, unsupported inputs, and security limitations.
- Approver and publication reference.

Until a release is explicitly made and verified, keep this record empty of release entries.
