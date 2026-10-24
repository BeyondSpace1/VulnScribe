# VulnScribe Release Record and Policy

## Current release state

**No actual release is recorded in this file.** The current branch prepares a preview candidate with Python package metadata version `0.2.0a1`, corresponding to the proposed GitHub pre-release label/tag `v0.2.0-alpha.1`. The candidate is not yet verified or published. Do not create a tag, upload an artifact, or declare a release until exact-head tests, linting, package checks, release-note review, and explicit publication approval are complete.

The previous package metadata version `0.1.0` and merge commits were development state, not proof of a published release.

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
