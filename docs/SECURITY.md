# Security Model and Threat Notes

All source text, filenames, HTTP exchanges, repository contents, and future scanner outputs are untrusted. A future AI analyzer must treat embedded instructions as data, not instructions.

## Required before shared/public deployment
- Authentication and role-based authorization.
- Input limits, rate limits, secure CORS, and CSRF protections where cookie authentication is used.
- Isolated workers with no ambient credentials and resource quotas.
- Upload validation, path traversal protection, generated storage names, retention limits, and secret redaction.
- SSRF controls for future URL fetching: validate every redirect and resolved IP; block loopback, private, link-local, multicast, and metadata endpoints; enforce egress filtering.
- Explicit authorization and scope records for all active tests.
- Audit events for scans, exports, configuration changes, and active test launches.
- Dependency/container scanning, reproducible builds, pinned dependencies, and secret scanning.
- Never expose the development server publicly.

## Reporting discipline
Severity is an estimate based on rule metadata. Confidence is separate from severity. A finding is not confirmed until reviewed. CVSS is not assigned automatically in this MVP. Do not claim exploitation from static pattern matches.
