# VulnScribe OOAD — MVP Design

## Vision
A modular analysis platform that converts authorized source artifacts and HTTP exchanges into evidence-backed candidate findings and reproducible reports.

## Actors
- Security analyst: submits inputs, reviews findings, exports reports.
- Developer: reviews evidence and remediation guidance.
- Platform operator: manages deployment, retention, and integrations.
- Scanner adapter: analyzes a supported target and emits normalized findings.

## Use cases
1. Submit source code for static pattern checks.
2. Submit a raw HTTP response for security-header checks.
3. Review findings with evidence and line numbers.
4. Export findings as JSON or Markdown.
5. Extend the scanner registry with a new scanner implementation.

## Domain objects
- `ScanTarget`: input type, filename, source, language, metadata.
- `Finding`: rule ID, severity estimate, confidence, evidence, location, mappings, remediation, references, validation state.
- `ScanResult`: scan ID, timestamp, target metadata, findings, severity summary, limitations.
- `BaseScanner`: abstract `supports()` and `scan()` contract.
- `ScannerRegistry`: selects compatible scanners, deduplicates findings, sorts them, and computes counts.
- `ReportExporter`: serializes the canonical result to supported formats.

## Sequence
1. API/CLI validates input size and metadata.
2. Input is converted to `ScanTarget`.
3. Registry selects compatible scanners.
4. Rules emit candidate findings with rule IDs and evidence.
5. Registry deduplicates findings and computes summary counts.
6. Reporter serializes the same result to Markdown or JSON.
7. Human analyst validates candidates before marking them confirmed.

## Design principles
- Evidence first; AI is optional and non-authoritative.
- Fail closed on unsupported input types.
- Never execute submitted source.
- Keep scanner-specific logic behind a common interface.
- Preserve rule IDs and provenance for reproducibility.
- Never assign CVSS without a validated vector and calculator.
- Treat uploaded content as untrusted data, not as instructions.
