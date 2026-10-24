# VulnScribe — Local Preview

> **Preview candidate:** `0.2.0-alpha.1` (Python package version `0.2.0a1`). This is not a published release yet.

Local-first, evidence-first vulnerability analysis preview. Use the browser interface or CLI to scan supported source snippets and supplied raw HTTP responses, review candidate findings, and export JSON/Markdown reports. The current branch is preparing the first `0.2.0-alpha.1` preview candidate; publication follows exact-candidate verification.

**Safety boundary:** this version does not contact live targets, execute uploaded code, clone repositories, or perform active tests. Only analyze artifacts you are authorized to handle. Findings are candidates, not proof of exploitability.

## Requirements
Python 3.11+

## Install (Windows PowerShell)
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
uvicorn vulnscribe.api.main:app --reload
```
Open the local web interface at http://127.0.0.1:8000/ or the API docs at http://127.0.0.1:8000/docs. The server binds to loopback by default; do not expose it publicly.

## Local web interface

The home page provides source and raw HTTP-response scan forms, evidence-backed candidate findings, and JSON/Markdown export. Files selected in the browser are read as text and sent only to the local VulnScribe API. The interface does not upload artifacts to a third-party service or run submitted code.

The **Report a bug** link opens the repository's GitHub Issue Form in a browser. Issues may be public: do not submit source code, secrets, tokens, private reports, or unredacted diagnostics.

## CLI
```powershell
vulnscribe scan-code .\samples\unsafe_example.php --out report.json
vulnscribe scan-http .\samples\http_response.txt --format markdown --out report.md
pytest
```

For HTTP-response scans, pass `--transport-scheme https` only when the captured response is known to have been received over HTTPS. Use `--transport-scheme http` when the transport was HTTP. If omitted, transport is treated as unknown, missing-HSTS findings are suppressed, and the report includes a warning. The scheme is supplied capture metadata; VulnScribe does not infer it from the raw response or contact the target.

## API
- `GET /health`
- `POST /api/v1/scans/code` JSON: `{"filename":"app.php","source":"...","language":"php"}`
- `POST /api/v1/scans/http` JSON: `{"raw_response":"HTTP/1.1 200 OK\\r\\n...","transport_scheme":"https"}` (`transport_scheme` is optional; only use `https` when known from capture context)

## Preview limitations
- This is a local preview, not a stable or production-hardened release.
- Findings are deterministic candidates, not confirmed vulnerabilities or proof of exploitability.
- No source is executed, no live target is contacted, and no AI analysis is performed.
- The HSTS check requires an explicit transport scheme; unknown transport suppresses the missing-HSTS candidate and reports a warning.
- Scanner precision/recall has not been established by the synthetic regression suite.

## Important design choices
- Deterministic rules create candidate findings; AI is not required for V1.
- CVSS score/vector remain unset until a verified vector and scoring calculator are implemented.
- OWASP mapping uses 2025 taxonomy where justified.
- This is not a replacement for mature SAST/DAST/SCA tools or manual review.
- Do not expose the development server publicly.

See `docs/OOAD.md` and `docs/SECURITY.md` for design and security details.
