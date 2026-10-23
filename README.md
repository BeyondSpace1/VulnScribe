# VulnScribe MVP

Evidence-first vulnerability analysis starter: deterministic source-code pattern checks, raw HTTP response header checks, FastAPI endpoints, CLI, JSON/Markdown reports, and tests.

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
Open http://127.0.0.1:8000/docs.

## CLI
```powershell
vulnscribe scan-code .\samples\unsafe_example.php --out report.json
vulnscribe scan-http .\samples\http_response.txt --format markdown --out report.md
pytest
```

## API
- `GET /health`
- `POST /api/v1/scans/code` JSON: `{"filename":"app.php","source":"...","language":"php"}`
- `POST /api/v1/scans/http` JSON: `{"raw_response":"HTTP/1.1 200 OK\\r\\n..."}`

## Important design choices
- Deterministic rules create candidate findings; AI is not required for V1.
- CVSS score/vector remain unset until a verified vector and scoring calculator are implemented.
- OWASP mapping uses 2025 taxonomy where justified.
- This is not a replacement for mature SAST/DAST/SCA tools or manual review.
- Do not expose the development server publicly.

See `docs/OOAD.md` and `docs/SECURITY.md` for design and security details.
