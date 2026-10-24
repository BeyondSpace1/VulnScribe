from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse

from vulnscribe.api.middleware import RequestBodyLimitMiddleware
from vulnscribe.core import ScannerRegistry, code_target, http_target
from vulnscribe.models import CodeScanRequest, HttpScanRequest
from vulnscribe.reporting import to_markdown

app = FastAPI(title="VulnScribe API", version="0.1.0",
              description="Evidence-first MVP. Do not expose publicly without authentication and hardening.")

app.add_middleware(
    RequestBodyLimitMiddleware,
    max_body_size=1_048_576,
)
registry = ScannerRegistry()

@app.get("/health")
def health():
    return {"status": "ok", "service": "vulnscribe", "version": "0.1.0"}


@app.post("/api/v1/scans/code")
def scan_code(request: CodeScanRequest, format: str = "json"):
    result = registry.run(code_target(request.filename, request.source, request.language))
    if format == "markdown":
        return PlainTextResponse(to_markdown(result), media_type="text/markdown")
    if format != "json":
        raise HTTPException(status_code=400, detail="format must be json or markdown")
    return result


@app.post("/api/v1/scans/http")
def scan_http(request: HttpScanRequest, format: str = "json"):
    result = registry.run(
        http_target(
            request.target_label,
            request.raw_response,
            request.transport_scheme,
        )
    )
    if format == "markdown":
        return PlainTextResponse(to_markdown(result), media_type="text/markdown")
    if format != "json":
        raise HTTPException(status_code=400, detail="format must be json or markdown")
    return result
