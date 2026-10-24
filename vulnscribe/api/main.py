from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from vulnscribe import __version__
from vulnscribe.api.middleware import RequestBodyLimitMiddleware
from vulnscribe.core import ScannerRegistry, code_target, http_target
from vulnscribe.models import CodeScanRequest, HttpScanRequest, ScanResult
from vulnscribe.reporting import to_markdown

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

app = FastAPI(
    title="VulnScribe",
    version=__version__,
    description="Local-first, evidence-first vulnerability analysis preview. "
    "Do not expose publicly without authentication and hardening.",
)

app.add_middleware(
    RequestBodyLimitMiddleware,
    max_body_size=1_048_576,
)
registry = ScannerRegistry()

@app.get("/health")
def health():
    return {"status": "ok", "service": "vulnscribe", "version": __version__}


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def web_ui():
    index = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(
        content=index,
        headers={
            "Content-Security-Policy": (
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'"
            ),
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
        },
    )


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


@app.post("/api/v1/reports/markdown", response_class=PlainTextResponse)
def report_markdown(result: ScanResult):
    """Render a validated scan result without rescanning or changing its scan ID."""
    return PlainTextResponse(to_markdown(result), media_type="text/markdown")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
