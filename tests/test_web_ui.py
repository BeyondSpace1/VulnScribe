from fastapi.testclient import TestClient

from vulnscribe.api.main import app

client = TestClient(app)


def test_local_web_interface_returns_html_and_security_headers():
    response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "VulnScribe" in response.text
    assert "Source code" in response.text
    assert "HTTP response" in response.text
    assert "Report a bug on GitHub" in response.text
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"


def test_local_web_assets_are_served_from_same_origin():
    css = client.get("/static/app.css")
    js = client.get("/static/app.js")

    assert css.status_code == 200
    assert "text/css" in css.headers["content-type"]
    assert js.status_code == 200
    assert "javascript" in js.headers["content-type"]
    assert "innerHTML" not in js.text


def test_markdown_export_endpoint_preserves_scan_id_and_candidate_wording():
    scanned = client.post(
        "/api/v1/scans/code",
        json={
            "filename": "synthetic.py",
            "language": "python",
            "source": "eval(synthetic_input)\n",
        },
    )
    assert scanned.status_code == 200

    result = scanned.json()
    response = client.post("/api/v1/reports/markdown", json=result)

    assert response.status_code == 200
    assert "text/markdown" in response.headers["content-type"]
    assert result["scan_id"] in response.text
    assert "candidate findings follow" in response.text
    assert "No exploitability or CVSS score is asserted automatically." in response.text or "human validation" in response.text


def test_markdown_export_rejects_malformed_scan_result():
    response = client.post(
        "/api/v1/reports/markdown",
        json={"findings": "not-a-list"},
    )

    assert response.status_code == 422
