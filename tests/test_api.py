
from fastapi.testclient import TestClient

from vulnscribe.api.main import app

client = TestClient(app)


def test_health_endpoint_returns_service_metadata():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "vulnscribe",
        "version": "0.1.0",
    }


def test_code_endpoint_detects_eval():
    response = client.post(
        "/api/v1/scans/code",
        json={
            "filename": "api_test.py",
            "language": "python",
            "source": "eval(user_input)\n",
        },
    )

    assert response.status_code == 200
    data = response.json()

    assert data["target"]["filename"] == "api_test.py"
    assert any(
        finding["rule_id"] == "VS-PY-001"
        for finding in data["findings"]
    )
    assert data["summary"]["HIGH"] >= 1
    assert any("human validation" in warning for warning in data["warnings"])


def test_http_endpoint_detects_missing_security_headers():
    response = client.post(
        "/api/v1/scans/http",
        json={
            "target_label": "api-http-test",
            "raw_response": (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                "\r\n"
                "<html><body>OK</body></html>"
            ),
        },
    )

    assert response.status_code == 200
    data = response.json()

    rule_ids = {finding["rule_id"] for finding in data["findings"]}

    assert "VS-HTTP-CONTENTSECURITYPOLICY" in rule_ids
    assert "VS-HTTP-XCONTENTTYPEOPTIONS" in rule_ids
    assert data["target"]["type"] == "http_response"


def test_http_endpoint_recognizes_present_security_headers():
    response = client.post(
        "/api/v1/scans/http",
        json={
            "target_label": "api-secure-headers-test",
            "raw_response": (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                "Content-Security-Policy: default-src 'self'\r\n"
                "X-Content-Type-Options: nosniff\r\n"
                "Strict-Transport-Security: max-age=31536000\r\n"
                "Referrer-Policy: strict-origin-when-cross-origin\r\n"
                "Permissions-Policy: camera=(), microphone=()\r\n"
                "\r\n"
                "<html><body>OK</body></html>"
            ),
        },
    )

    assert response.status_code == 200
    data = response.json()

    missing_header_rules = {
        "VS-HTTP-CONTENTSECURITYPOLICY",
        "VS-HTTP-XCONTENTTYPEOPTIONS",
        "VS-HTTP-STRICTTRANSPORTSECURITY",
        "VS-HTTP-REFERRERPOLICY",
        "VS-HTTP-PERMISSIONSPOLICY",
    }
    reported_rules = {finding["rule_id"] for finding in data["findings"]}

    assert reported_rules.isdisjoint(missing_header_rules)


def test_code_endpoint_returns_markdown():
    response = client.post(
        "/api/v1/scans/code?format=markdown",
        json={
            "filename": "markdown_test.py",
            "language": "python",
            "source": "eval(user_input)\n",
        },
    )

    assert response.status_code == 200
    assert "text/markdown" in response.headers["content-type"]
    assert "# VulnScribe Security Analysis Report" in response.text
    assert "VS-PY-001" in response.text


def test_markdown_report_escapes_untrusted_filename_markup():
    response = client.post(
        "/api/v1/scans/code?format=markdown",
        json={
            "filename": "[click](javascript:alert(1)).py",
            "language": "python",
            "source": "eval(user_input)\n",
        },
    )

    assert response.status_code == 200
    assert r"\[click\]\(javascript:alert\(1\)\).py" in response.text


def test_code_endpoint_rejects_unsupported_format():
    response = client.post(
        "/api/v1/scans/code?format=xml",
        json={
            "filename": "format_test.py",
            "language": "python",
            "source": "value = 42\n",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "format must be json or markdown"


def test_http_endpoint_rejects_unsupported_format():
    response = client.post(
        "/api/v1/scans/http?format=xml",
        json={
            "target_label": "format-test",
            "raw_response": "HTTP/1.1 200 OK\r\n\r\n",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "format must be json or markdown"


def test_code_endpoint_rejects_missing_required_fields():
    response = client.post(
        "/api/v1/scans/code",
        json={},
    )

    assert response.status_code == 422


def test_http_endpoint_rejects_missing_required_fields():
    response = client.post(
        "/api/v1/scans/http",
        json={},
    )

    assert response.status_code == 422

def test_code_endpoint_rejects_oversized_request_body():
    oversized_source = "x" * (1_048_576 + 1)

    response = client.post(
        "/api/v1/scans/code",
        json={"source": oversized_source},
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "Request body too large"

def test_code_endpoint_accepts_request_within_body_limit():
    response = client.post(
        "/api/v1/scans/code",
        json={
            "filename": "small_test.py",
            "language": "python",
            "source": "value = 42\n",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["target"]["filename"] == "small_test.py"
    assert isinstance(data["findings"], list)


def test_code_endpoint_rejects_whitespace_only_source():
    response = client.post(
        "/api/v1/scans/code",
        json={
            "filename": "blank.py",
            "language": "python",
            "source": "   \n\t ",
        },
    )

    assert response.status_code == 422


def test_http_endpoint_rejects_whitespace_only_response():
    response = client.post(
        "/api/v1/scans/http",
        json={
            "target_label": "blank-response",
            "raw_response": "   \n\t ",
        },
    )

    assert response.status_code == 422

def test_code_endpoint_rejects_invalid_content_length():
    response = client.post(
        "/api/v1/scans/code",
        content=b'{"source": "value = 42"}',
        headers={
            "Content-Type": "application/json",
            "Content-Length": "invalid",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid Content-Length header"

def test_code_endpoint_rejects_duplicate_content_length():
    response = client.post(
        "/api/v1/scans/code",
        content=b'{"source": "value = 42"}',
        headers=[
            ("Content-Type", "application/json"),
            ("Content-Length", "22"),
            ("Content-Length", "22"),
        ],
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid Content-Length header"
