import json

from typer.testing import CliRunner

from vulnscribe.cli.main import app

runner = CliRunner()


def test_scan_http_without_transport_context_warns_and_skips_hsts(tmp_path):
    response_path = tmp_path / "synthetic-response.txt"
    response_path.write_text(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n",
        encoding="utf-8",
    )
    report_path = tmp_path / "report.json"

    result = runner.invoke(
        app,
        [
            "scan-http",
            str(response_path),
            "--format",
            "json",
            "--out",
            str(report_path),
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(report_path.read_text(encoding="utf-8"))
    rule_ids = {finding["rule_id"] for finding in data["findings"]}

    assert data["target"]["transport_scheme"] == "unknown"
    assert "VS-HTTP-STRICTTRANSPORTSECURITY" not in rule_ids
    assert any(
        "HSTS applicability was not evaluated because transport_scheme is unknown"
        in warning
        for warning in data["warnings"]
    )


def test_scan_http_explicit_https_reports_missing_hsts(tmp_path):
    response_path = tmp_path / "synthetic-response.txt"
    response_path.write_text(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n",
        encoding="utf-8",
    )
    report_path = tmp_path / "report.json"

    result = runner.invoke(
        app,
        [
            "scan-http",
            str(response_path),
            "--transport-scheme",
            "https",
            "--format",
            "json",
            "--out",
            str(report_path),
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(report_path.read_text(encoding="utf-8"))
    rule_ids = {finding["rule_id"] for finding in data["findings"]}

    assert data["target"]["transport_scheme"] == "https"
    assert "VS-HTTP-STRICTTRANSPORTSECURITY" in rule_ids
