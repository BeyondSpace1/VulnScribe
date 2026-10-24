import pytest

from vulnscribe.models import InputType, ScanTarget
from vulnscribe.scanners.http_response import HttpResponseScanner
from vulnscribe.scanners.static_code import StaticCodeScanner

# These snippets are synthetic source text passed only to the scanner; none is executed.
STATIC_CASES = [
    pytest.param(
        "VS-PHP-001",
        "php",
        "<?php\neval($syntheticExpression);\n",
        "eval($syntheticExpression);",
        2,
        "python",
        id="php-dynamic-evaluation",
    ),
    pytest.param(
        "VS-PHP-002",
        "php",
        '<?php\nmysqli_query($syntheticConnection, "SELECT id FROM demo WHERE id = " . $syntheticId);\n',
        'mysqli_query($syntheticConnection, "SELECT id FROM demo WHERE id = " . $syntheticId);',
        2,
        "python",
        id="php-query-concatenation",
    ),
    pytest.param(
        "VS-PHP-003",
        "php",
        "<?php\ninclude($syntheticTemplate);\n",
        "include($syntheticTemplate);",
        2,
        "python",
        id="php-dynamic-include",
    ),
    pytest.param(
        "VS-PY-001",
        "python",
        'eval("synthetic expression");\n',
        'eval("synthetic expression");',
        1,
        "javascript",
        id="python-dynamic-evaluation",
    ),
    pytest.param(
        "VS-PY-002",
        "python",
        'pickle.loads(b"synthetic-only");\n',
        'pickle.loads(b"synthetic-only");',
        1,
        "javascript",
        id="python-pickle-load",
    ),
    pytest.param(
        "VS-PY-003",
        "python",
        'import subprocess\nsubprocess.run(["echo", "synthetic"], shell=True)\n',
        'subprocess.run(["echo", "synthetic"], shell=True)',
        2,
        "javascript",
        id="python-subprocess-shell",
    ),
    pytest.param(
        "VS-PY-004",
        "python",
        'api_key = "SYNTHETIC_ONLY_0123456789"\n',
        'api_key = "SYNTHETIC_ONLY_0123456789"',
        1,
        "javascript",
        id="python-synthetic-credential-shape",
    ),
    pytest.param(
        "VS-PY-005",
        "python",
        'cursor.execute(f"SELECT name FROM demo WHERE id = {synthetic_id}")\n',
        'cursor.execute(f"SELECT name FROM demo WHERE id = {synthetic_id}")',
        1,
        "javascript",
        id="python-dynamic-sql",
    ),
    pytest.param(
        "VS-JS-001",
        "javascript",
        'eval("synthetic expression");\n',
        'eval("synthetic expression");',
        1,
        "go",
        id="javascript-dynamic-evaluation",
    ),
    pytest.param(
        "VS-JS-002",
        "javascript",
        'element.innerHTML = "static synthetic text";\n',
        'element.innerHTML = "static synthetic text";',
        1,
        "go",
        id="javascript-static-innerhtml-candidate",
    ),
    pytest.param(
        "VS-JS-001",
        "typescript",
        'eval("synthetic expression");\n',
        'eval("synthetic expression");',
        1,
        "go",
        id="typescript-dynamic-evaluation",
    ),
    pytest.param(
        "VS-JS-002",
        "typescript",
        'element.innerHTML = "static synthetic text";\n',
        'element.innerHTML = "static synthetic text";',
        1,
        "go",
        id="typescript-innerhtml-candidate",
    ),
    pytest.param(
        "VS-GO-001",
        "go",
        'http.ListenAndServe(":8080", handler)\n',
        'http.ListenAndServe(":8080", handler)',
        1,
        "python",
        id="go-all-interface-bind-address",
    ),
]


def scan_source(language: str, source: str, filename: str = "synthetic.input"):
    target = ScanTarget(
        input_type=InputType.SOURCE_CODE,
        filename=filename,
        language=language,
        source=source,
    )
    return StaticCodeScanner().scan(target)


@pytest.mark.parametrize(
    "rule_id,language,source,evidence,line_start,unrelated_language",
    STATIC_CASES,
)
def test_static_rule_emits_evidence_backed_candidate(
    rule_id, language, source, evidence, line_start, unrelated_language
):
    filename = f"synthetic.{language}"
    findings = scan_source(language, source, filename)
    finding = next(item for item in findings if item.rule_id == rule_id)

    assert evidence in finding.evidence
    assert finding.affected_component == filename
    assert finding.line_start == line_start
    assert finding.line_end is not None
    assert finding.validation_status == "needs_review"
    assert finding.cvss_score is None
    assert finding.cvss_vector is None


@pytest.mark.parametrize(
    "rule_id,language,source,evidence,line_start,unrelated_language",
    STATIC_CASES,
)
def test_static_rule_does_not_route_to_unrelated_language(
    rule_id, language, source, evidence, line_start, unrelated_language
):
    findings = scan_source(unrelated_language, source)

    assert rule_id not in {item.rule_id for item in findings}


SAFE_CONTROLS = [
    pytest.param("php", "print($syntheticExpression);", "VS-PHP-001", id="php-no-eval"),
    pytest.param(
        "php",
        'mysqli_query($connection, "SELECT 1");',
        "VS-PHP-002",
        id="php-constant-query-with-connection-variable",
    ),
    pytest.param("php", 'include "fixed-template.php";', "VS-PHP-003", id="php-fixed-include"),
    pytest.param("python", 'ast.literal_eval("synthetic")', "VS-PY-001", id="python-literal-eval"),
    pytest.param("python", 'json.loads(b"synthetic")', "VS-PY-002", id="python-json-load"),
    pytest.param(
        "python",
        'subprocess.run(["echo", "synthetic"], check=True)',
        "VS-PY-003",
        id="python-subprocess-without-shell",
    ),
    pytest.param(
        "python",
        'api_key = os.environ["API_KEY"]',
        "VS-PY-004",
        id="python-environment-credential-reference",
    ),
    pytest.param(
        "python",
        'cursor.execute("SELECT name FROM demo WHERE id = ?", (item_id,))',
        "VS-PY-005",
        id="python-parameterized-query",
    ),
    pytest.param("javascript", "const parsed = JSON.parse(rawText);", "VS-JS-001", id="js-json-parse"),
    pytest.param(
        "javascript",
        "element.textContent = syntheticText;",
        "VS-JS-002",
        id="js-text-content",
    ),
    pytest.param(
        "go",
        'http.ListenAndServe("127.0.0.1:8080", handler)',
        "VS-GO-001",
        id="go-loopback-bind-address",
    ),
]


@pytest.mark.parametrize("language,source,rule_id", SAFE_CONTROLS)
def test_safe_static_control_does_not_emit_selected_rule(language, source, rule_id):
    findings = scan_source(language, source)

    assert rule_id not in {item.rule_id for item in findings}


def test_static_constant_innerhtml_is_a_candidate_not_a_confirmed_vulnerability():
    """The scanner cannot infer taint; this harmless literal remains review-only."""
    findings = scan_source("javascript", 'element.innerHTML = "static text";')

    finding = next(item for item in findings if item.rule_id == "VS-JS-002")
    assert finding.validation_status == "needs_review"
    assert finding.line_start == 1


def test_comment_text_can_produce_a_candidate_from_a_line_pattern_rule():
    """Line-pattern checks can match comments; the result remains a candidate."""
    findings = scan_source("python", "# eval(synthetic_value)\n")

    finding = next(item for item in findings if item.rule_id == "VS-PY-001")
    assert finding.evidence == "# eval(synthetic_value)"
    assert finding.validation_status == "needs_review"


HTTP_RULES = {
    "content-security-policy": "VS-HTTP-CONTENTSECURITYPOLICY",
    "x-content-type-options": "VS-HTTP-XCONTENTTYPEOPTIONS",
    "referrer-policy": "VS-HTTP-REFERRERPOLICY",
    "permissions-policy": "VS-HTTP-PERMISSIONSPOLICY",
    "strict-transport-security": "VS-HTTP-STRICTTRANSPORTSECURITY",
}


@pytest.fixture
def http_scanner():
    return HttpResponseScanner()


def http_target(response: str, transport_scheme: str | None = None) -> ScanTarget:
    return ScanTarget(
        input_type=InputType.HTTP_RESPONSE,
        filename="synthetic-response.txt",
        source=response,
        metadata={"transport_scheme": transport_scheme or "unknown"},
    )


def test_http_response_reports_each_missing_security_header_with_evidence(http_scanner):
    response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nsynthetic body"
    findings = http_scanner.scan(http_target(response, transport_scheme="https"))

    assert {item.rule_id for item in findings} == set(HTTP_RULES.values())
    for item in findings:
        header = next(name for name, rule_id in HTTP_RULES.items() if rule_id == item.rule_id)
        assert item.evidence == f"Header not present: {header}"
        assert item.affected_component == "synthetic-response.txt"
        assert item.line_start is None
        assert item.line_end is None
        assert item.validation_status == "needs_review"
        assert item.cvss_score is None


def test_http_response_with_all_headers_emits_no_missing_header_candidates(http_scanner):
    response = (
        "HTTP/1.1 200 OK\r\n"
        "cOnTeNt-SeCuRiTy-PoLiCy: default-src 'self'\r\n"
        "X-CoNtEnT-TyPe-OpTiOnS: nosniff\r\n"
        "rEfErReR-PoLiCy: no-referrer\r\n"
        "PeRmIsSiOnS-PoLiCy: camera=()\r\n"
        "sTrIcT-TrAnSpOrT-SeCuRiTy: max-age=1000\r\n"
        "\r\n"
        "synthetic body"
    )

    assert http_scanner.scan(http_target(response, transport_scheme="https")) == []


@pytest.mark.parametrize(
    "transport_scheme",
    [None, "http"],
    ids=["unknown-transport", "plain-http"],
)
def test_missing_hsts_is_not_reported_without_explicit_https_context(
    http_scanner, transport_scheme
):
    response = "HTTP/1.1 200 OK\\r\\nContent-Type: text/plain\\r\\n\\r\\nsynthetic body"
    findings = http_scanner.scan(http_target(response, transport_scheme=transport_scheme))

    assert "VS-HTTP-STRICTTRANSPORTSECURITY" not in {
        item.rule_id for item in findings
    }


@pytest.mark.parametrize(
    "response",
    ["", "not an HTTP status line\r\nBad Header\r\n\r\n"],
    ids=["empty-input", "malformed-without-status-line"],
)
def test_http_response_without_status_line_emits_no_candidates(http_scanner, response):
    assert http_scanner.scan(http_target(response)) == []


def test_scanner_supports_only_its_input_type():
    source = ScanTarget(input_type=InputType.SOURCE_CODE, filename="synthetic.py", source="pass")
    response = http_target("HTTP/1.1 200 OK\r\n\r\n")

    assert StaticCodeScanner().supports(source)
    assert not StaticCodeScanner().supports(response)
    assert HttpResponseScanner().supports(response)
    assert not HttpResponseScanner().supports(source)
