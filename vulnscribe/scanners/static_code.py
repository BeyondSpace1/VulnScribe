import ast
import re
from pathlib import Path
from typing import ClassVar

from vulnscribe.models import Finding, InputType, ScanTarget, Severity
from vulnscribe.scanners.base import BaseScanner


class StaticCodeScanner(BaseScanner):
    scanner_name = "static-code-patterns"
    RULES: ClassVar = [
        dict(id="VS-PHP-001", langs={"php"}, pattern=r"\beval\s*\(", title="Dynamic code evaluation",
             desc="The code appears to evaluate a dynamically supplied expression. Review the origin and control of evaluated input.",
             severity=Severity.HIGH, confidence="medium", cwe="CWE-95", owasp="A05:2025 - Injection",
             fix="Avoid evaluating strings as code; use explicit parsing or allowlisted operations."),
        dict(id="VS-PHP-002", langs={"php"}, pattern=r"\b(?:mysql_query|mysqli_query)\s*\([^;\n]*(?:\.\s*\$|,\s*\$)", title="Possible SQL query built with variable concatenation",
             desc="A database query may include a variable directly. This pattern alone does not prove SQL injection.",
             severity=Severity.HIGH, confidence="low", cwe="CWE-89", owasp="A05:2025 - Injection",
             fix="Use parameterized queries/prepared statements and bind values separately from SQL syntax."),
        dict(id="VS-PHP-003", langs={"php"}, pattern=r"\b(?:include|require)(?:_once)?\s*\(?\s*\$", title="Dynamic file inclusion",
             desc="A variable appears to influence a PHP include/require path. Review whether an attacker can control it.",
             severity=Severity.HIGH, confidence="medium", cwe="CWE-98", owasp="A05:2025 - Injection",
             fix="Map identifiers to a fixed allowlist of files; do not accept arbitrary paths from users."),
        dict(id="VS-PY-001", langs={"python"}, pattern=r"\beval\s*\(|\bexec\s*\(", title="Dynamic Python code execution",
             desc="eval/exec can execute code represented as data. Risk depends on whether untrusted input reaches the call.",
             severity=Severity.HIGH, confidence="medium", cwe="CWE-95", owasp="A05:2025 - Injection",
             fix="Avoid eval/exec on user-controlled data; use safe parsers and allowlisted operations."),
        dict(id="VS-PY-002", langs={"python"}, pattern=r"\bpickle\.loads?\s*\(", title="Unsafe deserialization candidate",
             desc="Pickle deserialization can execute attacker-controlled behavior when the payload is untrusted.",
             severity=Severity.HIGH, confidence="medium", cwe="CWE-502", owasp="A08:2025 - Software or Data Integrity Failures",
             fix="Do not unpickle untrusted data. Prefer JSON or another non-object-instantiating format."),
        dict(
            id="VS-PY-003",
            langs={"python"},
            pattern=r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\(.*\bshell\s*=\s*True\b",
            title="Subprocess command executed through a shell",
            desc="A subprocess call enables shell interpretation. If command arguments contain untrusted input, this may allow command injection.",
            severity=Severity.HIGH,
            confidence="medium",
            cwe="CWE-78",
            owasp="A05:2025 - Injection",
            fix="Avoid shell=True when possible. Pass an argument list to subprocess and validate untrusted input against an allowlist.",
        ),
        dict(
            id="VS-PY-004",
            langs={"python"},
            pattern=(
                r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)"
                r"\b\s*[:=]\s*"
                r"""["'](?!\s*(?:your_api_key_here|replace_me|change_me|"""
                r"""changeme|placeholder|example|dummy|xxx|<))[A-Za-z0-9_./+=-]{8,}["']"""
            ),
            title="Potential hardcoded credential",
            desc="A credential-like variable is assigned a string literal. Confirm whether the value is a real secret rather than a test fixture or placeholder.",
            severity=Severity.MEDIUM,
            confidence="low",
            cwe="CWE-798",
            owasp="A07:2025 - Identification and Authentication Failures",
            fix="Store secrets in a secret manager or environment variables. Rotate any exposed credentials and remove them from repository history where necessary.",
        ),
        dict(
            id="VS-PY-005",
            langs={"python"},
            pattern=(
                r"\.execute\s*\(\s*"
                r"(?:f[\"']|[\"'][^\"']*[\"']\s*(?:\+|%))"
            ),
            title="Potential SQL injection through dynamic query construction",
            desc="A database execute() call appears to build a query using an f-string, string concatenation, or percent formatting. Verify whether untrusted input can affect the SQL statement.",
            severity=Severity.HIGH,
            confidence="low",
            cwe="CWE-89",
            owasp="A05:2025 - Injection",
            fix="Use parameterized queries and pass values separately from the SQL statement. Avoid building SQL syntax from untrusted input.",
        ),
        dict(id="VS-JS-001", langs={"javascript", "typescript"}, pattern=r"\beval\s*\(|new\s+Function\s*\(", title="Dynamic JavaScript code evaluation",
             desc="Dynamic evaluation can turn data into executable code. Confirm whether untrusted input can reach this call.",
             severity=Severity.HIGH, confidence="medium", cwe="CWE-95", owasp="A05:2025 - Injection",
             fix="Replace dynamic evaluation with explicit logic or safe data parsing."),
        dict(id="VS-JS-002", langs={"javascript", "typescript"}, pattern=r"\.innerHTML\s*=", title="Potential unsafe HTML sink",
             desc="innerHTML interprets strings as HTML. Determine whether the assigned value can contain attacker-controlled content.",
             severity=Severity.MEDIUM, confidence="low", cwe="CWE-79", owasp="A05:2025 - Injection",
             fix="Prefer textContent for text. If HTML is required, use a vetted sanitizer and contextual output encoding."),
        dict(id="VS-GO-001", langs={"go"}, pattern=r"\bhttp\.ListenAndServe\s*\(\s*['\"]:\d+['\"]", title="HTTP server may bind to all interfaces",
             desc="An address such as ':8080' typically binds on all interfaces. Confirm intended exposure.",
             severity=Severity.LOW, confidence="low", cwe="CWE-668", owasp="A02:2025 - Security Misconfiguration",
             fix="Bind to an explicit interface when appropriate and enforce network exposure controls."),
    ]
    EXTENSIONS: ClassVar = {".php":"php", ".phtml":"php", ".js":"javascript", ".jsx":"javascript",
                  ".ts":"typescript", ".tsx":"typescript", ".py":"python", ".go":"go"}

    def supports(self, target: ScanTarget) -> bool:
        return target.input_type == InputType.SOURCE_CODE

    def scan(self, target: ScanTarget) -> list[Finding]:
        language = (
            target.language
            or self.EXTENSIONS.get(Path(target.filename).suffix.lower(), "")
        ).lower()

        source = target.source
        source_lines = source.splitlines()
        findings = []

        tree = None
        if language == "python":
            try:
                tree = ast.parse(source)
            except SyntaxError:
                tree = None

        for rule in self.RULES:
            if language not in rule["langs"]:
                continue

            # AST-based detection for direct Python eval()/exec() calls.
            if rule["id"] == "VS-PY-001" and language == "python":
                if tree is None:
                    continue

                for node in ast.walk(tree):
                    if not (
                        isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id in {"eval", "exec"}
                    ):
                        continue

                    line_start = node.lineno
                    line_end = getattr(node, "end_lineno", line_start)
                    evidence = " ".join(
                        source_lines[line_start - 1:line_end]
                    ).strip()[:500]

                    cwe_num = rule["cwe"].split("-")[-1]
                    findings.append(
                        Finding(
                            rule_id=rule["id"],
                            title=rule["title"],
                            description=rule["desc"],
                            severity=rule["severity"],
                            confidence=rule["confidence"],
                            cwe_id=rule["cwe"],
                            owasp_category=rule["owasp"],
                            affected_component=target.filename,
                            line_start=line_start,
                            line_end=line_end,
                            evidence=evidence,
                            remediation=rule["fix"],
                            references=[
                                f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
                            ],
                            scanner=self.scanner_name,
                        )
                    )
                continue

            # AST-based detection for subprocess shell=True.
            if rule["id"] == "VS-PY-003" and language == "python":
                if tree is None:
                    continue

                for node in ast.walk(tree):
                    if not isinstance(node, ast.Call):
                        continue

                    func = node.func
                    if not (
                        isinstance(func, ast.Attribute)
                        and func.attr in {
                            "run", "Popen", "call",
                            "check_call", "check_output"
                        }
                        and isinstance(func.value, ast.Name)
                        and func.value.id == "subprocess"
                    ):
                        continue

                    shell_arg = next(
                        (kw.value for kw in node.keywords if kw.arg == "shell"),
                        None,
                    )
                    if not (
                        isinstance(shell_arg, ast.Constant)
                        and shell_arg.value is True
                    ):
                        continue

                    line_start = node.lineno
                    line_end = getattr(node, "end_lineno", line_start)
                    evidence = " ".join(
                        source_lines[line_start - 1:line_end]
                    ).strip()[:500]

                    cwe_num = rule["cwe"].split("-")[-1]
                    findings.append(Finding(
                        rule_id=rule["id"],
                        title=rule["title"],
                        description=rule["desc"],
                        severity=rule["severity"],
                        confidence=rule["confidence"],
                        cwe_id=rule["cwe"],
                        owasp_category=rule["owasp"],
                        affected_component=target.filename,
                        line_start=line_start,
                        line_end=line_end,
                        evidence=evidence,
                        remediation=rule["fix"],
                        references=[
                            f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
                        ],
                        scanner=self.scanner_name,
                    ))
                continue

            # AST-based heuristic for dynamically constructed SQL.
            if rule["id"] == "VS-PY-005" and language == "python":
                if tree is None:
                    continue

                sql_keywords = {
                    "SELECT", "INSERT", "UPDATE", "DELETE", "REPLACE", "WITH"
                }

                for node in ast.walk(tree):
                    if not (
                        isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "execute"
                        and node.args
                    ):
                        continue

                    query = node.args[0]
                    string_constants = [
                        child.value
                        for child in ast.walk(query)
                        if isinstance(child, ast.Constant)
                        and isinstance(child.value, str)
                    ]
                    sql_text = " ".join(string_constants).upper()
                    has_sql_keyword = any(
                        re.search(r"\b" + keyword + r"\b", sql_text)
                        for keyword in sql_keywords
                    )

                    is_dynamic = any(
                        isinstance(child, ast.JoinedStr)
                        or (
                            isinstance(child, ast.BinOp)
                            and isinstance(child.op, (ast.Add, ast.Mod))
                        )
                        or (
                            isinstance(child, ast.Call)
                            and isinstance(child.func, ast.Attribute)
                            and child.func.attr == "format"
                        )
                        for child in ast.walk(query)
                    )

                    if not (has_sql_keyword and is_dynamic):
                        continue

                    line_start = node.lineno
                    line_end = getattr(node, "end_lineno", line_start)
                    evidence = " ".join(
                        source_lines[line_start - 1:line_end]
                    ).strip()[:500]

                    cwe_num = rule["cwe"].split("-")[-1]
                    findings.append(Finding(
                        rule_id=rule["id"],
                        title=rule["title"],
                        description=rule["desc"],
                        severity=rule["severity"],
                        confidence=rule["confidence"],
                        cwe_id=rule["cwe"],
                        owasp_category=rule["owasp"],
                        affected_component=target.filename,
                        line_start=line_start,
                        line_end=line_end,
                        evidence=evidence,
                        remediation=rule["fix"],
                        references=[
                            f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
                        ],
                        scanner=self.scanner_name,
                    ))
                continue

            # Regex-based checks for the remaining rules.
            for line_no, line in enumerate(source_lines, 1):
                if not re.search(rule["pattern"], line, re.IGNORECASE):
                    continue

                cwe_num = rule["cwe"].split("-")[-1]
                findings.append(Finding(
                    rule_id=rule["id"],
                    title=rule["title"],
                    description=rule["desc"],
                    severity=rule["severity"],
                    confidence=rule["confidence"],
                    cwe_id=rule["cwe"],
                    owasp_category=rule["owasp"],
                    affected_component=target.filename,
                    line_start=line_no,
                    line_end=line_no,
                    evidence=line.strip()[:500],
                    remediation=rule["fix"],
                    references=[
                        f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
                    ],
                    scanner=self.scanner_name,
                ))

        return findings
