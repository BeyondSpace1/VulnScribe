from typing import ClassVar

from vulnscribe.models import Finding, InputType, ScanTarget, Severity
from vulnscribe.scanners.base import BaseScanner


class HttpResponseScanner(BaseScanner):
    scanner_name = "http-response-headers"
    CHECKS: ClassVar = {
        "content-security-policy": ("Content Security Policy is absent", "A missing CSP can increase impact of some injection issues; it does not prove XSS.", Severity.LOW),
        "x-content-type-options": ("X-Content-Type-Options is absent", "Without nosniff, browsers may MIME-sniff in some contexts.", Severity.LOW),
        "referrer-policy": ("Referrer-Policy is absent", "A policy can reduce unintended referrer information disclosure.", Severity.INFO),
        "permissions-policy": ("Permissions-Policy is absent", "A policy can restrict browser features not needed by the application.", Severity.INFO),
        "strict-transport-security": ("Strict-Transport-Security is absent", "HSTS can instruct browsers to use HTTPS for future requests; enable only after HTTPS readiness is confirmed.", Severity.LOW),
    }

    def supports(self, target: ScanTarget) -> bool:
        return target.input_type == InputType.HTTP_RESPONSE

    # def scan(self, target: ScanTarget) -> list[Finding]:
    #     headers = {}
    #     in_headers = False
    #     status_line_found = False

    #     for line in target.source.replace("\r\n", "\n").split("\n"):
    #         if line.startswith("HTTP/"):
    #             status_line_found = True
    #             in_headers = True
    #             continue
    #     if not status_line_found:
    #         return []
    #     findings = []
    #     for header, (title, desc, severity) in self.CHECKS.items():
    #         if header in headers:
    #             continue
    #         findings.append(Finding(
    #             rule_id=f"VS-HTTP-{header.upper().replace('-', '')}", title=title, description=desc,
    #             severity=severity, confidence="high" if header != "strict-transport-security" else "medium",
    #             cwe_id="CWE-319" if header == "strict-transport-security" else None,
    #             owasp_category="A02:2025 - Security Misconfiguration", affected_component=target.filename,
    #             evidence=f"Header not present: {header}",
    #             remediation=f"Review whether the application needs the {header} response header and configure a suitable policy.",
    #             references=["https://owasp.org/www-project-secure-headers/"], scanner=self.scanner_name))
    #     return findings


    def scan(self, target: ScanTarget) -> list[Finding]:
        headers = {}
        in_headers = False
        status_line_found = False

        for line in target.source.replace("\r\n", "\n").split("\n"):
            if line.startswith("HTTP/"):
                status_line_found = True
                in_headers = True
                continue

            if in_headers and not line.strip():
                break

            if in_headers and ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()

        if not status_line_found:
            return []

        findings = []
        for header, (title, desc, severity) in self.CHECKS.items():
            if (
                header == "strict-transport-security"
                and target.metadata.get("transport_scheme") != "https"
            ):
                continue
            if header in headers:
                continue

            findings.append(
                Finding(
                    rule_id=f"VS-HTTP-{header.upper().replace('-', '')}",
                    title=title,
                    description=desc,
                    severity=severity,
                    confidence=(
                        "high"
                        if header != "strict-transport-security"
                        else "medium"
                    ),
                    cwe_id=(
                        "CWE-319"
                        if header == "strict-transport-security"
                        else None
                    ),
                    owasp_category="A02:2025 - Security Misconfiguration",
                    affected_component=target.filename,
                    evidence=f"Header not present: {header}",
                    remediation=(
                        f"Review whether the application needs the {header} "
                        "response header and configure a suitable policy."
                    ),
                    references=["https://owasp.org/www-project-secure-headers/"],
                    scanner=self.scanner_name,
                )
            )

        return findings
