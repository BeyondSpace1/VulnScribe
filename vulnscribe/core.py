from collections import Counter

from vulnscribe.models import Finding, InputType, ScanResult, ScanTarget, Severity
from vulnscribe.scanners.http_response import HttpResponseScanner
from vulnscribe.scanners.static_code import StaticCodeScanner


class ScannerRegistry:
    def __init__(self):
        self._scanners = [StaticCodeScanner(), HttpResponseScanner()]

    def register(self, scanner):
        self._scanners.append(scanner)

    def run(self, target: ScanTarget) -> ScanResult:
        findings: list[Finding] = []
        for scanner in self._scanners:
            if scanner.supports(target):
                findings.extend(scanner.scan(target))
        unique = {}
        for finding in findings:
            unique[(finding.rule_id, finding.affected_component, finding.line_start)] = finding
        findings = sorted(unique.values(), key=lambda f: (list(Severity).index(f.severity), f.affected_component, f.line_start or 0))
        counts = Counter(f.severity.value for f in findings)
        summary = {s.value: counts.get(s.value, 0) for s in Severity}
        warnings = [
            "Pattern checks can produce false positives and false negatives.",
            "Findings require human validation; no exploitability or CVSS score is asserted automatically.",
        ]
        target_info = {
            "type": target.input_type.value,
            "filename": target.filename,
            "language": target.language,
        }
        if target.input_type == InputType.HTTP_RESPONSE:
            transport_scheme = target.metadata.get("transport_scheme", "unknown")
            target_info["transport_scheme"] = transport_scheme
            if transport_scheme == "http":
                warnings.append(
                    "HSTS applicability was not evaluated because transport_scheme is 'http'; "
                    "browsers ignore HSTS received over insecure transport."
                )
            elif transport_scheme != "https":
                warnings.append(
                    "HSTS applicability was not evaluated because transport_scheme is unknown. "
                    "Set transport_scheme='https' only when the captured response was received over HTTPS."
                )

        return ScanResult(
            target=target_info,
            findings=findings,
            summary=summary,
            warnings=warnings,
        )


def code_target(filename: str, source: str, language: str | None = None) -> ScanTarget:
    return ScanTarget(input_type=InputType.SOURCE_CODE, filename=filename, source=source, language=language)


def http_target(
    filename: str,
    raw_response: str,
    transport_scheme: str | None = None,
) -> ScanTarget:
    scheme = transport_scheme.lower() if transport_scheme else "unknown"
    if scheme not in {"http", "https"}:
        scheme = "unknown"
    return ScanTarget(
        input_type=InputType.HTTP_RESPONSE,
        filename=filename,
        source=raw_response,
        metadata={"transport_scheme": scheme},
    )
