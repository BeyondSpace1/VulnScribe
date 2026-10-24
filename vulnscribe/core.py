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
        return ScanResult(
            target={"type": target.input_type.value, "filename": target.filename, "language": target.language},
            findings=findings, summary=summary,
            warnings=["Pattern checks can produce false positives and false negatives.",
                      "Findings require human validation; no exploitability or CVSS score is asserted automatically."])


def code_target(filename: str, source: str, language: str | None = None) -> ScanTarget:
    return ScanTarget(input_type=InputType.SOURCE_CODE, filename=filename, source=source, language=language)


def http_target(filename: str, raw_response: str) -> ScanTarget:
    return ScanTarget(input_type=InputType.HTTP_RESPONSE, filename=filename, source=raw_response)
