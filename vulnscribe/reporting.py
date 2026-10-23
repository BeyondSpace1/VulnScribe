import re
from html import escape
from pathlib import Path

from vulnscribe.models import ScanResult

_MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()|])")


def _markdown_text(value: object) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    return _MARKDOWN_SPECIAL.sub(r"\\\1", escape(text, quote=False))


def to_json(result: ScanResult) -> str:
    return result.model_dump_json(indent=2)


def to_markdown(result: ScanResult) -> str:
    lines = [
        "# VulnScribe Security Analysis Report",
        "",
        f"- **Scan ID:** `{result.scan_id}`",
        f"- **Created:** {result.created_at.isoformat()}",
        f"- **Input:** {_markdown_text(result.target.get('filename', 'unknown'))}",
        f"- **Type:** {_markdown_text(result.target.get('type', 'unknown'))}",
        "",
        "## Executive Summary",
        "",
        "Automated candidate findings follow. Validate each item before treating it as confirmed.",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]

    lines += [
        f"| {severity} | {count} |"
        for severity, count in result.summary.items()
    ]

    lines += ["", "## Findings", ""]

    if not result.findings:
        lines.append(
            "No findings were produced by enabled checks. "
            "This is not proof the target is secure."
        )

    for f in result.findings:
        lines += [
            f"### {_markdown_text(f.id)}: {_markdown_text(f.title)}",
             "",
            f"- **Severity estimate:** {_markdown_text(f.severity.value)}",
            f"- **Confidence:** {_markdown_text(f.confidence)}",
            f"- **Rule:** {_markdown_text(f.rule_id)}",
            f"- **CWE:** {_markdown_text(f.cwe_id or 'Not mapped')}",
            f"- **OWASP:** {_markdown_text(f.owasp_category or 'Not mapped')}",
            f"- **Location:** {_markdown_text(f.affected_component)}"
            + (f":{f.line_start}" if f.line_start else ""),
            "- **CVSS:** Not scored automatically",
            f"- **Validation status:** {_markdown_text(f.validation_status)}",
            "",
            _markdown_text(f.description),
            "",
            "**Evidence**",
            "",
        ]

        evidence = f.evidence[:2000]
        max_backticks = max(
            (len(match) for match in re.findall(r"`+", evidence)),
            default=0,
        )
        fence = "`" * max(3, max_backticks + 1)

        lines += [
            fence + "text",
            evidence,
            fence,
            "",
            "**Remediation**",
            "",
            _markdown_text(f.remediation),
            "",
            "**References**",
        ]

        lines += [f"- {_markdown_text(ref)}" for ref in f.references]
        lines.append("")

    lines += [
        "## Limitations",
        *[f"- {_markdown_text(w)}" for w in result.warnings],
        "",
        "## Methodology",
        "",
        (
            "VulnScribe MVP deterministic checks; no active tests, "
            "code execution, or external AI analysis were performed."
        ),
    ]

    return "\n".join(lines) + "\n"


def to_pdf(result: ScanResult, output_path: str | Path) -> Path:
    try:
        from weasyprint import HTML
    except ImportError as exc:
        raise RuntimeError("PDF export requires optional dependencies: pip install '.[pdf]'") from exc
    md = escape(to_markdown(result))
    html = ("<!doctype html><html><head><meta charset='utf-8'><style>"
            "body{font-family:sans-serif;margin:28px;color:#202124}"
            "pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:10pt}"
            "@page{size:A4;margin:18mm}</style></head><body><pre>" + md + "</pre></body></html>")
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html).write_pdf(str(path))
    return path
