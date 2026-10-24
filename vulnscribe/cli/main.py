from pathlib import Path

import typer
from rich import print

from vulnscribe.core import ScannerRegistry, code_target, http_target
from vulnscribe.reporting import to_json, to_markdown

app = typer.Typer(help="VulnScribe security analysis CLI")
registry = ScannerRegistry()


def write_result(result, out: Path, fmt: str):
    content = to_markdown(result) if fmt == "markdown" else to_json(result)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content, encoding="utf-8")
    print(f"[green]Report written:[/green] {out}")
    print(f"Findings: {len(result.findings)}")


@app.command("scan-code")
def scan_code(file: Path = typer.Argument(..., exists=True, readable=True),
              out: Path = typer.Option(Path("report.json"), "--out", "-o"),
              language: str | None = typer.Option(None, "--language", "-l"),
              format: str = typer.Option("json", "--format")):
    if format not in {"json", "markdown"}:
        raise typer.BadParameter("format must be json or markdown")
    result = registry.run(code_target(file.name, file.read_text(encoding="utf-8", errors="replace"), language))
    write_result(result, out, format)


@app.command("scan-http")
def scan_http(
    file: Path = typer.Argument(..., exists=True, readable=True),
    out: Path = typer.Option(Path("report.md"), "--out", "-o"),
    format: str = typer.Option("markdown", "--format"),
    transport_scheme: str | None = typer.Option(
        None,
        "--transport-scheme",
        help="Transport scheme for the captured response (http or https); required to evaluate HSTS.",
    ),
):
    if format not in {"json", "markdown"}:
        raise typer.BadParameter("format must be json or markdown")
    if transport_scheme is not None:
        transport_scheme = transport_scheme.lower()
        if transport_scheme not in {"http", "https"}:
            raise typer.BadParameter("transport-scheme must be http or https")
    result = registry.run(
        http_target(
            file.name,
            file.read_text(encoding="utf-8", errors="replace"),
            transport_scheme,
        )
    )
    write_result(result, out, format)


if __name__ == "__main__":
    app()
