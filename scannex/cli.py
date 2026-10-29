"""Command-line interface for ScanneX AppSec pipeline."""

import asyncio
import os
from pathlib import Path
import sys
import threading
import zipfile

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import click
from rich.console import Console
from scannex.benchmark import get_benchmark_dir
from scannex.config import ScannexConfig
from scannex.db.models import FindingStatus
from scannex.db.store import FindingsStore
from scannex.orchestrator.pipeline import PipelineEvent, ScannexOrchestrator
from scannex.reporter.markdown_exporter import MarkdownExporter
from scannex.reporter.sarif_exporter import SarifExporter
from scannex.reporter.terminal_ui import TerminalUI

console = Console()
ui = TerminalUI(console)


@click.group()
@click.version_option(version="0.1.0")
def main():
    """ScanneX: Autonomous AppSec Verification & Speculative Remediation Pipeline."""
    pass


@main.command()
@click.argument("target", default=".", type=click.Path(exists=True, file_okay=True, dir_okay=True))
@click.option("--mock/--no-mock", default=False, help="Use offline mock mode — no API key needed")
@click.option("--dockeronly", is_flag=True, default=False, help="Abort immediately if Docker is unavailable (no subprocess fallback)")
@click.option("--model", default=None, help="LLM model (e.g. gemini/gemini-2.5-flash, ollama/codellama)")
@click.option("--sarif", default="scannex-report.sarif", help="Path for SARIF 2.1.0 export")
@click.option("--markdown", default="scannex-report.md", help="Path for Markdown report export")
@click.option("--html", default="scannex-report.html", help="Path for HTML report export")
@click.option("--db", default=".scannex/findings.db", help="SQLite findings store path")
@click.option("--concurrency", default=2, type=int, help="Max parallel sandboxes")
def scan(target, mock, dockeronly, model, sarif, markdown, html, db, concurrency):
    """Scan a target repository or file with ScanneX."""
    ui.print_banner()

    target_path = Path(target).resolve()
    if target_path.is_file() and (target_path.suffix.lower() == ".zip" or zipfile.is_zipfile(target_path)):
        console.print(f"[bold cyan]Scanning ZIP archive target:[/bold cyan] {target_path}")
        console.print(f"[dim]ScanneX will safely unpack and inspect the archive codebase.[/dim]\n")
    else:
        console.print(f"[bold cyan]Scanning target directory:[/bold cyan] {target_path}\n")

    config = ScannexConfig.from_env()
    config.mock_mode = mock
    config.docker_only = dockeronly
    if model:
        config.model_name = model
    config.db_path = Path(db)
    config.max_concurrency = concurrency

    store = FindingsStore(config.db_path)

    def event_handler(ev: PipelineEvent):
        color = {
            "EXTRACT": "bold cyan",
            "INIT": "cyan",
            "MALWARE_SCAN": "bold red",
            "STATIC_SCAN": "yellow",
            "BANDIT_SCAN": "yellow",
            "SEMGREP_SCAN": "bright_blue",
            "AI_HUNT": "magenta",
            "ADVERSARIAL_VERIFY": "blue",
            "CONSOLIDATE": "bright_blue",
            "SPECULATIVE_EXEC": "magenta",
            "PROBE_CONFIRMED": "red",
            "RETEST_PATCH": "green",
            "FIX_VERIFIED": "bold green",
            "COMPLETE": "bold green",
            "FAILED": "bold red",
        }.get(ev.stage, "white")
        console.print(f"[{color}]* [{ev.stage}][/{color}] {ev.message}")

    orchestrator = ScannexOrchestrator(
        target_dir=target_path,
        config=config,
        store=store,
        event_callback=event_handler,
    )

    findings = asyncio.run(orchestrator.run())

    console.print("\n")
    ui.render_findings_table(findings)

    # Render syntax-highlighted diffs for verified patches
    for f in findings:
        if f.status == FindingStatus.VERIFIED_FIXED and f.patch_spec:
            console.print("\n")
            ui.render_patch_diff(f)

    # Export reports
    SarifExporter.export(findings, sarif)
    MarkdownExporter.export_markdown(findings, markdown)
    MarkdownExporter.export_html(findings, html)

    console.print(f"\n[bold green][OK][/bold green] SARIF report exported to: [underline]{sarif}[/underline]")
    console.print(f"[bold green][OK][/bold green] Markdown report exported to: [underline]{markdown}[/underline]")
    console.print(f"[bold green][OK][/bold green] HTML report exported to: [underline]{html}[/underline]")


@main.command()
@click.option("--mock/--no-mock", default=False, help="Use offline mock mode — no API key needed")
@click.option("--dockeronly", is_flag=True, default=False, help="Abort immediately if Docker is unavailable (no subprocess fallback)")
@click.option("--sarif", default="scannex-demo-report.sarif", help="Path for SARIF export")
@click.option("--markdown", default="scannex-demo-report.md", help="Path for Markdown report")
@click.option("--html", default="scannex-demo-report.html", help="Path for HTML report")
def demo(mock, dockeronly, sarif, markdown, html):
    """Run retrospective verification demo on bundled vulnerable benchmark application."""
    ui.print_banner()

    benchmark_dir = get_benchmark_dir()
    console.print(f"[bold magenta]>> Running ScanneX Retrospective Demo on Pre-Patch Benchmark App[/bold magenta]")
    console.print(f"  Target: [cyan]{benchmark_dir}[/cyan]\n")

    config = ScannexConfig(
        mock_mode=mock,
        docker_only=dockeronly,
        db_path=Path(".scannex/demo_findings.db"),
        max_concurrency=2,
    )

    store = FindingsStore(config.db_path)
    store.clear()

    def event_handler(ev: PipelineEvent):
        color = {
            "INIT": "cyan",
            "STATIC_SCAN": "yellow",
            "BANDIT_SCAN": "yellow",
            "SEMGREP_SCAN": "bright_blue",
            "AI_HUNT": "magenta",
            "ADVERSARIAL_VERIFY": "blue",
            "CONSOLIDATE": "bright_blue",
            "SPECULATIVE_EXEC": "magenta",
            "PROBE_CONFIRMED": "bold red",
            "RETEST_PATCH": "cyan",
            "FIX_VERIFIED": "bold green",
            "COMPLETE": "bold green",
            "FAILED": "bold red",
        }.get(ev.stage, "white")
        console.print(f"[{color}]* [{ev.stage}][/{color}] {ev.message}")

    orchestrator = ScannexOrchestrator(
        target_dir=benchmark_dir,
        config=config,
        store=store,
        event_callback=event_handler,
    )

    findings = asyncio.run(orchestrator.run())

    console.print("\n")
    ui.render_findings_table(findings)

    # Render verified patches
    for f in findings:
        if f.status == FindingStatus.VERIFIED_FIXED and f.patch_spec:
            console.print("\n")
            ui.render_patch_diff(f)

    # Export reports
    SarifExporter.export(findings, sarif)
    MarkdownExporter.export_markdown(findings, markdown)
    MarkdownExporter.export_html(findings, html)

    console.print(f"\n[bold green][OK][/bold green] SARIF report exported to: [underline]{sarif}[/underline]")
    console.print(f"[bold green][OK][/bold green] Markdown report exported to: [underline]{markdown}[/underline]")
    console.print(f"[bold green][OK][/bold green] HTML report exported to: [underline]{html}[/underline]\n")
    console.print("[bold green]All findings dynamically proven and speculatively remediated![/bold green]")


@main.command()
@click.option("--db", default=".scannex/findings.db", help="SQLite store path")
def report(db):
    """View stored findings from a previous ScanneX run."""
    ui.print_banner()
    store = FindingsStore(db)
    findings = store.list_findings()

    if not findings:
        console.print(f"[yellow]No findings located in {db}. Run `scannex scan` or `scannex demo` first.[/yellow]")
        return

    ui.render_findings_table(findings)
    for f in findings:
        if f.status == FindingStatus.VERIFIED_FIXED and f.patch_spec:
            console.print("\n")
            ui.render_patch_diff(f)


@main.command()
@click.option("--port", default=8080, help="Port to bind the web dashboard to")
@click.option("--host", default="127.0.0.1", help="Host interface to bind to")
@click.option("--open-browser/--no-open-browser", default=True, help="Automatically open browser")
def dashboard(port, host, open_browser):
    """Launch the interactive web dashboard for drag-and-drop ZIP and GitHub scans."""
    ui.print_banner()
    console.print(f"[bold cyan]Launching ScanneX Web Dashboard at:[/bold cyan] [underline green]http://{host}:{port}/[/underline green]\n")
    
    if open_browser:
        import webbrowser
        threading.Timer(1.2, lambda: webbrowser.open(f"http://{host}:{port}/")).start()

    from scannex.web import run_web_dashboard
    run_web_dashboard(host=host, port=port)


if __name__ == "__main__":
    main()
