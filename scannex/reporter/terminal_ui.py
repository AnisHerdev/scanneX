"""Rich terminal UI for ScanneX live scanning, tables, and patch diff presentation."""

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from scannex.db.models import Finding, FindingStatus, Severity


class TerminalUI:
    """Renders interactive command-line security reports and diffs."""

    def __init__(self, console: Console | None = None):
        self.console = console or Console()

    def print_banner(self) -> None:
        """Display ScanneX banner."""
        banner_text = Text()
        banner_text.append("   _____                                 __   __\n", style="bold cyan")
        banner_text.append("  / ____|                                \\ \\ / /\n", style="bold cyan")
        banner_text.append(" | (___   ___ __ _ _ __  _ __   _____  __ \\ V / \n", style="bold blue")
        banner_text.append("  \\___ \\ / __/ _` | '_ \\| '_ \\ / _ \\ \\/ /  > <  \n", style="bold blue")
        banner_text.append("  ____) | (_| (_| | | | | | | |  __/>  <  / . \\ \n", style="bold magenta")
        banner_text.append(" |_____/ \\___\\__,_|_| |_|_| |_|\\___/_/\\_\\/_/ \\_\\\n", style="bold magenta")
        banner_text.append("\n  Autonomous AppSec Verification & Speculative Remediation\n", style="italic bold white")
        banner_text.append("  Team Gravitas (T2-13) - HackFest 2026\n", style="dim white")
        self.console.print(Panel(banner_text, border_style="cyan"))

    def render_findings_table(self, findings: list[Finding]) -> None:
        """Render findings table with color-coded status badges."""
        table = Table(
            title="ScanneX Evidence-Backed Findings Summary",
            header_style="bold white on dark_blue",
            show_lines=True,
        )

        table.add_column("Severity", justify="center", style="bold", width=10)
        table.add_column("Status", justify="center", width=18)
        table.add_column("Vulnerability / CWE", style="cyan", width=22)
        table.add_column("Location", style="white", width=20)
        table.add_column("Proof / Oracle Evidence", style="dim white")

        for f in findings:
            sev_style = {
                Severity.CRITICAL: "bold red",
                Severity.HIGH: "red",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "blue",
                Severity.INFO: "dim white",
            }.get(f.severity, "white")

            status_text = Text(f.status.value)
            if f.status == FindingStatus.VERIFIED_FIXED:
                status_text.stylize("bold black on green")
            elif f.status == FindingStatus.CONFIRMED_DYNAMIC:
                status_text.stylize("bold white on red")
            elif f.status == FindingStatus.CONFIRMED_STATIC:
                status_text.stylize("bold yellow")
            elif f.status == FindingStatus.UNVERIFIED:
                status_text.stylize("dim")
            elif f.status == FindingStatus.REJECTED:
                status_text.stylize("strike dim red")

            # Evidence snippet
            evidence = "No dynamic probe"
            if f.probe_result and f.probe_result.canary_tripped:
                evidence = f"Canary Tripped: {f.probe_result.response_snippet or 'Token present'}"
            elif f.verifier_notes:
                evidence = f.verifier_notes[:45] + "..." if len(f.verifier_notes) > 45 else f.verifier_notes

            table.add_row(
                Text(f.severity.value, style=sev_style),
                status_text,
                f"{f.vuln_type}\n({f.cwe})",
                f"{f.file_path}:{f.line_number}",
                evidence,
            )

        self.console.print(table)

    def render_patch_diff(self, finding: Finding) -> None:
        """Render syntax-highlighted unified diff for verified patches."""
        if not finding.patch_spec or not finding.patch_spec.unified_diff:
            return

        verified_badge = (
            "[bold green][VERIFIED IN SANDBOX][/bold green]"
            if finding.patch_spec.retest_verified
            else "[dim][CANDIDATE SUGGESTION][/dim]"
        )

        title = f"Speculative Patch for {finding.title} {verified_badge}"
        syntax = Syntax(finding.patch_spec.unified_diff, "diff", theme="monokai", line_numbers=True)

        self.console.print(
            Panel(
                syntax,
                title=title,
                subtitle=finding.patch_spec.explanation or "Search & Replace Remediation",
                border_style="green" if finding.patch_spec.retest_verified else "yellow",
            )
        )
