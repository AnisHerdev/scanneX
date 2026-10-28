"""Markdown and HTML report generator for ScanneX."""

from pathlib import Path
from scannex.db.models import Finding, FindingStatus


class MarkdownExporter:
    """Exports findings and evidence traces to Markdown and standalone HTML."""

    @classmethod
    def export_markdown(cls, findings: list[Finding], output_path: Path | str) -> str:
        """Write findings summary to Markdown."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        md = []
        md.append("# ScanneX Security Audit Report")
        md.append("*Autonomous Verification & Speculative Remediation*\n")

        # Status summary table
        status_counts = {}
        for f in findings:
            status_counts[f.status.value] = status_counts.get(f.status.value, 0) + 1

        md.append("## Executive Summary")
        md.append("| Status | Meaning | Count |")
        md.append("| :--- | :--- | :--- |")
        md.append(f"| `verified_fixed` | Flaw dynamically proven & patch confirmed | {status_counts.get('verified_fixed', 0)} |")
        md.append(f"| `confirmed_dynamic` | Exploit canary tripped in isolated sandbox | {status_counts.get('confirmed_dynamic', 0)} |")
        md.append(f"| `confirmed_static` | Full source-to-sink taint path verified | {status_counts.get('confirmed_static', 0)} |")
        md.append(f"| `unverified` | Probe failed to trip canary (uncertainty preserved) | {status_counts.get('unverified', 0)} |")
        md.append(f"| `rejected` | Debunked by Adversarial Verifier | {status_counts.get('rejected', 0)} |\n")

        md.append("## Detailed Findings\n")
        if not findings:
            md.append("No security issues detected. Target repository passed all checks.")
        else:
            for i, f in enumerate(findings, 1):
                status_badge = f"`{f.status.value}`"
                md.append(f"### {i}. [{f.severity.value}] {f.title} ({status_badge})")
                md.append(f"- **File:** `{f.file_path}:{f.line_number}`")
                md.append(f"- **Vulnerability Type:** `{f.vuln_type}` ({f.cwe})")
                md.append(f"- **Source:** `{f.source}`")
                md.append(f"- **Description:** {f.description}")

                if f.sink_code:
                    md.append(f"\n**Code Sink:**\n```python\n{f.sink_code}\n```")

                if f.probe_spec:
                    md.append(f"\n**Canary Probe Blueprint:**")
                    md.append(f"- Endpoint: `{f.probe_spec.method} {f.probe_spec.endpoint}`")
                    md.append(f"- Canary Token: `{f.probe_spec.canary_token}`")
                    if f.probe_result:
                        tripped = "YES (EXPLOIT PROVEN)" if f.probe_result.canary_tripped else "NO"
                        md.append(f"- Canary Tripped: **{tripped}** ({f.probe_result.execution_time_ms:.1f}ms)")
                        if f.probe_result.response_snippet:
                            md.append(f"- Oracle Evidence: `{f.probe_result.response_snippet}`")

                if f.patch_spec and f.patch_spec.unified_diff:
                    verified = " (VERIFIED IN SANDBOX)" if f.patch_spec.retest_verified else ""
                    md.append(f"\n**Speculative Patch{verified}:**")
                    md.append(f"*{f.patch_spec.explanation}*")
                    md.append(f"```diff\n{f.patch_spec.unified_diff}\n```")

                if f.evidence_trace:
                    md.append("\n**Audit Evidence Trail:**")
                    for trace in f.evidence_trace:
                        md.append(f"- {trace}")

                md.append("\n---")

        content = "\n".join(md)
        out.write_text(content, encoding="utf-8")
        return content

    @classmethod
    def export_html(cls, findings: list[Finding], output_path: Path | str) -> str:
        """Generate styled standalone HTML report."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        md_content = cls.export_markdown(findings, out.with_suffix(".md"))
        
        # Simple beautiful responsive HTML wrapper
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ScanneX Security Report</title>
<style>
  :root {{
    --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  }}
  body {{
    font-family: var(--font-sans);
    line-height: 1.6;
    color: #09090b;
    max-width: 920px;
    margin: 40px auto;
    padding: 0 24px;
    -webkit-font-smoothing: antialiased;
    text-rendering: optimizeLegibility;
  }}
  h1, h2, h3 {{
    color: #09090b;
    border-bottom: 1px solid #e4e4e7;
    padding-bottom: 8px;
    letter-spacing: -0.015em;
    text-wrap: balance;
  }}
  table {{
    border-collapse: collapse;
    width: 100%;
    margin: 20px 0;
    font-variant-numeric: tabular-nums;
  }}
  th, td {{
    border: 1px solid #e4e4e7;
    padding: 8px 14px;
    text-align: left;
    font-size: 13px;
  }}
  th {{
    background-color: #f4f4f5;
    font-weight: 600;
  }}
  code {{
    background-color: #f1f5f9;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 12px;
    font-family: var(--font-mono);
    border: 1px solid #e4e4e7;
    font-variant-numeric: tabular-nums;
  }}
  pre {{
    background-color: #f8fafc;
    padding: 16px;
    border-radius: 6px;
    overflow-x: auto;
    border: 1px solid #e4e4e7;
    font-family: var(--font-mono);
    font-size: 13px;
    line-height: 1.5;
    font-variant-numeric: tabular-nums;
  }}
  .badge-fixed {{
    background: #ecfdf5;
    color: #047857;
    padding: 3px 8px;
    border-radius: 12px;
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
  }}
  .badge-dynamic {{
    background: #fff1f2;
    color: #be123c;
    padding: 3px 8px;
    border-radius: 12px;
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
  }}
</style>
</head>
<body>
<pre>{md_content}</pre>
</body>
</html>"""
        out.write_text(html, encoding="utf-8")
        return html
