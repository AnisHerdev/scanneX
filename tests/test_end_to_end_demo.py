"""End-to-end integration tests for ScanneX demo and SARIF export."""

import json
from pathlib import Path
import pytest
from scannex.benchmark import get_benchmark_dir
from scannex.config import ScannexConfig
from scannex.db.models import FindingStatus
from scannex.db.store import FindingsStore
from scannex.orchestrator.pipeline import ScannexOrchestrator
from scannex.reporter.markdown_exporter import MarkdownExporter
from scannex.reporter.sarif_exporter import SarifExporter


@pytest.mark.asyncio
async def test_end_to_end_benchmark_scan(tmp_path):
    benchmark_dir = get_benchmark_dir()
    assert benchmark_dir.exists()

    db_path = tmp_path / "test_findings.db"
    config = ScannexConfig(
        mock_mode=True,
        db_path=db_path,
        max_concurrency=2,
    )
    store = FindingsStore(db_path)

    events = []
    orchestrator = ScannexOrchestrator(
        target_dir=benchmark_dir,
        config=config,
        store=store,
        event_callback=lambda ev: events.append(ev),
    )

    findings = await orchestrator.run()

    # Verify findings were produced
    assert len(findings) > 0

    # Check for at least one dynamically verified/fixed vulnerability
    statuses = {f.status for f in findings}
    assert (FindingStatus.VERIFIED_FIXED in statuses) or (FindingStatus.CONFIRMED_DYNAMIC in statuses)

    # Test SARIF export
    sarif_path = tmp_path / "report.sarif"
    sarif_str = SarifExporter.export(findings, sarif_path)
    assert sarif_path.exists()
    sarif_data = json.loads(sarif_str)
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"][0]["results"]) == len(findings)

    # Test Markdown export
    md_path = tmp_path / "report.md"
    md_str = MarkdownExporter.export_markdown(findings, md_path)
    assert md_path.exists()
    assert "ScanneX Security Audit Report" in md_str

    # Test HTML export
    html_path = tmp_path / "report.html"
    html_str = MarkdownExporter.export_html(findings, html_path)
    assert html_path.exists()
    assert "<!DOCTYPE html>" in html_str
