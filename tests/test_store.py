"""Unit tests for FindingsStore and models."""

import pytest
from scannex.db.models import (
    CanaryType,
    Finding,
    FindingStatus,
    PatchSpec,
    ProbeResult,
    ProbeSpec,
    Severity,
)
from scannex.db.store import FindingsStore


def test_create_and_retrieve_finding():
    store = FindingsStore(":memory:")
    
    finding = Finding(
        file_path="app/routes.py",
        line_number=42,
        vuln_type="SQL_INJECTION",
        cwe="CWE-89",
        severity=Severity.HIGH,
        title="Unsanitized user input in raw SQL query",
        description="User query parameter injected directly into raw SQL string",
        sink_code="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        source="static_bandit",
        status=FindingStatus.NEEDS_VALIDATION,
    )
    finding.add_trace("Detected by Bandit scanner")
    
    store.save_finding(finding)
    
    retrieved = store.get_finding(finding.id)
    assert retrieved is not None
    assert retrieved.file_path == "app/routes.py"
    assert retrieved.line_number == 42
    assert retrieved.vuln_type == "SQL_INJECTION"
    assert retrieved.status == FindingStatus.NEEDS_VALIDATION
    assert len(retrieved.evidence_trace) == 1
    assert "Bandit scanner" in retrieved.evidence_trace[0]


def test_update_finding_lifecycle():
    store = FindingsStore(":memory:")
    
    finding = Finding(
        file_path="app/views.py",
        line_number=10,
        vuln_type="COMMAND_INJECTION",
        cwe="CWE-78",
        severity=Severity.CRITICAL,
        title="Command injection via subprocess",
        description="os.system called with untrusted host",
        source="ai_hunter",
        status=FindingStatus.NEEDS_VALIDATION,
    )
    store.save_finding(finding)
    
    # Update with probe spec and patch
    finding.status = FindingStatus.CONFIRMED_DYNAMIC
    finding.probe_spec = ProbeSpec(
        endpoint="/ping",
        method="POST",
        data={"host": "127.0.0.1; echo SCANX_CANARY_TEST"},
        canary_type=CanaryType.REFLECTED,
        canary_token="SCANX_CANARY_TEST",
    )
    finding.probe_result = ProbeResult(
        success=True,
        canary_tripped=True,
        status_code=200,
        response_snippet="SCANX_CANARY_TEST found in response",
    )
    finding.patch_spec = PatchSpec(
        file_path="app/views.py",
        search_block="os.system(f'ping {host}')",
        replace_block="subprocess.run(['ping', host], check=True)",
        applied_successfully=True,
        retest_verified=True,
    )
    finding.status = FindingStatus.VERIFIED_FIXED
    finding.add_trace("Dynamic probe confirmed exploitability")
    finding.add_trace("Speculative patch applied and verified fixed")
    
    store.save_finding(finding)
    
    updated = store.get_finding(finding.id)
    assert updated is not None
    assert updated.status == FindingStatus.VERIFIED_FIXED
    assert updated.probe_spec.canary_token == "SCANX_CANARY_TEST"
    assert updated.probe_result.canary_tripped is True
    assert updated.patch_spec.retest_verified is True
    assert len(updated.evidence_trace) == 2


def test_store_summary_and_filtering():
    store = FindingsStore(":memory:")
    
    f1 = Finding(
        file_path="app/a.py",
        line_number=1,
        vuln_type="SQL_INJECTION",
        severity=Severity.CRITICAL,
        title="SQLi",
        description="desc",
        status=FindingStatus.CONFIRMED_DYNAMIC,
    )
    f2 = Finding(
        file_path="app/b.py",
        line_number=5,
        vuln_type="XSS",
        severity=Severity.MEDIUM,
        title="XSS",
        description="desc",
        status=FindingStatus.REJECTED,
    )
    f3 = Finding(
        file_path="app/c.py",
        line_number=9,
        vuln_type="SSTI",
        severity=Severity.HIGH,
        title="SSTI",
        description="desc",
        status=FindingStatus.VERIFIED_FIXED,
    )
    
    store.save_finding(f1)
    store.save_finding(f2)
    store.save_finding(f3)
    
    assert len(store.list_findings()) == 3
    assert len(store.list_findings(FindingStatus.CONFIRMED_DYNAMIC)) == 1
    assert len(store.list_findings(FindingStatus.REJECTED)) == 1
    
    summary = store.get_summary()
    assert summary["total"] == 3
    assert summary["by_status"][FindingStatus.CONFIRMED_DYNAMIC.value] == 1
    assert summary["by_status"][FindingStatus.REJECTED.value] == 1
    assert summary["by_status"][FindingStatus.VERIFIED_FIXED.value] == 1
    assert summary["by_severity"][Severity.CRITICAL.value] == 1
