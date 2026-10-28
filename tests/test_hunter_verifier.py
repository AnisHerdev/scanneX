"""Tests for AI Hunter, Adversarial Verifier, and Speculative Patcher."""

import pytest
from scannex.agents.hunter import HunterAgent
from scannex.agents.patcher import SpeculativePatchAgent
from scannex.agents.verifier import VerifierAgent
from scannex.config import ScannexConfig
from scannex.db.models import Finding, FindingStatus, Severity


@pytest.mark.asyncio
async def test_hunter_detects_flaw_in_mock_mode(tmp_path):
    config = ScannexConfig(mock_mode=True)
    
    # Create sample vulnerable file
    app_file = tmp_path / "app.py"
    app_file.write_text("""
from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route('/render')
def render():
    name = request.args.get('name', 'guest')
    template = f"Hello {name}"
    return render_template_string(template)
""", encoding="utf-8")

    hunter = HunterAgent(tmp_path, config=config)
    findings = await hunter.hunt([app_file])

    assert len(findings) >= 1
    f = findings[0]
    assert f.vuln_type == "SSTI"
    assert f.probe_spec is not None
    assert f.probe_spec.endpoint == "/render"
    assert f.probe_spec.canary_token is not None
    assert len(f.probe_spec.canary_token) > 0


@pytest.mark.asyncio
async def test_verifier_adversarial_rejection(tmp_path):
    config = ScannexConfig(mock_mode=True)
    
    # File with sanitization present
    app_file = tmp_path / "safe.py"
    app_file.write_text("""
import shlex, os
def ping(host):
    safe_host = shlex.quote(host)
    os.system(f"ping {safe_host}")
""", encoding="utf-8")

    finding = Finding(
        file_path="safe.py",
        line_number=4,
        vuln_type="COMMAND_INJECTION",
        title="Unsanitized host in ping",
        description="os.system call with user host",
        sink_code="os.system(f'ping {safe_host}')",
        status=FindingStatus.NEEDS_VALIDATION,
    )

    verifier = VerifierAgent(tmp_path, config=config)
    result = await verifier.verify(finding)

    assert result.up_approved is False
    assert finding.status == FindingStatus.REJECTED
    assert "sanitization" in finding.verifier_notes.lower()


@pytest.mark.asyncio
async def test_speculative_patcher_remediation(tmp_path):
    config = ScannexConfig(mock_mode=True)
    
    original_code = """import sqlite3
def get_user(username):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchone()
"""
    app_file = tmp_path / "db_ops.py"
    app_file.write_text(original_code, encoding="utf-8")

    finding = Finding(
        file_path="db_ops.py",
        line_number=5,
        vuln_type="SQL_INJECTION",
        title="SQL Injection in user lookup",
        description="Raw string query formatting",
        sink_code="cursor.execute(f\"SELECT * FROM users WHERE username = '{username}'\")",
    )

    patcher = SpeculativePatchAgent(tmp_path, config=config)
    patch = await patcher.generate_patch(finding)

    assert patch.search_block != ""
    assert patch.replace_block != ""
    assert "%s" in patch.replace_block or "username" in patch.replace_block

    # Test applying patch
    patched_code, success = patcher.apply_patch_to_text(original_code, patch)
    assert success is True
    assert "%s" in patched_code
    assert "{username}'" not in patched_code
