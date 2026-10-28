"""Tests for Semgrep SAST analyzer integration."""

import tempfile
from pathlib import Path
import pytest

from scannex.db.models import FindingStatus, Severity
from scannex.scanner.semgrep_runner import SemgrepRunner


def test_semgrep_is_available():
    """Verify that Semgrep is detected as available (via Docker or native CLI)."""
    with tempfile.TemporaryDirectory() as tmp:
        runner = SemgrepRunner(tmp)
        assert runner.is_available() is True


def test_semgrep_parse_item_container_path():
    """Verify path normalization when results return container /src paths."""
    with tempfile.TemporaryDirectory() as tmp:
        target_dir = Path(tmp)
        test_file = target_dir / "vuln.php"
        test_file.write_text("<?php system($_GET['cmd']); ?>\n", encoding="utf-8")

        runner = SemgrepRunner(target_dir)
        mock_item = {
            "check_id": "php.lang.security.injection.tainted-exec",
            "path": "/src/vuln.php",
            "start": {"line": 1, "col": 1},
            "end": {"line": 1, "col": 30},
            "extra": {
                "message": "User input flows into system execution",
                "severity": "ERROR",
                "metadata": {
                    "cwe": ["CWE-78: Improper Neutralization of Special Elements used in an OS Command"],
                    "vulnerability_class": ["Command Injection"],
                },
            },
        }

        finding = runner._parse_semgrep_item(mock_item)
        assert finding is not None
        assert finding.file_path == "vuln.php"
        assert finding.line_number == 1
        assert finding.vuln_type == "COMMAND_INJECTION"
        assert finding.cwe == "CWE-78"
        assert finding.severity == Severity.HIGH
        assert finding.source == "static_semgrep"
        assert finding.status == FindingStatus.CONFIRMED_STATIC
        assert "system($_GET['cmd'])" in finding.sink_code


def test_semgrep_parse_item_sqli():
    """Verify SQL injection classification from rule metadata."""
    with tempfile.TemporaryDirectory() as tmp:
        target_dir = Path(tmp)
        test_file = target_dir / "db.py"
        test_file.write_text("cur.execute(f'SELECT * FROM users WHERE id = {user_id}')\n", encoding="utf-8")

        runner = SemgrepRunner(target_dir)
        mock_item = {
            "check_id": "python.flask.security.injection.tainted-sql-string",
            "path": str(test_file),
            "start": {"line": 1, "col": 1},
            "end": {"line": 1, "col": 50},
            "extra": {
                "message": "Detected user input used to construct SQL query",
                "severity": "WARNING",
                "metadata": {
                    "cwe": ["CWE-89: SQL Injection"],
                    "vulnerability_class": ["SQL Injection"],
                },
            },
        }

        finding = runner._parse_semgrep_item(mock_item)
        assert finding is not None
        assert finding.vuln_type == "SQL_INJECTION"
        assert finding.cwe == "CWE-89"
        assert finding.severity == Severity.MEDIUM
        assert "cur.execute" in finding.sink_code


def test_semgrep_parse_item_ssti():
    """Verify SSTI classification for template injection."""
    with tempfile.TemporaryDirectory() as tmp:
        target_dir = Path(tmp)
        test_file = target_dir / "render.py"
        test_file.write_text("render_template_string(template)\n", encoding="utf-8")

        runner = SemgrepRunner(target_dir)
        mock_item = {
            "check_id": "python.flask.security.dangerous-template-string",
            "path": str(test_file),
            "start": {"line": 1, "col": 1},
            "end": {"line": 1, "col": 30},
            "extra": {
                "message": "Template created with string formatting is susceptible to server-side template injection and cross-site scripting attacks.",
                "severity": "ERROR",
                "metadata": {
                    "cwe": ["CWE-96: Static Code Injection"],
                },
            },
        }

        finding = runner._parse_semgrep_item(mock_item)
        assert finding is not None
        assert finding.vuln_type == "SSTI"
        assert finding.cwe == "CWE-94"


def test_semgrep_live_scan_test_target():
    """Verify live Semgrep scan against test_target finds genuine vulnerabilities."""
    runner = SemgrepRunner("test_target")
    assert runner.is_available() is True
    findings = runner.run()
    assert len(findings) >= 3

    vuln_types = {f.vuln_type for f in findings}
    assert "SQL_INJECTION" in vuln_types or "COMMAND_INJECTION" in vuln_types or "SSTI" in vuln_types
    for f in findings:
        assert f.source == "static_semgrep"
        assert f.status == FindingStatus.CONFIRMED_STATIC
        assert len(f.sink_code) > 0
