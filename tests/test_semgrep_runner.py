"""Tests for Semgrep SAST analyzer integration."""

import tempfile
from pathlib import Path
import pytest

from scannex.db.models import CanaryType, FindingStatus, Severity
from scannex.scanner.route_mapper import RouteMapper
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


def test_semgrep_default_configs_includes_javascript():
    """Verify DEFAULT_CONFIGS includes dedicated JavaScript rule pack."""
    assert "p/javascript" in SemgrepRunner.DEFAULT_CONFIGS
    assert "p/php" in SemgrepRunner.DEFAULT_CONFIGS
    assert "p/owasp-top-ten" in SemgrepRunner.DEFAULT_CONFIGS
    assert "p/security-audit" in SemgrepRunner.DEFAULT_CONFIGS


def test_semgrep_parse_item_javascript_command_injection():
    """Verify parsing and classification of JavaScript child_process command injection."""
    with tempfile.TemporaryDirectory() as tmp:
        target_dir = Path(tmp)
        test_file = target_dir / "server.js"
        test_file.write_text("const { exec } = require('child_process');\napp.get('/exec', (req, res) => { exec(req.query.cmd); });\n", encoding="utf-8")

        runner = SemgrepRunner(target_dir)
        mock_item = {
            "check_id": "javascript.lang.security.detect-child-process.detect-child-process",
            "path": "server.js",
            "start": {"line": 2, "col": 35},
            "end": {"line": 2, "col": 55},
            "extra": {
                "message": "Detected calls to child_process with untrusted command execution",
                "severity": "ERROR",
                "metadata": {
                    "cwe": ["CWE-78: OS Command Injection"],
                    "vulnerability_class": ["Command Injection"],
                },
            },
        }

        finding = runner._parse_semgrep_item(mock_item)
        assert finding is not None
        assert finding.file_path == "server.js"
        assert finding.vuln_type == "COMMAND_INJECTION"
        assert finding.cwe == "CWE-78"
        assert finding.severity == Severity.HIGH
        # Check Express route mapping & canary file marker synthesis
        assert finding.probe_spec is not None
        assert finding.probe_spec.endpoint == "/exec"
        assert finding.probe_spec.canary_type == CanaryType.FILE_MARKER
        assert finding.probe_spec.file_marker_path is not None
        assert "/tmp/canary_" in finding.probe_spec.file_marker_path


def test_semgrep_parse_item_javascript_xss():
    """Verify parsing and classification of DOM XSS in React/JSX."""
    with tempfile.TemporaryDirectory() as tmp:
        target_dir = Path(tmp)
        test_file = target_dir / "Component.jsx"
        test_file.write_text("<div dangerouslySetInnerHTML={{ __html: userHtml }} />\n", encoding="utf-8")

        runner = SemgrepRunner(target_dir)
        mock_item = {
            "check_id": "javascript.browser.security.dom-xss",
            "path": "Component.jsx",
            "start": {"line": 1, "col": 1},
            "end": {"line": 1, "col": 50},
            "extra": {
                "message": "Detected unescaped HTML content insertion susceptible to cross-site scripting",
                "severity": "WARNING",
                "metadata": {
                    "cwe": ["CWE-79: Cross-site Scripting"],
                    "vulnerability_class": ["Cross-site Scripting"],
                },
            },
        }

        finding = runner._parse_semgrep_item(mock_item)
        assert finding is not None
        assert finding.vuln_type == "XSS"
        assert finding.cwe == "CWE-79"
        assert finding.severity == Severity.MEDIUM


def test_route_mapper_express_routes():
    """Verify RouteMapper extracts endpoints, methods, and parameters from Express code."""
    with tempfile.TemporaryDirectory() as tmp:
        target_dir = Path(tmp)
        js_file = target_dir / "routes.js"
        js_file.write_text("""
const express = require('express');
const app = express();

app.get('/api/users/:userId', (req, res) => {
    const action = req.query.action;
    res.json({ user: req.params.userId });
});

router.post('/login', (req, res) => {
    const { username, password } = req.body;
    res.send('ok');
});
""", encoding="utf-8")

        mapper = RouteMapper(target_dir)
        routes = mapper.scan_file(js_file)
        assert len(routes) == 2

        # Route 1: GET /api/users/:userId
        r1 = mapper.find_route_for_line(js_file, 5)
        assert r1 is not None
        assert r1.endpoint == "/api/users/:userId"
        assert "GET" in r1.methods
        assert "userId" in r1.param_names
        assert "action" in r1.param_names

        # Route 2: POST /login
        r2 = mapper.find_route_for_line(js_file, 11)
        assert r2 is not None
        assert r2.endpoint == "/login"
        assert "POST" in r2.methods
        assert "username" in r2.param_names


@pytest.mark.asyncio
async def test_pipeline_separate_semgrep_and_bandit_events():
    """Verify orchestrator pipeline emits separated SEMGREP_SCAN and BANDIT_SCAN events."""
    from scannex.orchestrator.pipeline import ScannexOrchestrator
    from scannex.config import ScannexConfig
    from scannex.db.store import FindingsStore

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        target_dir = Path(tmp)
        (target_dir / "app.py").write_text("import os\nos.system('ls')\n", encoding="utf-8")

        events = []
        config = ScannexConfig(mock_mode=True, db_path=target_dir / "findings.db")
        store = FindingsStore(config.db_path)
        orchestrator = ScannexOrchestrator(
            target_dir=target_dir,
            config=config,
            store=store,
            event_callback=lambda ev: events.append(ev),
        )
        await orchestrator.run()

        stages = [e.stage for e in events]
        assert "SEMGREP_SCAN" in stages
        assert "BANDIT_SCAN" in stages
        static_event = next(e for e in events if e.stage == "STATIC_SCAN" and "complete" in e.message.lower())
        assert static_event.metadata is not None
        assert "semgrep_count" in static_event.metadata
        assert "bandit_count" in static_event.metadata
