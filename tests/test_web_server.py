"""Tests for the ScanneX web dashboard server and REST API."""

import io
import time
import zipfile
from pathlib import Path
import pytest
from scannex.web.server import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_index_dashboard_serves_html(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"ScanneX" in res.data
    assert b"Drop source code .ZIP" in res.data
    assert b"GitHub Repository" in res.data


def test_demo_scan_endpoint(client):
    res = client.post("/api/scan/demo", json={"mock": True})
    assert res.status_code == 200
    data = res.get_json()
    assert "session_id" in data
    assert data["status"] == "queued"

    session_id = data["session_id"]
    time.sleep(1)

    status_res = client.get(f"/api/scan/{session_id}/status")
    assert status_res.status_code == 200
    status_data = status_res.get_json()
    assert status_data["id"] == session_id
    assert status_data["status"] in ("queued", "running", "completed")


def test_upload_invalid_file(client):
    res = client.post("/api/scan/upload", data={"file": (io.BytesIO(b"not a zip"), "test.txt")})
    assert res.status_code == 400
    assert "must be a .zip" in res.get_json()["error"]


def test_upload_valid_zip(client):
    # Create in-memory zip containing a minimal app.py
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as z:
        z.writestr("app.py", "from flask import Flask\napp = Flask(__name__)\n")
    zip_buffer.seek(0)

    res = client.post(
        "/api/scan/upload",
        data={"file": (zip_buffer, "test_repo.zip"), "mock": "true"},
        content_type="multipart/form-data",
    )
    assert res.status_code == 200
    data = res.get_json()
    assert "session_id" in data


def test_upload_and_scan_vulnerable_zip_with_pycache(client):
    """Ensure a zip archive with flat files and __pycache__ properly discovers vulnerabilities and events."""
    bench_app = Path("scannex/benchmark/vulnerable_flask_app/app.py")
    assert bench_app.is_file()

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as z:
        z.write(bench_app, "app.py")
        z.writestr("__pycache__/app.cpython-311.pyc", "mock-bytecode")
    zip_buffer.seek(0)

    res = client.post(
        "/api/scan/upload",
        data={"file": (zip_buffer, "vuln_with_cache.zip"), "mock": "true"},
        content_type="multipart/form-data",
    )
    assert res.status_code == 200
    session_id = res.get_json()["session_id"]

    # Poll status until completed or timed out
    completed = False
    for _ in range(50):
        time.sleep(1)
        status_res = client.get(f"/api/scan/{session_id}/status")
        data = status_res.get_json()
        if data["status"] in ("completed", "failed"):
            completed = True
            assert data["status"] == "completed"
            assert len(data["findings"]) > 0
            # Ensure EXTRACT event is in events
            stages = [ev["stage"] for ev in data["events"]]
            assert "EXTRACT" in stages
            assert "INIT" in stages
            break
    assert completed, "Scan session did not complete in time"


def test_list_ollama_models(client):
    res = client.get("/api/ollama/models")
    assert res.status_code == 200
    data = res.get_json()
    assert "available" in data
    assert "models" in data
    assert isinstance(data["models"], list)


def test_index_contains_checklist_options(client):
    """Ensure the dashboard HTML includes manual checklist options for static analyzers."""
    res = client.get("/")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Static Analyzers &amp; Rule Packs" in html or "Static Analyzers & Rule Packs" in html
    assert "rule-owasp" in html
    assert "rule-php" in html
    assert "rule-security-audit" in html
    assert "rule-javascript" in html
    assert "count-semgrep" in html
    assert "count-bandit" in html
    assert "rule-bandit" in html
    assert "rule-workflows" in html


def test_demo_scan_with_custom_rule_checklist(client):
    """Ensure demo endpoint accepts customized semgrep_configs and scanner flags."""
    res = client.post(
        "/api/scan/demo",
        json={
            "mock": True,
            "semgrep_configs": ["p/php", "p/owasp-top-ten"],
            "enable_bandit": False,
            "scan_workflows": True,
        },
    )
    assert res.status_code == 200
    data = res.get_json()
    assert "session_id" in data
    assert data["status"] == "queued"


def test_upload_with_custom_rule_checklist(client):
    """Ensure upload endpoint parses semgrep_configs and flags from multipart form data."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as z:
        z.writestr("index.php", "<?php echo $_GET['user']; ?>")
    zip_buffer.seek(0)

    res = client.post(
        "/api/scan/upload",
        data={
            "file": (zip_buffer, "php_sample.zip"),
            "mock": "true",
            "semgrep_configs": '["p/php", "p/owasp-top-ten"]',
            "enable_bandit": "false",
            "scan_workflows": "false",
        },
        content_type="multipart/form-data",
    )
    assert res.status_code == 200
    data = res.get_json()
    assert "session_id" in data
    assert data["status"] == "queued"



def test_upload_and_scan_eicar_zip_detects_malware(client):
    """Ensure a ZIP containing eicar.com is properly flagged as MALWARE / CWE-506 in the web upload."""
    import zipfile
    from scannex.scanner.malware_runner import EICAR_EXACT_BYTES

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as z:
        z.writestr("eicar.com", EICAR_EXACT_BYTES)
    zip_buffer.seek(0)

    res = client.post(
        "/api/scan/upload",
        data={"file": (zip_buffer, "eicar_test.zip"), "mock": "true"},
        content_type="multipart/form-data",
    )
    assert res.status_code == 200
    session_id = res.get_json()["session_id"]

    completed = False
    for _ in range(30):
        time.sleep(0.5)
        status_res = client.get(f"/api/scan/{session_id}/status")
        data = status_res.get_json()
        if data["status"] in ("completed", "failed"):
            completed = True
            assert data["status"] == "completed"
            assert len(data["findings"]) == 1
            finding = data["findings"][0]
            assert finding["vuln_type"] == "MALWARE"
            assert finding["cwe"] == "CWE-506"
            assert finding["status"] == "confirmed_static"
            break
    assert completed, "Scan session did not complete in time"


def test_dashboard_log_contrast_tokens_and_classes(client):
    """Ensure the event-log console uses high-contrast terminal tokens and dedicated classes."""
    res = client.get("/")
    assert res.status_code == 200
    html = res.data.decode("utf-8")

    # High-contrast terminal design tokens in light & dark modes
    assert "--terminal-bg" in html
    assert "--terminal-text" in html
    assert "--terminal-stage" in html
    assert "--terminal-border" in html

    # Terminal event log container and entry classes
    assert ".event-log {" in html
    assert "color: var(--terminal-text);" in html
    assert ".event-stage {" in html
    assert "color: var(--terminal-stage);" in html
    assert ".event-canary" in html
    assert ".event-fixed" in html
    assert ".event-error" in html
    assert ".event-extract" in html
    assert ".event-semgrep" in html
    assert ".event-bandit" in html
    assert ".event-malware" in html

def test_dashboard_mitigation_elements(client):
    """Ensure dashboard table and drawer render mitigation guidance elements."""
    res = client.get("/")
    assert res.status_code == 200
    html = res.data.decode("utf-8")

    assert "Mitigation Measure" in html
    assert "Remediation &amp; Mitigation Guidance (For QA Testers &amp; Devs)" in html
    assert "mitigationText" in html
