"""Flask Web Server & REST API for the ScanneX Interactive Dashboard."""

import asyncio
import logging
import os
import shutil
import subprocess
import tempfile
import threading
import uuid
import zipfile
from pathlib import Path
from typing import Any, Optional
from flask import Flask, jsonify, render_template, request, send_file
from scannex.benchmark import get_benchmark_dir
from scannex.config import ScannexConfig
from scannex.db.models import Finding
from scannex.db.store import FindingsStore
from scannex.orchestrator.pipeline import PipelineEvent, ScannexOrchestrator
from scannex.reporter.markdown_exporter import MarkdownExporter
from scannex.reporter.sarif_exporter import SarifExporter

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).parent / "templates"
app = Flask(__name__, template_folder=str(TEMPLATE_DIR))

# In-memory session tracking
sessions: dict[str, dict[str, Any]] = {}


def run_scan_async(session_id: str, target_dir: Path, mock_mode: bool, model_name: str) -> None:
    """Run ScanneX orchestrator in a background thread."""
    session = sessions[session_id]
    session["status"] = "running"
    session["events"] = []

    def event_handler(ev: PipelineEvent):
        session["events"].append({
            "stage": ev.stage,
            "message": ev.message,
            "vuln_type": ev.finding.vuln_type if ev.finding else None,
            "title": ev.finding.title if ev.finding else None,
            "status": ev.finding.status.value if ev.finding else None,
        })
        session["current_stage"] = ev.stage

    try:
        config = ScannexConfig.from_env()
        config.mock_mode = mock_mode
        if model_name:
            config.model_name = model_name
        
        # Dedicated SQLite store for this session
        session_db = target_dir / ".scannex_session.db"
        config.db_path = session_db
        store = FindingsStore(session_db)

        orchestrator = ScannexOrchestrator(
            target_dir=target_dir,
            config=config,
            store=store,
            event_callback=event_handler,
        )

        findings = asyncio.run(orchestrator.run())

        session["findings"] = [f.model_dump() for f in findings]
        session["sarif_path"] = str(target_dir / "report.sarif")
        session["markdown_path"] = str(target_dir / "report.md")

        SarifExporter.export(findings, session["sarif_path"])
        MarkdownExporter.export_markdown(findings, session["markdown_path"])

        session["status"] = "completed"
        session["current_stage"] = "COMPLETE"

    except Exception as e:
        logger.error(f"Scan session {session_id} failed: {e}", exc_info=True)
        session["status"] = "failed"
        session["error"] = str(e)


@app.route("/")
def index():
    """Render the ScanneX single-page dashboard."""
    return render_template("index.html")


@app.route("/api/scan/upload", methods=["POST"])
def upload_scan():
    """Accept dropped .zip archive, extract, and begin scan."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    uploaded_file = request.files["file"]
    if not uploaded_file.filename or not uploaded_file.filename.endswith(".zip"):
        return jsonify({"error": "Uploaded file must be a .zip archive"}), 400

    mock_mode = request.form.get("mock", "true").lower() in ("true", "1", "yes")
    model_name = request.form.get("model", "ollama/llama3.2:1b")

    session_id = str(uuid.uuid4())
    temp_dir = Path(tempfile.mkdtemp(prefix=f"scannex_upload_{session_id[:8]}_"))

    try:
        zip_path = temp_dir / "upload.zip"
        uploaded_file.save(str(zip_path))

        extract_dir = temp_dir / "repo"
        extract_dir.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as z:
            # Safe extraction avoiding zip slip
            for member in z.infolist():
                target_path = extract_dir / member.filename
                if not target_path.resolve().is_relative_to(extract_dir.resolve()):
                    raise ValueError(f"Unsafe path in ZIP: {member.filename}")
            z.extractall(extract_dir)

        # If archive had a single enclosing directory, descend into it
        subdirs = [p for p in extract_dir.iterdir() if p.is_dir() and not p.name.startswith(".")]
        final_dir = subdirs[0] if len(subdirs) == 1 else extract_dir

        sessions[session_id] = {
            "id": session_id,
            "target_name": uploaded_file.filename,
            "temp_dir": str(temp_dir),
            "status": "queued",
            "findings": [],
            "events": [],
            "error": None,
        }

        thread = threading.Thread(
            target=run_scan_async,
            args=(session_id, final_dir, mock_mode, model_name),
            daemon=True,
        )
        thread.start()

        return jsonify({"session_id": session_id, "status": "queued"})

    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return jsonify({"error": f"Failed to unpack ZIP archive: {str(e)}"}), 500


@app.route("/api/scan/github", methods=["POST"])
def github_scan():
    """Clone remote GitHub repository and start scan."""
    data = request.get_json(silent=True) or request.form
    repo_url = data.get("url", "").strip()

    if not repo_url or ("github.com" not in repo_url):
        return jsonify({"error": "Valid GitHub URL required (e.g. https://github.com/owner/repo)"}), 400

    mock_mode = str(data.get("mock", "true")).lower() in ("true", "1", "yes")
    model_name = data.get("model", "ollama/llama3.2:1b")

    session_id = str(uuid.uuid4())
    temp_dir = Path(tempfile.mkdtemp(prefix=f"scannex_git_{session_id[:8]}_"))
    clone_dir = temp_dir / "repo"

    try:
        cmd = ["git", "clone", "--depth", "1", repo_url, str(clone_dir)]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if res.returncode != 0:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return jsonify({"error": f"Git clone failed: {res.stderr}"}), 400

        repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        sessions[session_id] = {
            "id": session_id,
            "target_name": repo_name,
            "temp_dir": str(temp_dir),
            "status": "queued",
            "findings": [],
            "events": [],
            "error": None,
        }

        thread = threading.Thread(
            target=run_scan_async,
            args=(session_id, clone_dir, mock_mode, model_name),
            daemon=True,
        )
        thread.start()

        return jsonify({"session_id": session_id, "status": "queued"})

    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return jsonify({"error": f"GitHub clone failed: {str(e)}"}), 500


@app.route("/api/scan/demo", methods=["POST"])
def demo_scan():
    """Run retrospective verification on bundled benchmark vulnerable app."""
    session_id = str(uuid.uuid4())
    benchmark_dir = get_benchmark_dir()

    data = request.get_json(silent=True) or request.form
    mock_mode = str(data.get("mock", "true")).lower() in ("true", "1", "yes")
    model_name = data.get("model", "ollama/llama3.2:1b")

    temp_dir = Path(tempfile.mkdtemp(prefix="scannex_demo_"))
    shutil.copytree(benchmark_dir, temp_dir, dirs_exist_ok=True)

    sessions[session_id] = {
        "id": session_id,
        "target_name": "vulnerable_flask_app (Pre-Patch Benchmark)",
        "temp_dir": str(temp_dir),
        "status": "queued",
        "findings": [],
        "events": [],
        "error": None,
    }

    thread = threading.Thread(
        target=run_scan_async,
        args=(session_id, temp_dir, mock_mode, model_name),
        daemon=True,
    )
    thread.start()

    return jsonify({"session_id": session_id, "status": "queued"})


@app.route("/api/scan/<session_id>/status", methods=["GET"])
def scan_status(session_id: str):
    """Retrieve session progress, events, and results."""
    session = sessions.get(session_id)
    if not session:
        return jsonify({"error": "Session not found"}), 404

    return jsonify({
        "id": session["id"],
        "target_name": session.get("target_name"),
        "status": session["status"],
        "current_stage": session.get("current_stage", "QUEUED"),
        "events": session["events"],
        "findings": session["findings"],
        "error": session["error"],
    })


@app.route("/api/scan/<session_id>/sarif", methods=["GET"])
def download_sarif(session_id: str):
    """Download standard SARIF 2.1.0 file."""
    session = sessions.get(session_id)
    if not session or not session.get("sarif_path"):
        return jsonify({"error": "Report not ready"}), 404
    return send_file(session["sarif_path"], as_attachment=True, download_name="scannex-report.sarif")


@app.route("/api/scan/<session_id>/markdown", methods=["GET"])
def download_markdown(session_id: str):
    """Download Markdown summary report."""
    session = sessions.get(session_id)
    if not session or not session.get("markdown_path"):
        return jsonify({"error": "Report not ready"}), 404
    return send_file(session["markdown_path"], as_attachment=True, download_name="scannex-report.md")


def run_web_dashboard(host: str = "127.0.0.1", port: int = 8080, debug: bool = False) -> None:
    """Launch the ScanneX web dashboard server."""
    print(f"\n[ScanneX Dashboard] Starting web interface at http://{host}:{port}/")
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_web_dashboard()
