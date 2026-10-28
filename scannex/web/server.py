"""Flask Web Server & REST API for the ScanneX Interactive Dashboard."""

import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
import threading
import uuid
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
from scannex.scanner.archive_extractor import extract_zip_archive

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).parent / "templates"
app = Flask(__name__, template_folder=str(TEMPLATE_DIR))
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.auto_reload = True

# In-memory session tracking
sessions: dict[str, dict[str, Any]] = {}


def parse_scanner_options(data_or_form: Any) -> tuple[list[str], bool, bool]:
    """Extract checklist configurations for Semgrep and Bandit from request form or JSON."""
    semgrep_configs = ["p/owasp-top-ten", "p/security-audit", "p/php"]
    enable_bandit = True
    scan_workflows = False

    raw_configs = None
    if hasattr(data_or_form, "getlist") and data_or_form.getlist("semgrep_configs"):
        raw_list = data_or_form.getlist("semgrep_configs")
        if len(raw_list) == 1 and raw_list[0].startswith("["):
            try:
                raw_configs = json.loads(raw_list[0])
            except Exception:
                raw_configs = [s.strip() for s in raw_list[0].split(",") if s.strip()]
        else:
            raw_configs = raw_list
    elif isinstance(data_or_form, dict) and "semgrep_configs" in data_or_form:
        val = data_or_form["semgrep_configs"]
        if isinstance(val, list):
            raw_configs = val
        elif isinstance(val, str):
            try:
                raw_configs = json.loads(val)
            except Exception:
                raw_configs = [s.strip() for s in val.split(",") if s.strip()]
    elif hasattr(data_or_form, "get") and data_or_form.get("semgrep_configs"):
        val = data_or_form.get("semgrep_configs")
        try:
            raw_configs = json.loads(val)
        except Exception:
            raw_configs = [s.strip() for s in val.split(",") if s.strip()]

    if raw_configs is not None:
        semgrep_configs = [str(c) for c in raw_configs]

    raw_bandit = None
    if hasattr(data_or_form, "get"):
        raw_bandit = data_or_form.get("enable_bandit")
    elif isinstance(data_or_form, dict):
        raw_bandit = data_or_form.get("enable_bandit")
    if raw_bandit is not None:
        enable_bandit = str(raw_bandit).lower() in ("true", "1", "yes")

    raw_workflows = None
    if hasattr(data_or_form, "get"):
        raw_workflows = data_or_form.get("scan_workflows")
    elif isinstance(data_or_form, dict):
        raw_workflows = data_or_form.get("scan_workflows")
    if raw_workflows is not None:
        scan_workflows = str(raw_workflows).lower() in ("true", "1", "yes")

    return semgrep_configs, enable_bandit, scan_workflows


def get_source_summary(target_dir: Path) -> tuple[int, str]:
    """Count source files across supported languages and provide a human summary."""
    src_exts = {".py", ".php", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rb", ".c", ".cpp"}
    files = [p for p in target_dir.rglob("*") if p.is_file() and p.suffix.lower() in src_exts]
    total = len(files)
    if total == 0:
        all_artifacts = [
            p for p in target_dir.rglob("*")
            if p.is_file() and not any(part in {"__pycache__", ".git", ".venv", "node_modules"} for part in p.parts)
        ]
        if all_artifacts:
            return 0, f"0 source files ({len(all_artifacts)} artifacts/binaries)"
        return 0, "0 source files" 

    php_count = sum(1 for p in files if p.suffix.lower() == ".php")
    py_count = sum(1 for p in files if p.suffix.lower() == ".py")
    js_count = sum(1 for p in files if p.suffix.lower() in {".js", ".jsx", ".ts", ".tsx"})

    parts = []
    if php_count:
        parts.append(f"{php_count} PHP")
    if py_count:
        parts.append(f"{py_count} Python")
    if js_count:
        parts.append(f"{js_count} JS/TS")
    other = total - php_count - py_count - js_count
    if other > 0:
        parts.append(f"{other} other")

    summary = f"{total} source files ({', '.join(parts)})" if parts else f"{total} source files"
    return total, summary


def run_scan_async(
    session_id: str,
    target_dir: Path,
    mock_mode: bool,
    model_name: str,
    docker_only: bool = False,
    semgrep_configs: list[str] | None = None,
    enable_bandit: bool = True,
    scan_workflows: bool = False,
) -> None:
    """Run ScanneX orchestrator in a background thread."""
    session = sessions[session_id]
    session["status"] = "running"
    session.setdefault("events", [])
    session["active_sandboxes"] = []

    def event_handler(ev: PipelineEvent):
        if ev.metadata and ev.metadata.get("action") == "created":
            sb_entry = {
                "id": ev.metadata.get("sandbox_id"),
                "type": ev.metadata.get("sandbox_type", "docker"),
                "container_id": ev.metadata.get("container_id"),
                "pid": ev.metadata.get("pid"),
                "port": ev.metadata.get("port"),
                "vuln_type": ev.finding.vuln_type if ev.finding else None,
            }
            session["active_sandboxes"] = [
                s for s in session.get("active_sandboxes", []) if s["id"] != sb_entry["id"]
            ] + [sb_entry]
        elif ev.metadata and ev.metadata.get("action") == "deleted":
            target_id = ev.metadata.get("sandbox_id")
            session["active_sandboxes"] = [
                s for s in session.get("active_sandboxes", []) if s["id"] != target_id
            ]

        session["events"].append({
            "stage": ev.stage,
            "message": ev.message,
            "vuln_type": ev.finding.vuln_type if ev.finding else None,
            "title": ev.finding.title if ev.finding else None,
            "status": ev.finding.status.value if ev.finding else None,
        })
        session["current_stage"] = ev.stage
        print(f"[{session_id[:8]}] [{ev.stage}] {ev.message}")

    try:
        config = ScannexConfig.from_env()
        config.mock_mode = mock_mode
        config.docker_only = docker_only
        if model_name:
            config.model_name = model_name
        if semgrep_configs is not None:
            config.semgrep_configs = semgrep_configs
        config.enable_bandit = enable_bandit
        config.scan_workflows = scan_workflows
        
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
        print(f"[{session_id[:8]}] [COMPLETE] Scan finished with {len(findings)} findings.")

    except Exception as e:
        logger.error(f"Scan session {session_id} failed: {e}", exc_info=True)
        print(f"[{session_id[:8]}] [ERROR] Scan session failed: {e}")
        session["status"] = "failed"
        session["error"] = str(e)
        session["current_stage"] = "FAILED"
        session["events"].append({
            "stage": "FAILED",
            "message": f"Scan failed: {str(e)}",
            "vuln_type": None,
            "title": None,
            "status": None,
        })


@app.after_request
def add_cache_headers(response):
    """Prevent aggressive browser caching during local development."""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route("/")
def index():
    """Render the ScanneX single-page dashboard."""
    return render_template("index.html")


@app.route("/api/ollama/models", methods=["GET"])
def list_ollama_models():
    """Discover locally installed Ollama models dynamically."""
    import urllib.request
    import json

    ollama_base = os.getenv("OLLAMA_API_BASE", "http://127.0.0.1:11434").rstrip("/")
    tags_url = f"{ollama_base}/api/tags"

    try:
        req = urllib.request.Request(tags_url, headers={"User-Agent": "ScanneX/1.0"})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                models = []
                for m in data.get("models", []):
                    name = m.get("name", "")
                    details = m.get("details", {}) or {}
                    param_size = details.get("parameter_size", "")
                    quant = details.get("quantization_level", "")
                    size_bytes = m.get("size", 0)

                    label = name
                    if param_size:
                        label += f" ({param_size})"
                    elif size_bytes:
                        mb = size_bytes / (1024 * 1024)
                        if mb >= 1024:
                            label += f" ({mb/1024:.1f} GB)"
                        else:
                            label += f" ({int(mb)} MB)"

                    models.append({
                        "name": name,
                        "model_id": f"ollama/{name}",
                        "label": label,
                        "parameter_size": param_size,
                        "quantization": quant,
                        "size": size_bytes,
                    })
                return jsonify({
                    "available": True,
                    "ollama_base": ollama_base,
                    "models": models,
                })
    except Exception as e:
        logger.debug(f"Local Ollama connection failed: {e}")
        return jsonify({
            "available": False,
            "ollama_base": ollama_base,
            "error": str(e),
            "models": [],
        })


@app.route("/api/scan/upload", methods=["POST"])
def upload_scan():
    """Accept dropped .zip archive, extract, and begin scan."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    uploaded_file = request.files["file"]
    if not uploaded_file.filename or not uploaded_file.filename.lower().endswith(".zip"):
        return jsonify({"error": "Uploaded file must be a .zip archive"}), 400

    mock_mode = request.form.get("mock", "false").lower() in ("true", "1", "yes")
    model_name = request.form.get("model", "ollama/llama3.2:1b")
    docker_only = request.form.get("docker_only", "false").lower() in ("true", "1", "yes")
    semgrep_configs, enable_bandit, scan_workflows = parse_scanner_options(request.form)

    session_id = str(uuid.uuid4())
    temp_dir = Path(tempfile.mkdtemp(prefix=f"scannex_upload_{session_id[:8]}_"))

    try:
        print(f"\n[ScanneX Upload] Received ZIP archive: {uploaded_file.filename}")
        zip_path = temp_dir / "upload.zip"
        uploaded_file.save(str(zip_path))

        extract_dir = temp_dir / "repo"
        extract_dir.mkdir(parents=True, exist_ok=True)

        final_dir = extract_zip_archive(zip_path, extract_dir)
        total_src, src_summary = get_source_summary(final_dir)

        print(f"[ScanneX Upload] Extracted '{uploaded_file.filename}' -> Root: {final_dir.name} ({src_summary})")

        sessions[session_id] = {
            "id": session_id,
            "target_name": uploaded_file.filename,
            "temp_dir": str(temp_dir),
            "status": "queued",
            "findings": [],
            "events": [
                {
                    "stage": "EXTRACT",
                    "message": f"Successfully unpacked '{uploaded_file.filename}' -> codebase root '{final_dir.name}' ({src_summary})",
                    "vuln_type": None,
                    "title": None,
                    "status": None,
                }
            ],
            "error": None,
        }

        thread = threading.Thread(
            target=run_scan_async,
            args=(session_id, final_dir, mock_mode, model_name, docker_only, semgrep_configs, enable_bandit, scan_workflows),
            daemon=True,
        )
        thread.start()

        return jsonify({"session_id": session_id, "status": "queued"})

    except Exception as e:
        logger.error(f"Failed to unpack ZIP archive: {e}", exc_info=True)
        print(f"[ScanneX Upload ERROR] Failed to unpack ZIP archive: {e}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return jsonify({"error": f"Failed to unpack ZIP archive: {str(e)}"}), 500


@app.route("/api/scan/github", methods=["POST"])
def github_scan():
    """Clone remote GitHub repository and start scan."""
    data = request.get_json(silent=True) or request.form
    repo_url = data.get("url", "").strip()

    if not repo_url or ("github.com" not in repo_url):
        return jsonify({"error": "Valid GitHub URL required (e.g. https://github.com/owner/repo)"}), 400

    mock_mode = str(data.get("mock", "false")).lower() in ("true", "1", "yes")
    model_name = data.get("model", "ollama/llama3.2:1b")
    docker_only = str(data.get("docker_only", "false")).lower() in ("true", "1", "yes")
    semgrep_configs, enable_bandit, scan_workflows = parse_scanner_options(data)

    session_id = str(uuid.uuid4())
    temp_dir = Path(tempfile.mkdtemp(prefix=f"scannex_git_{session_id[:8]}_"))
    clone_dir = temp_dir / "repo"

    try:
        print(f"\n[ScanneX Git] Cloning repository: {repo_url}")
        cmd = ["git", "clone", "--depth", "1", repo_url, str(clone_dir)]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if res.returncode != 0:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return jsonify({"error": f"Git clone failed: {res.stderr}"}), 400

        repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        total_src, src_summary = get_source_summary(clone_dir)
        print(f"[ScanneX Git] Cloned {repo_name} ({src_summary})")

        sessions[session_id] = {
            "id": session_id,
            "target_name": repo_name,
            "temp_dir": str(temp_dir),
            "status": "queued",
            "findings": [],
            "events": [
                {
                    "stage": "GIT_CLONE",
                    "message": f"Successfully cloned {repo_url} ({src_summary})",
                    "vuln_type": None,
                    "title": None,
                    "status": None,
                }
            ],
            "error": None,
        }

        thread = threading.Thread(
            target=run_scan_async,
            args=(session_id, clone_dir, mock_mode, model_name, docker_only, semgrep_configs, enable_bandit, scan_workflows),
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
    mock_mode = str(data.get("mock", "false")).lower() in ("true", "1", "yes")
    model_name = data.get("model", "ollama/llama3.2:1b")
    docker_only = str(data.get("docker_only", "false")).lower() in ("true", "1", "yes")
    semgrep_configs, enable_bandit, scan_workflows = parse_scanner_options(data)

    temp_dir = Path(tempfile.mkdtemp(prefix="scannex_demo_"))
    shutil.copytree(benchmark_dir, temp_dir, dirs_exist_ok=True)
    total_src, src_summary = get_source_summary(temp_dir)

    print(f"\n[ScanneX Demo] Launching benchmark scan ({src_summary})")

    sessions[session_id] = {
        "id": session_id,
        "target_name": "vulnerable_flask_app (Pre-Patch Benchmark)",
        "temp_dir": str(temp_dir),
        "status": "queued",
        "findings": [],
        "events": [
            {
                "stage": "DEMO_INIT",
                "message": f"Initialized benchmark vulnerable app sandbox target ({src_summary})",
                "vuln_type": None,
                "title": None,
                "status": None,
            }
        ],
        "error": None,
    }

    thread = threading.Thread(
        target=run_scan_async,
        args=(session_id, temp_dir, mock_mode, model_name, docker_only, semgrep_configs, enable_bandit, scan_workflows),
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
        "active_sandboxes": session.get("active_sandboxes", []),
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
