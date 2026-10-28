"""Sandbox execution engine supporting Docker and ephemeral subprocess environments."""

import asyncio
import logging
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Optional
import requests
from scannex.config import ScannexConfig
from scannex.db.models import PatchSpec, ProbeResult, ProbeSpec
from scannex.sandbox.oracle import DeterministicOracle

logger = logging.getLogger(__name__)


class SandboxExecutor:
    """Manages ephemeral application sandbox and executes canary probes."""

    def __init__(self, target_dir: Path | str, config: Optional[ScannexConfig] = None):
        self.target_dir = Path(target_dir).resolve()
        self.config = config or ScannexConfig.from_env()
        self.oracle = DeterministicOracle()
        self.sandbox_dir: Optional[Path] = None
        self.process: Optional[subprocess.Popen] = None
        self.container_name: Optional[str] = None
        self.port: int = 0
        self.base_url: str = ""
        self.sandbox_type: str = "subprocess"

    def is_docker_available(self) -> bool:
        """Check if Docker engine is running."""
        if not self.config.prefer_docker:
            return False
        try:
            res = subprocess.run(["docker", "info"], capture_output=True, timeout=2)
            return res.returncode == 0
        except Exception:
            return False

    def find_free_port(self) -> int:
        """Allocate a free dynamic OS port."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            return s.getsockname()[1]

    async def start(self) -> None:
        """Spin up the isolated application sandbox (Docker first, subprocess fallback)."""
        entrypoint = self._find_entrypoint()
        if not entrypoint:
            raise RuntimeError(f"No runnable Python entrypoint (app.py, main.py) found in {self.target_dir}")

        # Setup ephemeral sandbox directory
        self.sandbox_dir = Path(tempfile.mkdtemp(prefix="scannex_sandbox_"))
        shutil.copytree(self.target_dir, self.sandbox_dir, dirs_exist_ok=True)

        self.port = self.find_free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"

        if self.is_docker_available():
            try:
                await self._start_docker(entrypoint)
                return
            except Exception as e:
                logger.warning(f"Docker sandbox startup failed ({e}); falling back to subprocess.")

        await self._start_subprocess(entrypoint)

    async def _start_docker(self, entrypoint: Path) -> None:
        """Launch isolated Docker container mounting the ephemeral sandbox copy."""
        self.container_name = f"scannex_box_{uuid.uuid4().hex[:8]}"
        self.sandbox_type = "docker"

        # Inject auto-bind hook so any Flask/WSGI app binds to 0.0.0.0 inside the container
        hook_file = self.sandbox_dir / "sitecustomize.py"
        hook_code = """
try:
    import flask
    _orig_run = flask.Flask.run
    def _patched_run(self, *args, **kwargs):
        kwargs['host'] = '0.0.0.0'
        return _orig_run(self, *args, **kwargs)
    flask.Flask.run = _patched_run
except Exception:
    pass
"""
        hook_file.write_text(hook_code, encoding="utf-8")

        cmd = [
            "docker", "run", "-d",
            "--name", self.container_name,
            "-p", f"{self.port}:5000",
            "-v", f"{self.sandbox_dir.as_posix()}:/app",
            "-w", "/app",
            "-e", "PYTHONPATH=/app",
            "-e", "PORT=5000",
            "-e", "FLASK_RUN_HOST=0.0.0.0",
            "-e", "FLASK_RUN_PORT=5000",
            "-e", "PYTHONUNBUFFERED=1",
            "scannex-sandbox-base:latest",
            "python", entrypoint.name, "--port", "5000",
        ]

        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if res.returncode != 0:
            raise RuntimeError(f"Docker run failed: {res.stderr}")

        await self._wait_for_ready()

    async def _start_subprocess(self, entrypoint: Path) -> None:
        """Fallback runner executing isolated Python subprocess."""
        self.sandbox_type = "subprocess"
        env = os.environ.copy()
        env["PORT"] = str(self.port)
        env["FLASK_RUN_PORT"] = str(self.port)
        env["PYTHONUNBUFFERED"] = "1"

        sandbox_entrypoint = self.sandbox_dir / entrypoint.name

        self.process = subprocess.Popen(
            [sys.executable, str(sandbox_entrypoint), "--port", str(self.port)],
            cwd=str(self.sandbox_dir),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        await self._wait_for_ready()

    def _find_entrypoint(self) -> Optional[Path]:
        """Locate primary application file."""
        for candidate in ("app.py", "main.py", "server.py", "wsgi.py", "run.py"):
            p = self.target_dir / candidate
            if p.is_file():
                return p
        # Any .py file in root
        py_files = list(self.target_dir.glob("*.py"))
        return py_files[0] if py_files else None

    async def _wait_for_ready(self, timeout_sec: float = 6.0) -> None:
        """Poll the local port until application accepts connections."""
        start_time = time.time()
        while time.time() - start_time < timeout_sec:
            if self.process and self.process.poll() is not None:
                _, stderr = self.process.communicate()
                raise RuntimeError(f"Sandbox application crashed on boot: {stderr.decode('utf-8', errors='ignore')}")

            try:
                # Test connectivity
                requests.get(f"{self.base_url}/", timeout=0.5)
                return
            except requests.RequestException:
                await asyncio.sleep(0.2)

        # If base / returned 404 but connection succeeded, that's still ready
        return

    async def execute_probe(self, probe_spec: ProbeSpec) -> ProbeResult:
        """Fire harmless canary probe against the running sandbox."""
        if not self.base_url:
            await self.start()

        target_url = f"{self.base_url}{probe_spec.endpoint}"
        t0 = time.time()

        try:
            # Run blocking HTTP request in thread pool
            loop = asyncio.get_running_loop()
            res = await loop.run_in_executor(
                None,
                lambda: requests.request(
                    method=probe_spec.method,
                    url=target_url,
                    headers=probe_spec.headers,
                    params=probe_spec.params,
                    data=probe_spec.data,
                    json=probe_spec.json_body,
                    timeout=probe_spec.timeout_sec,
                ),
            )
            duration_ms = (time.time() - t0) * 1000
            return self.oracle.evaluate_http_response(
                probe_spec=probe_spec,
                response=res,
                sandbox_dir=self.sandbox_dir,
                duration_ms=duration_ms,
                sandbox_type=self.sandbox_type,
            )
        except Exception as e:
            duration_ms = (time.time() - t0) * 1000
            return self.oracle.evaluate_http_response(
                probe_spec=probe_spec,
                response=None,
                sandbox_dir=self.sandbox_dir,
                error=e,
                duration_ms=duration_ms,
                sandbox_type=self.sandbox_type,
            )

    async def test_patch(self, patch: PatchSpec, probe_spec: ProbeSpec) -> tuple[bool, ProbeResult]:
        """Apply speculative patch to sandbox copy and re-fire probe to verify fix."""
        if not self.sandbox_dir:
            return False, ProbeResult(error_message="Sandbox not running")

        target_file = self.sandbox_dir / patch.file_path
        if not target_file.is_file():
            return False, ProbeResult(error_message=f"File {patch.file_path} not found in sandbox")

        # Read current content
        content = target_file.read_text(encoding="utf-8", errors="ignore")
        applied = False
        patched_content = content

        if patch.search_block and patch.search_block in content:
            patched_content = content.replace(patch.search_block, patch.replace_block, 1)
            applied = True
        elif patch.search_block and patch.search_block.strip() in content:
            patched_content = content.replace(patch.search_block.strip(), patch.replace_block.strip(), 1)
            applied = True
        else:
            # Line-by-line whitespace-tolerant matching
            search_lines = [l.strip() for l in patch.search_block.splitlines() if l.strip()]
            replace_lines = patch.replace_block.splitlines()
            if search_lines:
                content_lines = content.splitlines()
                for idx in range(len(content_lines) - len(search_lines) + 1):
                    window = [content_lines[idx + j].strip() for j in range(len(search_lines))]
                    if window == search_lines:
                        leading_indent = len(content_lines[idx]) - len(content_lines[idx].lstrip())
                        indent_str = " " * leading_indent
                        indented_replacement = [indent_str + rl.strip() for rl in replace_lines]
                        new_lines = content_lines[:idx] + indented_replacement + content_lines[idx + len(search_lines):]
                        patched_content = "\n".join(new_lines) + ("\n" if content.endswith("\n") else "")
                        applied = True
                        break

        if not applied:
            return False, ProbeResult(error_message="Patch search block could not be matched")

        # Hot-patch the sandbox copy
        target_file.write_text(patched_content, encoding="utf-8")
        patch.applied_successfully = True

        # Restart sandbox with the patched code
        if self.container_name:
            # Hot-restart Docker container with mounted patched code
            subprocess.run(["docker", "restart", self.container_name], check=True, capture_output=True, timeout=10)
            await self._wait_for_ready()
        else:
            self.stop_process()
            self.port = self.find_free_port()
            self.base_url = f"http://127.0.0.1:{self.port}"

            env = os.environ.copy()
            env["PORT"] = str(self.port)
            env["FLASK_RUN_PORT"] = str(self.port)

            entrypoint = self._find_entrypoint()
            if entrypoint:
                self.process = subprocess.Popen(
                    [sys.executable, str(self.sandbox_dir / entrypoint.name), "--port", str(self.port)],
                    cwd=str(self.sandbox_dir),
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                await self._wait_for_ready()

        # Re-fire probe!
        retest_result = await self.execute_probe(probe_spec)
        
        # If canary is NOT tripped now, the exploit was successfully defeated!
        is_fixed = not retest_result.canary_tripped
        patch.retest_verified = is_fixed

        return is_fixed, retest_result

    def stop_process(self) -> None:
        """Terminate the running sandbox process."""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            self.process = None

    def teardown(self) -> None:
        """Cleanly shutdown sandbox container or process and remove ephemeral directory."""
        if self.container_name:
            try:
                subprocess.run(["docker", "rm", "-f", self.container_name], capture_output=True, timeout=5)
            except Exception:
                pass
            self.container_name = None

        self.stop_process()
        if self.sandbox_dir and self.sandbox_dir.exists():
            try:
                shutil.rmtree(self.sandbox_dir, ignore_errors=True)
            except Exception:
                pass
            self.sandbox_dir = None
