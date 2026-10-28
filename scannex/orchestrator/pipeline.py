"""Core ScanneX Orchestration Pipeline with Concurrent Speculative Patching."""

import asyncio
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Callable, Optional
from scannex.agents.hunter import HunterAgent
from scannex.agents.patcher import SpeculativePatchAgent
from scannex.agents.verifier import VerifierAgent
from scannex.config import ScannexConfig
from scannex.db.models import Finding, FindingStatus
from scannex.db.store import FindingsStore
from scannex.sandbox.executor import SandboxExecutor
from scannex.scanner.archive_extractor import extract_zip_archive
from scannex.scanner.bandit_runner import BanditRunner
from scannex.scanner.malware_runner import MalwareRunner
from scannex.scanner.semgrep_runner import SemgrepRunner


class PipelineEvent:
    """Status callback event for terminal UI updates."""
    def __init__(
        self,
        stage: str,
        message: str,
        finding: Optional[Finding] = None,
        metadata: Optional[dict] = None,
    ):
        self.stage = stage
        self.message = message
        self.finding = finding
        self.metadata = metadata or {}


class ScannexOrchestrator:
    """Coordinates the dual-track static/AI scan, adversarial verification, and speculative patching."""

    def __init__(
        self,
        target_dir: Path | str,
        config: Optional[ScannexConfig] = None,
        store: Optional[FindingsStore] = None,
        event_callback: Optional[Callable[[PipelineEvent], None]] = None,
    ):
        target_path = Path(target_dir).resolve()
        self.cleanup_temp_dir: Optional[Path] = None

        # Automatically unpack if target is a ZIP file
        if target_path.is_file() and (target_path.suffix.lower() == ".zip" or zipfile.is_zipfile(target_path)):
            temp_extract = Path(tempfile.mkdtemp(prefix="scannex_zip_"))
            self.cleanup_temp_dir = temp_extract
            self.target_dir = extract_zip_archive(target_path, temp_extract)
        else:
            self.target_dir = target_path

        self.config = config or ScannexConfig.from_env()
        self.store = store or FindingsStore(self.config.db_path)
        self.event_callback = event_callback or (lambda ev: None)

        # Scanners and agents
        self.malware_runner = MalwareRunner(self.target_dir)
        self.bandit_runner = BanditRunner(self.target_dir)
        self.semgrep_runner = SemgrepRunner(
            self.target_dir,
            configs=getattr(self.config, "semgrep_configs", None),
            scan_workflows=getattr(self.config, "scan_workflows", False),
        )
        self.hunter_agent = HunterAgent(self.target_dir, self.config)
        self.verifier_agent = VerifierAgent(self.target_dir, self.config)
        self.patch_agent = SpeculativePatchAgent(self.target_dir, self.config)

    def _emit(
        self,
        stage: str,
        message: str,
        finding: Optional[Finding] = None,
        metadata: Optional[dict] = None,
    ) -> None:
        """Notify UI listeners of pipeline progress."""
        self.event_callback(PipelineEvent(stage, message, finding, metadata))

    async def run(self) -> list[Finding]:
        """Execute the end-to-end autonomous AppSec pipeline."""
        try:
            ignored_dirs = {
                "__pycache__",
                ".venv",
                "venv",
                "env",
                ".env",
                "node_modules",
                ".git",
                ".pytest_cache",
                "site-packages",
            }
            source_extensions = {".py", ".php", ".inc", ".js", ".ts", ".html", ".go", ".java", ".rb", ".cs"}
            src_files = [
                p for p in self.target_dir.rglob("*")
                if p.is_file() and p.suffix.lower() in source_extensions
                and not any(part in ignored_dirs or (part.startswith(".") and part != ".") for part in p.parts)
            ]
            self._emit(
                "INIT",
                f"Initializing ScanneX scan on {self.target_dir.name} ({len(src_files)} source files detected)",
            )

            # -------------------------------------------------------------
            # Track 0: Deterministic Malware & Artifact Inspection
            # -------------------------------------------------------------
            malware_findings: list[Finding] = []
            loop = asyncio.get_running_loop()
            if getattr(self.config, "enable_malware_scan", True):
                self._emit("MALWARE_SCAN", "Scanning all files and archives for malware signatures, webshells, and embedded threats...")
                malware_findings = await loop.run_in_executor(None, self.malware_runner.run)
                self._emit("MALWARE_SCAN", f"Malware scan complete: {len(malware_findings)} threat(s) detected.")

            # -------------------------------------------------------------
            # Track 1: Deterministic Static Scanning (Preserved Intact)
            # -------------------------------------------------------------
            self._emit("STATIC_SCAN", "Executing static AST & taint rules (Bandit + Semgrep)...")
            
            static_tasks = []
            if getattr(self.config, "enable_bandit", True):
                static_tasks.append(loop.run_in_executor(None, self.bandit_runner.run))
            else:
                static_tasks.append(asyncio.sleep(0, result=[]))
            
            static_tasks.append(loop.run_in_executor(None, self.semgrep_runner.run))
            results = await asyncio.gather(*static_tasks)
            bandit_findings = results[0] or []
            semgrep_findings = results[1] or []
            static_findings = bandit_findings + semgrep_findings
            self._emit("STATIC_SCAN", f"Static scan complete: {len(static_findings)} rule findings identified.")

            # -------------------------------------------------------------
            # Track 2: AI Hunter + Immediate Adversarial Verifier
            # -------------------------------------------------------------
            self._emit("AI_HUNT", "AI Hunter analyzing business logic, auth flows, and unexpressed taint...")
            raw_ai_findings = await self.hunter_agent.hunt()
            self._emit("AI_HUNT", f"AI Hunter identified {len(raw_ai_findings)} candidate logic hypotheses.")

            approved_ai_findings: list[Finding] = []
            for candidate in raw_ai_findings:
                self._emit("ADVERSARIAL_VERIFY", f"Adversarial Verifier auditing hypothesis: {candidate.title}", candidate)
                verification = await self.verifier_agent.verify(candidate)
                if verification.up_approved:
                    approved_ai_findings.append(candidate)
                    self._emit("ADVERSARIAL_VERIFY", f"Hypothesis UP-APPROVED: {candidate.title}", candidate)
                else:
                    self.store.save_finding(candidate)
                    self._emit("ADVERSARIAL_VERIFY", f"Hypothesis REJECTED (disproved): {candidate.title}", candidate)

            # -------------------------------------------------------------
            # Consolidation & Early Exit Check
            # -------------------------------------------------------------
            all_candidates = malware_findings + static_findings + approved_ai_findings
            self._emit("CONSOLIDATE", f"Consolidated {len(all_candidates)} actionable findings.")

            if not all_candidates:
                self._emit("COMPLETE", "Zero vulnerabilities detected. Repository is secure!")
                return []

            # -------------------------------------------------------------
            # Concurrent Speculative Patching & Dynamic Sandbox Proving
            # -------------------------------------------------------------
            semaphore = asyncio.Semaphore(self.config.max_concurrency)
            tasks = [self._process_finding(f, semaphore) for f in all_candidates]
            completed_findings = await asyncio.gather(*tasks)

            self._emit("COMPLETE", f"Pipeline finished: {len(completed_findings)} findings verified and stored.")
            return completed_findings

        finally:
            if self.cleanup_temp_dir and self.cleanup_temp_dir.exists():
                shutil.rmtree(self.cleanup_temp_dir, ignore_errors=True)

    async def _process_finding(self, finding: Finding, semaphore: asyncio.Semaphore) -> Finding:
        """Concurrently run Sandbox Prover and Speculative Patch Agent."""
        async with semaphore:
            # If no probe spec was generated, keep as static finding
            if not finding.probe_spec:
                finding.status = FindingStatus.CONFIRMED_STATIC
                if finding.source == "malware_detector":
                    finding.add_trace("Deterministic malware signature confirmed; quarantined from dynamic sandbox")
                else:
                    finding.add_trace("No HTTP route mapped; confirmed via static source-to-sink analysis")
                self.store.save_finding(finding)
                return finding

            self._emit(
                "SPECULATIVE_EXEC",
                f"Launching concurrent Sandbox Prover + Patch Agent for [{finding.vuln_type}]",
                finding,
            )

            sandbox = SandboxExecutor(
                self.target_dir,
                self.config,
                event_callback=lambda stage, msg, meta=None: self._emit(stage, msg, finding, meta),
            )
            try:
                # Concurrent launch: don't wait for sandbox boot before generating patch!
                sandbox_task = asyncio.create_task(sandbox.execute_probe(finding.probe_spec))
                patch_task = asyncio.create_task(self.patch_agent.generate_patch(finding))

                probe_result, patch_spec = await asyncio.gather(sandbox_task, patch_task)
                finding.probe_result = probe_result
                finding.patch_spec = patch_spec

                # Deterministic Oracle Evaluation
                if probe_result.canary_tripped:
                    finding.status = FindingStatus.CONFIRMED_DYNAMIC
                    finding.add_trace(
                        f"Dynamic probe TRIPPED canary ({probe_result.response_snippet}) on {probe_result.sandbox_type}"
                    )
                    self._emit("PROBE_CONFIRMED", f"Exploit PROVEN live: canary tripped for {finding.title}", finding)

                    # Immediate Closed-Loop Retest with Pre-synthesized Patch
                    self._emit("RETEST_PATCH", f"Hot-applying pre-synthesized patch to sandbox for {finding.title}", finding)
                    is_fixed, retest_result = await sandbox.test_patch(patch_spec, finding.probe_spec)

                    if is_fixed:
                        finding.status = FindingStatus.VERIFIED_FIXED
                        finding.add_trace("Speculative patch applied to sandbox: retest probe failed (vulnerability resolved)")
                        self._emit("FIX_VERIFIED", f"Patch VERIFIED: flaw successfully neutralized in sandbox!", finding)
                    else:
                        finding.add_trace("Patch applied but retest probe still tripped canary (patch revision required)")
                        self._emit("FIX_FAILED", f"Patch failed to eliminate exploit; flagged for review", finding)

                else:
                    finding.status = FindingStatus.UNVERIFIED
                    finding.add_trace(
                        f"Probe did not trip canary (status={probe_result.status_code}, error={probe_result.error_message})"
                    )
                    self._emit("PROBE_UNVERIFIED", f"Probe unverified for {finding.title} (patch saved as suggestion)", finding)

            except Exception as e:
                finding.status = FindingStatus.UNVERIFIED
                finding.add_trace(f"Sandbox execution error: {str(e)}")
            finally:
                sandbox.teardown()
                self.store.save_finding(finding)

            return finding
