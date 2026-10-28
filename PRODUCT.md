# ScanneX Product Specification
*Team Gravitas (T2-13) • HackFest 2026*

## 1. Product Truth
ScanneX is an autonomous Application Security (AppSec) verification and speculative remediation pipeline. It eliminates static alert fatigue by proving vulnerabilities dynamically with isolated Docker/subprocess sandbox canaries and concurrently synthesizing verified code patches.

## 2. Target Users
- **Security Engineers & DevSecOps Specialists**: Tired of triaging hundreds of unverified SAST alerts; need proof of exploitability and SARIF 2.1.0 exports.
- **Software Developers**: Need immediate, actionable, tested code patches rather than vague warnings like "possible SQL injection at line 42".
- **Hackathon Judges & Evaluators**: Need a zero-friction, one-click experience to test custom repositories, drop ZIP archives, or run pre-packaged benchmark CVEs.

## 3. Core Capabilities
1. **Repository Ingestion**:
   - Drag-and-drop ZIP archive upload.
   - GitHub repository URL cloning (`git clone --depth 1`).
   - One-click bundled benchmark demo.
2. **Protected Dual-Track Verification**:
   - Deterministic AST rules (Bandit/Semgrep) preserved intact.
   - AI Hunter + Adversarial Gatekeeper debate to eliminate LLM hallucinations.
3. **Concurrent Speculative Sandboxing**:
   - Ephemeral Docker container launch with automatic WSGI hook.
   - Harmless canary probes evaluated by a deterministic oracle (never the LLM).
   - Parallel patch synthesis and closed-loop sandbox re-testing (`verified_fixed`).
4. **Honest Status Ontology**:
   - `verified_fixed`, `confirmed_dynamic`, `confirmed_static`, `unverified`, `rejected`.
5. **Standards-Compliant Exports**:
   - OASIS SARIF 2.1.0, Markdown summary, HTML report.
