"""Configuration management for ScanneX."""

import os
from pathlib import Path
from pydantic import BaseModel, Field


class ScannexConfig(BaseModel):
    """Global runtime configuration."""
    
    # Model configuration
    model_name: str = Field(default="gemini/gemini-2.5-flash")
    ollama_model: str = Field(default="ollama/codellama")
    mock_mode: bool = Field(default=False)
    
    # Database configuration
    db_path: Path = Field(default=Path(".scannex/findings.db"))
    
    # Concurrency and execution limits
    max_concurrency: int = Field(default=2)
    sandbox_timeout_sec: int = Field(default=25)
    probe_timeout_sec: int = Field(default=5)
    llm_timeout_sec: int = Field(default=180)
    
    # Canary configuration
    canary_prefix: str = Field(default="SCANX_CANARY_")
    file_marker_dir: str = Field(default="/tmp")
    
    # Docker / Execution preferences
    prefer_docker: bool = Field(default=True)
    docker_only: bool = Field(default=False)
    subprocess_port_range: tuple[int, int] = Field(default=(50000, 60000))

    # Multi-language Semgrep rule configurations & linters
    semgrep_configs: list[str] = Field(
        default_factory=lambda: ["p/owasp-top-ten", "p/security-audit", "p/php"]
    )
    enable_bandit: bool = Field(default=True)
    enable_malware_scan: bool = Field(default=True)
    scan_workflows: bool = Field(default=False)
    
    @classmethod
    def from_env(cls) -> "ScannexConfig":
        """Load configuration from environment variables."""
        mock = os.getenv("SCANNEX_MOCK_MODE", "").lower() in ("1", "true", "yes")
        model = os.getenv("SCANNEX_MODEL", "gemini/gemini-2.5-flash")
        timeout_env = os.getenv("SCANNEX_LLM_TIMEOUT")
        llm_timeout = int(timeout_env) if timeout_env else 180
        return cls(
            model_name=model,
            mock_mode=mock,
            db_path=Path(os.getenv("SCANNEX_DB_PATH", ".scannex/findings.db")),
            max_concurrency=int(os.getenv("SCANNEX_MAX_CONCURRENCY", "2")),
            prefer_docker=os.getenv("SCANNEX_USE_SUBPROCESS", "").lower() not in ("1", "true"),
            docker_only=os.getenv("SCANNEX_DOCKER_ONLY", "").lower() in ("1", "true", "yes"),
            llm_timeout_sec=llm_timeout,
        )
