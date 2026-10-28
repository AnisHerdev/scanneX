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
    
    # Canary configuration
    canary_prefix: str = Field(default="SCANX_CANARY_")
    file_marker_dir: str = Field(default="/tmp")
    
    # Docker / Execution preferences
    prefer_docker: bool = Field(default=True)
    subprocess_port_range: tuple[int, int] = Field(default=(50000, 60000))
    
    @classmethod
    def from_env(cls) -> "ScannexConfig":
        """Load configuration from environment variables."""
        mock = os.getenv("SCANNEX_MOCK_MODE", "").lower() in ("1", "true", "yes")
        # If neither GEMINI_API_KEY nor OPENAI_API_KEY nor OLLAMA_HOST is set, auto-enable mock mode
        has_keys = bool(os.getenv("GEMINI_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("OLLAMA_API_BASE"))
        if not has_keys and not mock:
            mock = True
            
        model = os.getenv("SCANNEX_MODEL", "gemini/gemini-2.5-flash")
        return cls(
            model_name=model,
            mock_mode=mock,
            db_path=Path(os.getenv("SCANNEX_DB_PATH", ".scannex/findings.db")),
            max_concurrency=int(os.getenv("SCANNEX_MAX_CONCURRENCY", "2")),
            prefer_docker=os.getenv("SCANNEX_USE_SUBPROCESS", "").lower() not in ("1", "true"),
        )
