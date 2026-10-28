"""Benchmark target applications for ScanneX evaluation."""

from pathlib import Path


def get_benchmark_dir() -> Path:
    """Return path to the bundled vulnerable Flask benchmark app."""
    return Path(__file__).parent / "vulnerable_flask_app"


__all__ = ["get_benchmark_dir"]
