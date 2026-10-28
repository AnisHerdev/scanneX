"""Secure ZIP archive extraction and codebase root resolution."""

import logging
import os
import shutil
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional, Set

logger = logging.getLogger(__name__)

# Directory and file names ignored when determining if a directory is an enclosing wrapper
METADATA_IGNORE_NAMES: Set[str] = {
    "__MACOSX",
    "__pycache__",
    ".pytest_cache",
    ".git",
    ".github",
    ".vscode",
    ".idea",
    ".DS_Store",
    ".venv",
    "venv",
    "env",
    ".env",
    "node_modules",
}

# Manifest/code indicators of a project root
PROJECT_ROOT_INDICATORS: Set[str] = {
    "requirements.txt",
    "setup.py",
    "pyproject.toml",
    "Pipfile",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "manage.py",
    "wsgi.py",
    "app.py",
    "main.py",
    "server.py",
    "run.py",
}


def resolve_project_root(extract_dir: Path | str) -> Path:
    """Intelligently determine the true project root within an extracted archive.

    If an archive was packed as a single enclosing directory (e.g. 'repo-main/'),
    unwraps down to that directory. If the archive contains root code files or
    multiple sibling directories (e.g. 'src/' and 'tests/'), preserves the current level.
    """
    curr = Path(extract_dir).resolve()

    while True:
        try:
            entries = list(curr.iterdir())
        except (OSError, PermissionError):
            return curr

        # Check if Python files exist directly in curr
        py_files_here = [
            p for p in entries
            if p.is_file() and p.suffix == ".py" and p.name not in METADATA_IGNORE_NAMES
        ]
        if py_files_here:
            # Code files are present at this level; curr is the root
            return curr

        # Filter out metadata noise
        visible_children = [
            p for p in entries
            if p.name not in METADATA_IGNORE_NAMES and not p.name.startswith(".")
        ]

        # Check if project manifest files exist at this level
        root_indicator_files = [
            p for p in visible_children
            if p.is_file() and p.name.lower() in PROJECT_ROOT_INDICATORS
        ]
        if root_indicator_files:
            return curr

        # Any non-ignored files at this level mean this is a root
        visible_files = [p for p in visible_children if p.is_file()]
        if visible_files:
            return curr

        # If only directories remain, check if there is a single enclosing folder
        visible_dirs = [p for p in visible_children if p.is_dir()]
        if len(visible_dirs) == 1:
            # Exactly one real folder (e.g. 'repo-main') -> unwrap into it
            curr = visible_dirs[0]
            continue

        # Either no visible entries or multiple sibling folders (e.g. 'src', 'tests')
        return curr


def extract_zip_archive(
    zip_path: Path | str,
    dest_dir: Path | str,
    max_size_bytes: int = 500 * 1024 * 1024,
) -> Path:
    """Safely extract a ZIP archive avoiding Zip Slip and zip bombs.

    Args:
        zip_path: Path to the .zip archive on disk.
        dest_dir: Directory where archive contents will be extracted.
        max_size_bytes: Maximum total uncompressed size permitted (default: 500 MB).

    Returns:
        Path to the resolved codebase root directory inside dest_dir.

    Raises:
        ValueError: If archive contains unsafe paths or exceeds size quota.
        zipfile.BadZipFile: If archive is corrupted or not a valid ZIP.
    """
    zip_path = Path(zip_path).resolve()
    dest_dir = Path(dest_dir).resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)

    if not zip_path.is_file():
        raise ValueError(f"Archive file not found: {zip_path}")

    total_extracted_size = 0

    with zipfile.ZipFile(zip_path, "r") as z:
        for member in z.infolist():
            # Check uncompressed size to prevent zip bomb attacks
            total_extracted_size += member.file_size
            if total_extracted_size > max_size_bytes:
                raise ValueError(
                    f"ZIP archive exceeds maximum size limit of {max_size_bytes / (1024 * 1024):.0f} MB"
                )

            # Sanitize member name: normalize Windows backslashes and remove drive letters/leading slashes
            clean_name = member.filename.replace("\\", "/")
            if ":" in clean_name:
                clean_name = clean_name.split(":", 1)[1]
            clean_name = clean_name.lstrip("/")

            if not clean_name:
                continue

            target_path = (dest_dir / clean_name).resolve()

            # Zip Slip directory traversal check
            if not target_path.is_relative_to(dest_dir):
                raise ValueError(f"Unsafe path traversal detected in ZIP: {member.filename}")

            # Directory entry
            if member.is_dir() or clean_name.endswith("/"):
                target_path.mkdir(parents=True, exist_ok=True)
                continue

            # Regular file entry
            target_path.parent.mkdir(parents=True, exist_ok=True)
            with z.open(member) as source, open(target_path, "wb") as target:
                shutil.copyfileobj(source, target)

    resolved_root = resolve_project_root(dest_dir)
    logger.info(f"Extracted ZIP archive '{zip_path.name}' -> resolved project root: {resolved_root}")
    return resolved_root


@contextmanager
def temporary_extracted_archive(
    archive_path: Path | str,
) -> Generator[Path, None, None]:
    """Context manager that unpacks a ZIP archive to a temp directory and cleans up afterwards."""
    archive_path = Path(archive_path).resolve()
    temp_dir = Path(tempfile.mkdtemp(prefix=f"scannex_extracted_{archive_path.stem[:8]}_"))
    try:
        resolved_root = extract_zip_archive(archive_path, temp_dir)
        yield resolved_root
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
