"""Unit tests for archive extraction, security safeguards, and root directory resolution."""

import io
import tempfile
import zipfile
from pathlib import Path
import pytest
from scannex.scanner.archive_extractor import (
    extract_zip_archive,
    resolve_project_root,
    temporary_extracted_archive,
)


def test_extract_flat_zip_with_pycache():
    """Flat zip with app.py and a __pycache__ directory must resolve to the extracted root."""
    temp_dir = Path(tempfile.mkdtemp()).resolve()
    zip_path = temp_dir / "test.zip"
    extract_dest = (temp_dir / "extracted").resolve()

    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr("app.py", "import flask\n")
        z.writestr("test_app.db", "mock-sqlite-db")
        z.writestr("__pycache__/app.cpython-311.pyc", "mock-bytecode")

    root = extract_zip_archive(zip_path, extract_dest)
    assert root == extract_dest
    assert (root / "app.py").is_file()
    assert (root / "__pycache__").is_dir()


def test_extract_enclosing_folder_zip():
    """Zip with single top-level folder 'my-repo-main/' must unwrap down to 'my-repo-main'."""
    temp_dir = Path(tempfile.mkdtemp()).resolve()
    zip_path = temp_dir / "test.zip"
    extract_dest = (temp_dir / "extracted").resolve()

    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr("my-repo-main/app.py", "import flask\n")
        z.writestr("my-repo-main/requirements.txt", "flask==3.0.0\n")

    root = extract_zip_archive(zip_path, extract_dest)
    assert root == extract_dest / "my-repo-main"
    assert (root / "app.py").is_file()


def test_extract_mac_zip_with_macosx_metadata():
    """Zip containing '__MACOSX' folder alongside project folder must ignore __MACOSX and unwrap project folder."""
    temp_dir = Path(tempfile.mkdtemp()).resolve()
    zip_path = temp_dir / "test.zip"
    extract_dest = (temp_dir / "extracted").resolve()

    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr("__MACOSX/._app.py", "mac-metadata")
        z.writestr("my-flask-app/app.py", "import flask\n")
        z.writestr("my-flask-app/templates/index.html", "<h1>Hello</h1>")

    root = extract_zip_archive(zip_path, extract_dest)
    assert root == extract_dest / "my-flask-app"
    assert (root / "app.py").is_file()


def test_zip_slip_path_traversal_rejection():
    """Archives with '../' attempting to escape target directory must raise ValueError."""
    temp_dir = Path(tempfile.mkdtemp()).resolve()
    zip_path = temp_dir / "evil.zip"
    extract_dest = (temp_dir / "extracted").resolve()

    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr("../../evil.txt", "pwned")

    with pytest.raises(ValueError, match="Unsafe path traversal"):
        extract_zip_archive(zip_path, extract_dest)


def test_zip_bomb_size_quota_rejection():
    """Archives exceeding max_size_bytes must raise ValueError."""
    temp_dir = Path(tempfile.mkdtemp()).resolve()
    zip_path = temp_dir / "bomb.zip"
    extract_dest = (temp_dir / "extracted").resolve()

    with zipfile.ZipFile(zip_path, "w") as z:
        # 2 MB uncompressed content
        z.writestr("huge.txt", "A" * (2 * 1024 * 1024))

    # Set quota to 1 MB
    with pytest.raises(ValueError, match="exceeds maximum size limit"):
        extract_zip_archive(zip_path, extract_dest, max_size_bytes=1024 * 1024)


def test_temporary_extracted_archive_context_manager():
    """temporary_extracted_archive extracts correctly and cleans up directory upon exit."""
    temp_dir = Path(tempfile.mkdtemp()).resolve()
    zip_path = temp_dir / "temp_test.zip"

    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr("service/main.py", "print('hello')\n")

    resolved_path = None
    with temporary_extracted_archive(zip_path) as root:
        resolved_path = root
        assert root.is_dir()
        assert (root / "main.py").is_file()

    # After exit, temp directory must be cleaned up
    assert not resolved_path.exists()
