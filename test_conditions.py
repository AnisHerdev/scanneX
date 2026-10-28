import os
import shutil
import sys
import tempfile
from pathlib import Path

# Insert project path
sys.path.insert(0, str(Path(__file__).parent.resolve()))

from scannex.scanner.bandit_runner import BanditRunner
from scannex.scanner.semgrep_runner import SemgrepRunner

print("=== STARTING COMPREHENSIVE SCANNER TESTS ===")

exe_dir = str(Path(sys.executable).parent)
if exe_dir not in os.environ.get("PATH", ""):
    os.environ["PATH"] = exe_dir + os.pathsep + os.environ.get("PATH", "")

def run_single_condition(name, setup_func):
    temp_dir = tempfile.mkdtemp()
    try:
        target = setup_func(Path(temp_dir))
        print(f"\n--- Testing Condition: {name} ---")
        print(f"Path: {target}")

        b_runner = BanditRunner(target)
        s_runner = SemgrepRunner(target)

        b_findings = b_runner.run()
        print(f"Bandit returned {len(b_findings)} findings.")
        for f in b_findings:
            print(f"  [Bandit] [{f.vuln_type}] {f.title} ({f.file_path}:{f.line_number})")

        s_available = s_runner.is_available()
        print(f"Semgrep available: {s_available}")
        s_findings = s_runner.run()
        print(f"Semgrep returned {len(s_findings)} findings.")
        for f in s_findings:
            print(f"  [Semgrep] [{f.vuln_type}] {f.title} ({f.file_path}:{f.line_number})")
            print(f"            sink_code: {repr(f.sink_code)}")

        return {
            "name": name,
            "bandit_count": len(b_findings),
            "semgrep_count": len(s_findings),
            "status": "SUCCESS"
        }
    except Exception as e:
        print(f"ERROR in {name}: {type(e).__name__}: {e}")
        return {
            "name": name,
            "error": str(e),
            "status": "FAILED"
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


conditions = [
    ("1. Non-existent Directory", lambda d: d / "non_existent_folder_abc"),
    ("2. Empty Directory", lambda d: (d / "empty").mkdir() or (d / "empty")),
    ("3. Non-Python Files Only", lambda d: _setup_non_py(d)),
    ("4. Clean Code (Safe)", lambda d: _setup_clean(d)),
    ("5. Python Syntax Errors", lambda d: _setup_syntax_error(d)),
    ("6. Path With Spaces and Brackets", lambda d: _setup_spaces(d)),
    ("7. UTF-8 / Non-ASCII Unicode Files", lambda d: _setup_unicode(d)),
    ("8. Vulnerable Flask App (SQLi, CMDi, SSTI)", lambda d: _setup_vulnerable(d)),
]

def _setup_non_py(d):
    p = d / "non_py_files"
    p.mkdir()
    (p / "notes.txt").write_text("SELECT * FROM users WHERE '1'='1'; os.system('calc')")
    (p / "data.json").write_text('{"api_token": "supersecret123"}')
    return p

def _setup_clean(d):
    p = d / "clean_code"
    p.mkdir()
    (p / "math_helper.py").write_text(
        "def compute_sum(a: int, b: int) -> int:\n"
        "    return a + b\n\n"
        "if __name__ == '__main__':\n"
        "    print(compute_sum(10, 20))\n"
    )
    return p

def _setup_syntax_error(d):
    p = d / "syntax_error"
    p.mkdir()
    (p / "bad_syntax.py").write_text(
        "def broken(\n"
        "    some illegal ::: syntax\n"
    )
    return p

def _setup_spaces(d):
    p = d / "folder with spaces & special [chars]"
    p.mkdir()
    (p / "vuln script.py").write_text(
        "import os\n"
        "import sqlite3\n"
        "def test(user_in):\n"
        "    os.system('ping ' + user_in)\n"
        "    conn = sqlite3.connect(':memory:')\n"
        "    conn.execute(f'SELECT * FROM users WHERE name = {user_in}')\n"
    )
    return p

def _setup_unicode(d):
    p = d / "unicode_app"
    p.mkdir()
    (p / "chinese_greek.py").write_text(
        "# -*- coding: utf-8 -*-\n"
        "# 这是一个测试应用程序 🚀\n"
        "import os\n"
        "def process():\n"
        "    greek_symbol = 'λ_func'\n"
        "    os.system('echo ' + greek_symbol)\n",
        encoding="utf-8"
    )
    return p

def _setup_vulnerable(d):
    p = d / "flask_app"
    p.mkdir()
    (p / "app.py").write_text(
        "import os, sqlite3\n"
        "from flask import Flask, request, render_template_string\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/query')\n"
        "def query():\n"
        "    user = request.args.get('user')\n"
        "    c = sqlite3.connect('test.db').cursor()\n"
        "    c.execute(f'SELECT * FROM t WHERE u = \"{user}\"')\n"
        "    return 'ok'\n\n"
        "@app.route('/ping')\n"
        "def ping():\n"
        "    h = request.args.get('host')\n"
        "    os.system('ping ' + h)\n"
        "    return 'pong'\n\n"
        "@app.route('/hello')\n"
        "def hello():\n"
        "    n = request.args.get('name')\n"
        "    return render_template_string(f'Hello {n}')\n"
    )
    return p

if __name__ == "__main__":
    summary = []
    for name, func in conditions:
        res = run_single_condition(name, func)
        summary.append(res)
    print("\n=== SUMMARY OF CONDITION TESTS ===")
    for item in summary:
        print(item)

