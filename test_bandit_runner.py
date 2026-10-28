import io
import shutil
import sys
import tempfile
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).parent.resolve()))

from scannex.scanner.bandit_runner import BanditRunner

print("=== VERIFYING BANDIT RUNNER BEHAVIOR ===")

# Test Helper to capture stdout
def run_and_capture(runner):
    old_stdout = sys.stdout
    buffer = io.StringIO()
    sys.stdout = buffer
    try:
        res = runner.run()
    finally:
        sys.stdout = old_stdout
    output = buffer.getvalue()
    return res, output

# Case 1: Target with vulnerabilities
runner_vuln = BanditRunner("gravitas-t2-13/test_target")
res_vuln, out_vuln = run_and_capture(runner_vuln)
print("1. Target with Vulnerabilities:")
print(f"   Printed output: {repr(out_vuln)}")
print(f"   Return type: {type(res_vuln)}, Findings count: {len(res_vuln)}")
assert out_vuln == "", "Should NOT print Execution Failed on successful execution"
assert isinstance(res_vuln, list) and len(res_vuln) == 3

# Case 2: Clean code (No vulnerabilities found)
temp_clean = tempfile.mkdtemp()
try:
    clean_file = Path(temp_clean) / "safe.py"
    clean_file.write_text("def hello():\n    return 'clean code'\n")
    runner_clean = BanditRunner(temp_clean)
    res_clean, out_clean = run_and_capture(runner_clean)
    print("\n2. Clean Code (0 vulnerabilities):")
    print(f"   Printed output: {repr(out_clean)}")
    print(f"   Return value: {res_clean}")
    assert out_clean == "", "Should NOT print Execution Failed when code runs and has 0 findings"
    assert res_clean == [], "Should return [] when Bandit runs cleanly"
finally:
    shutil.rmtree(temp_clean, ignore_errors=True)

# Case 3: Missing Target Directory (Execution Failed)
runner_missing = BanditRunner("gravitas-t2-13/missing_dir_xyz")
res_missing, out_missing = run_and_capture(runner_missing)
print("\n3. Missing Directory (Failed Execution):")
print(f"   Printed output: {repr(out_missing.strip())}")
print(f"   Return value: {res_missing}")
assert "Execution Failed" in out_missing, "Must print 'Execution Failed'"
assert res_missing == "Bandit failed/Did not execute"

# Case 4: Process Failure / Invalid Executable (Failed Execution)
runner_fail = BanditRunner("gravitas-t2-13/test_target")
orig_exe = sys.executable
sys.executable = "invalid_python_interpreter"
try:
    res_fail, out_fail = run_and_capture(runner_fail)
    print("\n4. Execution Crash / Binary Missing (Failed Execution):")
    print(f"   Printed output: {repr(out_fail.strip())}")
    print(f"   Return value: {res_fail}")
    assert "Execution Failed" in out_fail, "Must print 'Execution Failed'"
    assert res_fail == "Bandit failed/Did not execute"
finally:
    sys.executable = orig_exe

print("\n>>> ALL TEST CASES PASSED SUCCESSFULLY! <<<")

