"""Tests for SandboxExecutor and DeterministicOracle."""

import pytest
from scannex.db.models import CanaryType, PatchSpec, ProbeSpec
from scannex.sandbox.executor import SandboxExecutor
from scannex.sandbox.oracle import DeterministicOracle


def test_oracle_reflected_canary_tripped():
    oracle = DeterministicOracle()
    probe = ProbeSpec(
        endpoint="/test",
        method="GET",
        canary_type=CanaryType.REFLECTED,
        canary_token="SCANX_CANARY_SECRET123",
    )

    class MockResponse:
        status_code = 200
        text = "Welcome admin! Canary reflected: SCANX_CANARY_SECRET123 in payload."
        headers = {}

    result = oracle.evaluate_http_response(probe, MockResponse())
    assert result.success is True
    assert result.canary_tripped is True
    assert "SCANX_CANARY_SECRET123" in result.response_snippet


def test_oracle_error_not_tripped():
    oracle = DeterministicOracle()
    probe = ProbeSpec(
        endpoint="/test",
        method="GET",
        canary_type=CanaryType.REFLECTED,
        canary_token="SCANX_CANARY_SECRET123",
    )

    class MockErrorResponse:
        status_code = 500
        text = "Internal Server Error: ZeroDivisionError"
        headers = {}

    result = oracle.evaluate_http_response(probe, MockErrorResponse())
    assert result.canary_tripped is False


@pytest.mark.asyncio
async def test_sandbox_executor_end_to_end(tmp_path):
    # Create a small vulnerable Flask app
    app_file = tmp_path / "app.py"
    app_file.write_text("""
import sys, argparse
from flask import Flask, request

app = Flask(__name__)

@app.route('/query')
def query():
    val = request.args.get('q', '')
    # Vulnerable reflection
    return f"Result: {val}"

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=5000)
    args = parser.parse_args()
    app.run(host='127.0.0.1', port=args.port)
""", encoding="utf-8")

    executor = SandboxExecutor(tmp_path)
    try:
        await executor.start()
        assert executor.port > 0

        # Fire probe
        probe = ProbeSpec(
            endpoint="/query",
            method="GET",
            params={"q": "SCANX_CANARY_LIVE_TEST"},
            canary_type=CanaryType.REFLECTED,
            canary_token="SCANX_CANARY_LIVE_TEST",
        )

        probe_result = await executor.execute_probe(probe)
        assert probe_result.success is True
        assert probe_result.canary_tripped is True

        # Now test speculative patch
        patch = PatchSpec(
            file_path="app.py",
            search_block='return f"Result: {val}"',
            replace_block='return "Result: [Sanitized]"',
        )

        is_fixed, retest_result = await executor.test_patch(patch, probe)
        assert is_fixed is True
        assert retest_result.canary_tripped is False

    finally:
        executor.teardown()
