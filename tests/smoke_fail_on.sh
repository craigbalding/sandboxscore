#!/bin/bash
# Smoke test: verify --fail-on policy exits with code 1
cd "$(dirname "$0")/.."

echo "Running smoke_fail_on test..."

# Run with very low threshold (should fail since any points lost)
set +e
./agents/run.sh --fail-on "score>=0" >/dev/null 2>&1
exit_code=$?
set -e

if [[ $exit_code -ne 1 ]]; then
    echo "FAIL: expected exit 1 with score>=0, got $exit_code"
    exit 1
fi

# Run with very high threshold (should pass)
./agents/run.sh --fail-on "score>=10000" >/dev/null 2>&1
exit_code=$?

if [[ $exit_code -ne 0 ]]; then
    echo "FAIL: expected exit 0 with score>=10000, got $exit_code"
    exit 1
fi

# Test exposures>=1000 (should pass since unlikely to have that many)
./agents/run.sh --fail-on "exposures>=1000" >/dev/null 2>&1
exit_code=$?

if [[ $exit_code -ne 0 ]]; then
    echo "FAIL: expected exit 0 with exposures>=1000, got $exit_code"
    exit 1
fi

# Test grade<=C (should fail if grade is D or F, which it likely is)
set +e
./agents/run.sh --fail-on "grade<=C" >/dev/null 2>&1
exit_code=$?
set -e

# We just verify the command runs without error - actual result depends on environment
if [[ $exit_code -ne 0 && $exit_code -ne 1 ]]; then
    echo "FAIL: unexpected exit code $exit_code for grade<=C"
    exit 1
fi

echo "PASS: smoke_fail_on"
