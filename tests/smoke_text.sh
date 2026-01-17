#!/bin/bash
# Smoke test: verify output redaction and basic functionality
set -e
cd "$(dirname "$0")/.."

echo "Running smoke_text test..."

# Run tool (offline, default redaction)
output=$(./agents/run.sh 2>&1)
exit_code=$?

# Check exit 0
if [[ $exit_code -ne 0 ]]; then
    echo "FAIL: exit code $exit_code (expected 0)"
    exit 1
fi

# Check no IP addresses in output (except placeholders like [IP])
if echo "$output" | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -v '\[IP\]' >/dev/null 2>&1; then
    echo "FAIL: IP address found in output"
    echo "$output" | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -3
    exit 1
fi

# Check no obvious user paths (like /Users/username/)
if echo "$output" | grep -E '/Users/[a-zA-Z0-9_]+/' >/dev/null 2>&1; then
    echo "FAIL: User path found in output"
    echo "$output" | grep -E '/Users/[a-zA-Z0-9_]+/' | head -3
    exit 1
fi

# Check version is 1.1.0
if ! echo "$output" | grep -q 'v1.1.0'; then
    echo "FAIL: Version 1.1.0 not found in output"
    exit 1
fi

echo "PASS: smoke_text"
