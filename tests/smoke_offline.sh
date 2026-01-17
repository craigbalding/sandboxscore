#!/bin/bash
# Smoke test: verify network tests are disabled by default
set -e
cd "$(dirname "$0")/.."

echo "Running smoke_offline test..."

# Run without network flag, get JSON output
output=$(./agents/run.sh -f json 2>/dev/null)

# Check that network tests are marked as skipped (not exposed or blocked)
if ! echo "$output" | grep -q '"outbound_http": "skipped"'; then
    echo "FAIL: outbound_http should be skipped by default"
    exit 1
fi

if ! echo "$output" | grep -q '"dns_resolution": "skipped"'; then
    echo "FAIL: dns_resolution should be skipped by default"
    exit 1
fi

# Check egress tests are also skipped
if ! echo "$output" | grep -q '"egress_connectivity": "skipped"'; then
    echo "FAIL: egress_connectivity should be skipped by default"
    exit 1
fi

echo "PASS: smoke_offline"
