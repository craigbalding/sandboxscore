#!/bin/bash
# SandboxScore - Intelligence Module - Main Runner (macOS)
#
# Orchestrates all intelligence extraction modules.
# Requires: common.sh, intel_common.sh to be sourced first
#
# Phase 1: Process Intelligence (implemented)
# Phase 2: Network Topology (pending)
# Phase 3: Network Egress (implemented)
# Phase 4: File Intelligence (pending)
# Phase 5: Service Intelligence (pending)

# Get the directory where this script lives
DARWIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$(cd "$DARWIN_DIR/../../lib" && pwd)"

# =============================================================================
# Load Intelligence Modules
# =============================================================================

# Phase 1: Process Intelligence
if [[ -f "$DARWIN_DIR/intel_processes.sh" ]]; then
    source "$DARWIN_DIR/intel_processes.sh"
else
    warn "intel_processes.sh not found"
fi

# Phase 2: Network Topology
if [[ -f "$DARWIN_DIR/intel_network.sh" ]]; then
    source "$DARWIN_DIR/intel_network.sh"
else
    warn "intel_network.sh not found"
fi

# Phase 3: Network Egress (cross-platform, lives in lib/)
if [[ -f "$LIB_DIR/intel_egress.sh" ]]; then
    source "$LIB_DIR/intel_egress.sh"
else
    warn "intel_egress.sh not found"
fi

# Phase 4: File Intelligence
if [[ -f "$DARWIN_DIR/intel_files.sh" ]]; then
    source "$DARWIN_DIR/intel_files.sh"
else
    warn "intel_files.sh not found"
fi

# Phase 5: Service Intelligence
if [[ -f "$DARWIN_DIR/intel_services.sh" ]]; then
    source "$DARWIN_DIR/intel_services.sh"
else
    warn "intel_services.sh not found"
fi

# =============================================================================
# Main Runner
# =============================================================================

run_intelligence_tests() {
    debug "run_intelligence_tests: starting (darwin)"

    # Phase 1: Process Intelligence
    if type run_intel_processes_tests &>/dev/null; then
        run_intel_processes_tests
    fi

    # Phase 2: Network Topology
    if type run_intel_network_tests &>/dev/null; then
        run_intel_network_tests
    fi

    # Phase 3: Network Egress
    if type run_intel_egress_tests &>/dev/null; then
        run_intel_egress_tests
    fi

    # Phase 4: File Intelligence
    if type run_intel_files_tests &>/dev/null; then
        run_intel_files_tests
    fi

    # Phase 5: Service Intelligence
    if type run_intel_services_tests &>/dev/null; then
        run_intel_services_tests
    fi

    debug "run_intelligence_tests: complete"
}
