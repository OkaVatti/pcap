#!/usr/bin/env bash
#
# Continuous Integration script for the pcap Crystal shard.
# Runs tests, lints, and builds in various configurations.
#
# Usage:
#   ./ci.sh
#
# Environment variables:
#   TEST_LIVE=1        - enable live‑device tests (requires a working interface)
#   TEST_REMOTE=1      - enable remote capture tests (requires a remote server)
#   TEST_REMOTE_SOURCE - remote source string (e.g., rpcap://host/interface)

set -euo pipefail

# Colours for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Helper: print a section header
section() {
    echo -e "${GREEN}>>> $*${NC}"
}

# Check Crystal version
crystal_version=$(crystal --version | head -1)
section "Using Crystal: $crystal_version"

# Install dependencies
section "Installing shard dependencies"
shards install --ignore-crystal-version || shards install

# Lint with Ameba (if installed)
if shards list | grep -q ameba; then
    section "Running Ameba (linting)"
    bin/ameba || true  # don't fail on lint warnings
else
    echo "Ameba not installed; skipping lint."
fi

# Build with debug
section "Building in debug mode"
crystal build src/libpcap.cr --error-trace

# Build with release
section "Building in release mode"
crystal build src/libpcap.cr --error-trace --release

# Build with optional flags (remote, protocol)
section "Building with -D remote"
crystal build src/libpcap.cr -D remote --error-trace

section "Building with -D protocol"
crystal build src/libpcap.cr -D protocol --error-trace

section "Building with -D remote -D protocol"
crystal build src/libpcap.cr -D remote -D protocol --error-trace

# Run specs (without live tests by default)
section "Running specs (without live devices)"
crystal spec

# Run specs with live device tests if requested
if [ "${TEST_LIVE:-0}" = "1" ]; then
    section "Running specs with live device tests (TEST_LIVE=1)"
    crystal spec -D remote -D protocol
fi

# Run remote capture tests if requested
if [ "${TEST_REMOTE:-0}" = "1" ]; then
    section "Running remote capture tests (TEST_REMOTE=1)"
    TEST_REMOTE_SOURCE="${TEST_REMOTE_SOURCE:-rpcap://localhost/eth0}" \
    crystal spec -D remote
fi

# Generate documentation (optional)
section "Generating API documentation"
crystal docs

section "All tasks completed successfully."