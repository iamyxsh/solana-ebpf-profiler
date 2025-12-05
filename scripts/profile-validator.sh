#!/bin/bash
# Start a test validator, generate load, and profile it.
# Usage: ./scripts/profile-validator.sh [duration_seconds]
#
# Opens a live dashboard at http://localhost:3000

set -e

DURATION=${1:-120}  # default 2 minutes
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"

echo "=== solana validator profiler ==="
echo "duration: ${DURATION}s"
echo ""

# Start test validator
echo "starting test validator..."
pkill -f solana-test-validator 2>/dev/null || true
sleep 2
rm -rf /tmp/test-ledger
solana-test-validator --ledger /tmp/test-ledger --quiet --ticks-per-slot 8 &
VALIDATOR_PID=$!
echo "validator pid=$VALIDATOR_PID"

# Wait for readiness
echo "waiting for validator..."
until solana cluster-version --url http://127.0.0.1:8899 2>/dev/null; do
    sleep 1
done
echo ""

# Start load generation in background
echo "starting load generator..."
bash "$SCRIPT_DIR/load-test.sh" "$DURATION" &
LOAD_PID=$!

# Wait for some transactions to flow
sleep 5

# Build profiler if needed
if [ ! -f "$PROJECT_DIR/target/release/profiler" ]; then
    echo "building profiler..."
    cd "$PROJECT_DIR" && cargo build --release
fi

# Run profiler with auto-detection
echo "starting profiler (dashboard at http://localhost:3000)..."
cd "$PROJECT_DIR"
sudo ./target/release/profiler \
    --duration "$DURATION" \
    --output flamegraph.svg \
    --output-dir flamegraphs \
    --port 3000

# Cleanup
echo ""
echo "cleaning up..."
kill $LOAD_PID 2>/dev/null || true
kill $VALIDATOR_PID 2>/dev/null || true
pkill -f solana-test-validator 2>/dev/null || true
pkill -f "solana transfer" 2>/dev/null || true

echo "done. open flamegraph.svg or check flamegraphs/ for per-program SVGs."
