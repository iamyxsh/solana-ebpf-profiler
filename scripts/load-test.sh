#!/bin/bash
# Generate diverse transaction load against a solana-test-validator.
# Usage: ./scripts/load-test.sh [duration_seconds]
#
# Requires: solana CLI, spl-token CLI
# The test validator must already be running on localhost:8899.

set -e

DURATION=${1:-1200}  # default 20 minutes
RPC_URL="http://127.0.0.1:8899"

export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"

# Check prerequisites
command -v solana >/dev/null || { echo "error: solana CLI not found"; exit 1; }

echo "=== load test: ${DURATION}s of diverse transactions ==="

solana config set --url "$RPC_URL" 2>/dev/null

# Create and fund wallets
echo "creating wallets..."
for i in $(seq 1 5); do
    solana-keygen new --no-bip39-passphrase -o /tmp/wallet-$i.json --force 2>/dev/null
done

echo "funding wallets..."
for i in $(seq 1 5); do
    solana airdrop 1000 "$(solana-keygen pubkey /tmp/wallet-$i.json)" 2>/dev/null || true
done
sleep 2

W1=$(solana-keygen pubkey /tmp/wallet-1.json)
W2=$(solana-keygen pubkey /tmp/wallet-2.json)
W3=$(solana-keygen pubkey /tmp/wallet-3.json)

# Create a token mint for token operations
echo "creating token mint..."
HAS_SPL=false
if command -v spl-token >/dev/null 2>&1; then
    MINT=$(spl-token create-token --owner /tmp/wallet-1.json 2>/dev/null | grep "Creating token" | awk '{print $3}')
    if [ -n "$MINT" ]; then
        echo "mint: $MINT"
        spl-token create-account "$MINT" --owner /tmp/wallet-1.json 2>/dev/null || true
        spl-token create-account "$MINT" --owner /tmp/wallet-2.json 2>/dev/null || true
        spl-token mint "$MINT" 1000000 --mint-authority /tmp/wallet-1.json 2>/dev/null || true
        HAS_SPL=true
        echo "token setup done"
    fi
fi

echo "starting transaction loop..."
START=$(date +%s)
COUNTER=0
ERRORS=0

while [ $(($(date +%s) - START)) -lt "$DURATION" ]; do
    case $((COUNTER % 5)) in
        0) # SOL transfer
            solana transfer --from /tmp/wallet-1.json "$W2" 0.001 \
                --allow-unfunded-recipient --no-wait 2>/dev/null || ((ERRORS++))
            ;;
        1) # SOL transfer (different wallets)
            solana transfer --from /tmp/wallet-2.json "$W3" 0.001 \
                --allow-unfunded-recipient --no-wait 2>/dev/null || ((ERRORS++))
            ;;
        2) # SPL token transfer (if available)
            if [ "$HAS_SPL" = true ]; then
                spl-token transfer "$MINT" 1 "$W2" \
                    --from /tmp/wallet-1.json --fund-recipient --no-wait 2>/dev/null || ((ERRORS++))
            else
                solana transfer --from /tmp/wallet-3.json "$W1" 0.001 \
                    --allow-unfunded-recipient --no-wait 2>/dev/null || ((ERRORS++))
            fi
            ;;
        3) # SOL transfer with memo
            solana transfer --from /tmp/wallet-1.json "$W3" 0.001 \
                --allow-unfunded-recipient --no-wait \
                --with-memo "load-test-$COUNTER" 2>/dev/null || ((ERRORS++))
            ;;
        4) # Multiple transfers in quick succession
            for w in $W1 $W2 $W3; do
                solana transfer --from /tmp/wallet-$(( (COUNTER % 3) + 1 )).json "$w" 0.0001 \
                    --allow-unfunded-recipient --no-wait 2>/dev/null &
            done
            wait
            ;;
    esac

    COUNTER=$((COUNTER + 1))

    # Print progress every 100 transactions
    if [ $((COUNTER % 100)) -eq 0 ]; then
        ELAPSED=$(($(date +%s) - START))
        TPS=$((COUNTER / (ELAPSED + 1)))
        echo "  txns=$COUNTER elapsed=${ELAPSED}s tps~$TPS errors=$ERRORS"
    fi
done

echo "=== load test complete: $COUNTER transactions in ${DURATION}s ==="
