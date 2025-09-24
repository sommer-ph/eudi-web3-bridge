#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# zk-Proof CLI – EUDI Credential Wallet Binding
###############################################################################

echo
echo "------------------------------------------------------"
echo " zk-Proof CLI – EUDI Credential Wallet Binding"
echo "------------------------------------------------------"
echo

###############################################################################
# Ask for user ID
###############################################################################
read -rp "Enter user ID: " USER_ID
[[ -n "$USER_ID" ]] || { echo "Error: No user ID provided." >&2; exit 1; }

###############################################################################
# Paths and constants
###############################################################################
CIRCUIT_NAME="cred-bind"
BUILD_DIR="build"
INPUT_DIR="input/prepared"
SRC_FILE="../zk-backend/data/proof-preparation/${USER_ID}-credential-wallet-binding-extended.json"
DEST_FILE="${INPUT_DIR}/${USER_ID}-credential-wallet-binding-extended.json"
POT_FILE="../ptau/powersOfTau28_hez_final_22.ptau"

mkdir -p "$INPUT_DIR" "$BUILD_DIR"

# Perf logging
TIMESTAMP=$(date +%s)
UTC_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
PERF_FILE="${BUILD_DIR}/perf_${CIRCUIT_NAME}_${USER_ID}_${TIMESTAMP}.json"
perf_log=()

# Use Node with increased heap size for snarkjs
SNARKJS="node --max-old-space-size=8192 $(which snarkjs)"

###############################################################################
# Helper: Time measurement
###############################################################################
time_step() {
  local label="$1"
  shift
  local start_ns=$(date +%s%N)

  "$@"

  local end_ns=$(date +%s%N)
  local duration_ns=$((end_ns - start_ns))
  local duration_sec=$(awk "BEGIN {print ${duration_ns}/1000000000}")
  perf_log+=("{\"step\":\"$label\",\"seconds\":$duration_sec}")
}

###############################################################################
# Step 2:  Generate and verify proof using Rapidsnark (10 iterations)
###############################################################################
read -rp "Generate and verify proof using Rapidsnark 10 times? (y/N): " RUN_RAPIDSNARK

if [[ "$RUN_RAPIDSNARK" =~ ^[Yy]$ ]]; then
  echo
  echo "Running 10 iterations of proof generation and verification..."

  for i in {1..10}; do
    echo
    echo "=== Iteration $i/10 ==="

    # Reset perf log for this iteration
    perf_log=()

    echo "Step 8a: Generating proof with Rapidsnark (native prover) …"
    time_step "generate_proof_rapidsnark_iter_${i}" \
      prover \
        "${BUILD_DIR}/${CIRCUIT_NAME}.zkey" \
        "${BUILD_DIR}/${CIRCUIT_NAME}.wtns" \
        "${BUILD_DIR}/${CIRCUIT_NAME}.proof.bin" \
        "${BUILD_DIR}/${CIRCUIT_NAME}.public.json"

    echo "Step 8b: Verifying proof with Rapidsnark (native verifier) …"
    time_step "verify_proof_rapidsnark_iter_${i}" \
      verifier \
        "${BUILD_DIR}/${CIRCUIT_NAME}.vkey.json" \
        "${BUILD_DIR}/${CIRCUIT_NAME}.public.json" \
        "${BUILD_DIR}/${CIRCUIT_NAME}.proof.bin"

    echo "OK: Proof verified successfully with Rapidsnark (iteration $i)"

    # Write perf log for this iteration
    ITERATION_TIMESTAMP=$(date +%s)
    ITERATION_UTC_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    ITERATION_PERF_FILE="${BUILD_DIR}/perf_${CIRCUIT_NAME}_${USER_ID}_iter_${i}_${ITERATION_TIMESTAMP}.json"

    {
      echo "{"
      echo "  \"user_id\": \"${USER_ID}\","
      echo "  \"circuit\": \"${CIRCUIT_NAME}\","
      echo "  \"iteration\": ${i},"
      echo "  \"timestamp\": ${ITERATION_TIMESTAMP},"
      echo "  \"timestamp_utc\": \"${ITERATION_UTC_TIME}\","
      echo "  \"steps\": ["
      (IFS=,; echo "    ${perf_log[*]}")
      echo "  ]"
      echo "}"
    } > "$ITERATION_PERF_FILE"

    echo "Performance log for iteration $i saved to: $ITERATION_PERF_FILE"
  done

  echo
  echo "All 10 iterations completed successfully!"
fi

###############################################################################
# DONE
###############################################################################
echo "------------------------------------------------------"
echo " All steps completed successfully for user: ${USER_ID}"
echo "------------------------------------------------------"
