#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# zk-Proof CLI – EUDI Credential Wallet Binding
#
# This script orchestrates the complete zero-knowledge proof generation pipeline
# for EUDI (European Digital Identity) credential wallet binding.
#
# The process includes:
# 1. Circuit compilation (Circom)
# 2. Witness generation from input data
# 3. Trusted setup (Groth16)
# 4. Proof generation and verification
# 5. Optional Rapidsnark native proving/verification
# 6. Performance logging
#
# Usage: ./proof.sh
# The script will prompt for a user ID and process the corresponding credential data.
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
SRC_FILE="../zk-backend/data/proof-preparation/${USER_ID}-credential-wallet-binding.json"
DEST_FILE="${INPUT_DIR}/${USER_ID}-credential-wallet-binding.json"
POT_FILE="../ptau/powersOfTau28_hez_final_22.ptau"

mkdir -p "$INPUT_DIR" "$BUILD_DIR"

# Performance logging setup
TIMESTAMP=$(date +%s)
UTC_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
PERF_FILE="${BUILD_DIR}/perf_${CIRCUIT_NAME}_${USER_ID}_${TIMESTAMP}.json"
perf_log=()

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
# Step 1: Copy input JSON
###############################################################################
echo "Step 1: Copying input file from backend …"
time_step "copy_input" bash -c "
  [[ -f \"$SRC_FILE\" ]] || { echo \"Error: Missing input file: $SRC_FILE\" >&2; exit 1; }
  cp -f \"$SRC_FILE\" \"$DEST_FILE\"
"
echo "OK: Copied input file to ${DEST_FILE}"
echo

###############################################################################
# Step 2: Compile circuit
###############################################################################
echo "Step 2: Compiling circuit …"
time_step "compile_circuit" circom "circuits/${CIRCUIT_NAME}/${CIRCUIT_NAME}.circom" \
  --r1cs --wasm --sym \
  -l ../circom_libs -l node_modules \
  -o "$BUILD_DIR"
echo "OK: Circuit compiled"
echo

###############################################################################
# Step 3: Generate witness
###############################################################################
echo "Step 3: Generating witness …"
time_step "generate_witness" node "${BUILD_DIR}/${CIRCUIT_NAME}_js/generate_witness.js" \
  "${BUILD_DIR}/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm" \
  "$DEST_FILE" \
  "${BUILD_DIR}/${CIRCUIT_NAME}.wtns"
echo "OK: Witness generated"
echo

###############################################################################
# Step 4: Trusted setup
###############################################################################
echo "Step 4: Running Groth16 trusted setup …"
time_step "trusted_setup" snarkjs groth16 setup \
  "${BUILD_DIR}/${CIRCUIT_NAME}.r1cs" \
  "$POT_FILE" \
  "${BUILD_DIR}/${CIRCUIT_NAME}.zkey"
echo "OK: Trusted setup completed"
echo

###############################################################################
# Step 5: Export verification key
###############################################################################
echo "Step 5: Exporting verification key …"
time_step "export_vk" snarkjs zkey export verificationkey \
  "${BUILD_DIR}/${CIRCUIT_NAME}.zkey" \
  "${BUILD_DIR}/${CIRCUIT_NAME}.vkey.json"
echo "OK: Verification key exported"
echo

###############################################################################
# Step 6: Generate proof
###############################################################################
echo "Step 6: Generating proof …"
time_step "generate_proof" snarkjs groth16 prove \
  "${BUILD_DIR}/${CIRCUIT_NAME}.zkey" \
  "${BUILD_DIR}/${CIRCUIT_NAME}.wtns" \
  "${BUILD_DIR}/${CIRCUIT_NAME}.proof.json" \
  "${BUILD_DIR}/${CIRCUIT_NAME}.public.json"
echo "OK: Proof generated"
echo

###############################################################################
# Step 7: Verify proof
###############################################################################
echo "Step 7: Verifying proof …"
time_step "verify_proof" snarkjs groth16 verify \
  "${BUILD_DIR}/${CIRCUIT_NAME}.vkey.json" \
  "${BUILD_DIR}/${CIRCUIT_NAME}.public.json" \
  "${BUILD_DIR}/${CIRCUIT_NAME}.proof.json"
echo "OK: Proof verified successfully"
echo

###############################################################################
# Optional Step 8:  Generate and verify proof using Rapidsnark
###############################################################################
read -rp "Generate and verify proof using Rapidsnark? (y/N): " RUN_RAPIDSNARK

if [[ "$RUN_RAPIDSNARK" =~ ^[Yy]$ ]]; then
  echo
  echo "Step 8a: Generating proof with Rapidsnark (native prover) …"
  time_step "generate_proof_rapidsnark" \
    prover \
      "${BUILD_DIR}/${CIRCUIT_NAME}.zkey" \
      "${BUILD_DIR}/${CIRCUIT_NAME}.wtns" \
      "${BUILD_DIR}/${CIRCUIT_NAME}.proof.bin" \
      "${BUILD_DIR}/${CIRCUIT_NAME}.public.json"

  echo
  echo "Step 8b: Verifying proof with Rapidsnark (native verifier) …"
  time_step "verify_proof_rapidsnark" \
    verifier \
      "${BUILD_DIR}/${CIRCUIT_NAME}.vkey.json" \
      "${BUILD_DIR}/${CIRCUIT_NAME}.public.json" \
      "${BUILD_DIR}/${CIRCUIT_NAME}.proof.bin"

  echo "OK: Proof verified successfully with Rapidsnark"
  echo
fi

###############################################################################
# Write perf log
###############################################################################
{
  echo "{"
  echo "  \"user_id\": \"${USER_ID}\","
  echo "  \"circuit\": \"${CIRCUIT_NAME}\","
  echo "  \"timestamp\": ${TIMESTAMP},"
  echo "  \"timestamp_utc\": \"${UTC_TIME}\","
  echo "  \"steps\": ["
  (IFS=,; echo "    ${perf_log[*]}")
  echo "  ]"
  echo "}"
} > "$PERF_FILE"

echo "Performance log saved to: $PERF_FILE"
echo

###############################################################################
# DONE
###############################################################################
echo "------------------------------------------------------"
echo " All steps completed successfully for user: ${USER_ID}"
echo "------------------------------------------------------"
