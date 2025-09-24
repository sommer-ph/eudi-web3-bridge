#!/usr/bin/env bash
set -euo pipefail

echo
echo "------------------------------------------------------"
echo " zk-Proof Performance Loop – EdDSA Signature Verification"
echo "------------------------------------------------------"
echo

###############################################################################
# Paths and constants
###############################################################################
CIRCUIT_NAME="signature-verification"
BUILD_DIR="build"

# Check if required artifacts exist
REQUIRED_FILES=(
  "${BUILD_DIR}/${CIRCUIT_NAME}.zkey"
  "${BUILD_DIR}/${CIRCUIT_NAME}.wtns"
  "${BUILD_DIR}/${CIRCUIT_NAME}.vkey.json"
  "${BUILD_DIR}/${CIRCUIT_NAME}.public.json"
)

echo "Checking required artifacts..."
for file in "${REQUIRED_FILES[@]}"; do
  if [[ ! -f "$file" ]]; then
    echo "ERROR: Required file not found: $file"
    echo "Please run the full proof-eddsa-sigVerify.sh script first to generate all artifacts."
    exit 1
  fi
done
echo "OK: All required artifacts found"
echo

# Performance logging setup
TIMESTAMP=$(date +%s)
UTC_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
PERF_FILE="${BUILD_DIR}/perf_${CIRCUIT_NAME}_loop_${TIMESTAMP}.json"
perf_log=()

# Loop configuration
DEFAULT_ITERATIONS=10
read -rp "Number of iterations (default: $DEFAULT_ITERATIONS): " ITERATIONS
ITERATIONS=${ITERATIONS:-$DEFAULT_ITERATIONS}

if ! [[ "$ITERATIONS" =~ ^[0-9]+$ ]] || [[ "$ITERATIONS" -lt 1 ]]; then
  echo "ERROR: Invalid number of iterations. Must be a positive integer."
  exit 1
fi

echo "Running $ITERATIONS iterations of proof generation and verification..."
echo

###############################################################################
# Helper: Time measurement
###############################################################################
time_step() {
  local label="$1"
  local iteration="$2"
  shift 2
  local start_ns=$(date +%s%N)

  "$@"

  local end_ns=$(date +%s%N)
  local duration_ns=$((end_ns - start_ns))
  local duration_sec=$(awk "BEGIN {print ${duration_ns}/1000000000}")
  perf_log+=("{\"step\":\"$label\",\"iteration\":$iteration,\"seconds\":$duration_sec}")
}

###############################################################################
# Performance Loop
###############################################################################
for i in $(seq 1 "$ITERATIONS"); do
  echo "--- Iteration $i/$ITERATIONS ---"

  # Generate proof with Rapidsnark
  echo "Generating proof with Rapidsnark (iteration $i)..."
  time_step "generate_proof_rapidsnark" "$i" \
    prover \
      "${BUILD_DIR}/${CIRCUIT_NAME}.zkey" \
      "${BUILD_DIR}/${CIRCUIT_NAME}.wtns" \
      "${BUILD_DIR}/${CIRCUIT_NAME}_loop_${i}.proof.bin" \
      "${BUILD_DIR}/${CIRCUIT_NAME}_loop_${i}.public.json"

  # Verify proof with Rapidsnark
  echo "Verifying proof with Rapidsnark (iteration $i)..."
  time_step "verify_proof_rapidsnark" "$i" \
    verifier \
      "${BUILD_DIR}/${CIRCUIT_NAME}.vkey.json" \
      "${BUILD_DIR}/${CIRCUIT_NAME}_loop_${i}.public.json" \
      "${BUILD_DIR}/${CIRCUIT_NAME}_loop_${i}.proof.bin"

  echo "OK: Iteration $i completed"
  echo
done

###############################################################################
# Calculate statistics
###############################################################################
echo "Calculating performance statistics..."

# Extract timing data for analysis
prove_times=()
verify_times=()

for entry in "${perf_log[@]}"; do
  if echo "$entry" | grep -q "generate_proof_rapidsnark"; then
    time=$(echo "$entry" | grep -o '"seconds":[0-9.]*' | cut -d: -f2)
    prove_times+=("$time")
  elif echo "$entry" | grep -q "verify_proof_rapidsnark"; then
    time=$(echo "$entry" | grep -o '"seconds":[0-9.]*' | cut -d: -f2)
    verify_times+=("$time")
  fi
done

# Calculate averages using awk
avg_prove_time=$(printf '%s\n' "${prove_times[@]}" | awk '{sum+=$1} END {print sum/NR}')
avg_verify_time=$(printf '%s\n' "${verify_times[@]}" | awk '{sum+=$1} END {print sum/NR}')

# Calculate min/max
min_prove_time=$(printf '%s\n' "${prove_times[@]}" | sort -n | head -1)
max_prove_time=$(printf '%s\n' "${prove_times[@]}" | sort -n | tail -1)
min_verify_time=$(printf '%s\n' "${verify_times[@]}" | sort -n | head -1)
max_verify_time=$(printf '%s\n' "${verify_times[@]}" | sort -n | tail -1)

###############################################################################
# Write performance log
###############################################################################
{
  echo "{"
  echo "  \"circuit\": \"${CIRCUIT_NAME}\","
  echo "  \"timestamp\": ${TIMESTAMP},"
  echo "  \"timestamp_utc\": \"${UTC_TIME}\","
  echo "  \"iterations\": ${ITERATIONS},"
  echo "  \"statistics\": {"
  echo "    \"prove\": {"
  echo "      \"average_seconds\": ${avg_prove_time},"
  echo "      \"min_seconds\": ${min_prove_time},"
  echo "      \"max_seconds\": ${max_prove_time}"
  echo "    },"
  echo "    \"verify\": {"
  echo "      \"average_seconds\": ${avg_verify_time},"
  echo "      \"min_seconds\": ${min_verify_time},"
  echo "      \"max_seconds\": ${max_verify_time}"
  echo "    }"
  echo "  },"
  echo "  \"detailed_steps\": ["
  (IFS=,; echo "    ${perf_log[*]}")
  echo "  ]"
  echo "}"
} > "$PERF_FILE"

###############################################################################
# Cleanup temporary files
###############################################################################
echo "Cleaning up temporary proof files..."
for i in $(seq 1 "$ITERATIONS"); do
  rm -f "${BUILD_DIR}/${CIRCUIT_NAME}_loop_${i}.proof.bin"
  rm -f "${BUILD_DIR}/${CIRCUIT_NAME}_loop_${i}.public.json"
done

###############################################################################
# Results
###############################################################################
echo "------------------------------------------------------"
echo " Performance Results (${ITERATIONS} iterations)"
echo "------------------------------------------------------"
echo "Proof Generation (Rapidsnark):"
echo "  Average: ${avg_prove_time}s"
echo "  Min:     ${min_prove_time}s"
echo "  Max:     ${max_prove_time}s"
echo
echo "Proof Verification (Rapidsnark):"
echo "  Average: ${avg_verify_time}s"
echo "  Min:     ${min_verify_time}s"
echo "  Max:     ${max_verify_time}s"
echo
echo "Performance log saved to: $PERF_FILE"
echo
echo "------------------------------------------------------"
echo " Performance loop completed successfully"
echo "------------------------------------------------------"