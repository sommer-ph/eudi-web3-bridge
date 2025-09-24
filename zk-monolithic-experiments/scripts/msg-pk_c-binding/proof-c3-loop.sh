#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# zk-Proof Performance Loop – c3-with-hash (Rapidsnark Only)
###############################################################################

echo
echo "------------------------------------------------------"
echo " zk-Proof Performance Loop – c3-with-hash"
echo " Running 10 iterations of proof generation and verification"
echo "------------------------------------------------------"
echo

###############################################################################
# Paths and constants
###############################################################################
CIRCUIT_NAME="c3-with-hash"
BUILD_DIR="build"
LOOPS=10

# Check if required artifacts exist
if [ ! -f "${BUILD_DIR}/${CIRCUIT_NAME}.zkey" ]; then
    echo "ERROR: ${BUILD_DIR}/${CIRCUIT_NAME}.zkey not found. Please run proof-c3.sh first."
    exit 1
fi

if [ ! -f "${BUILD_DIR}/${CIRCUIT_NAME}.wtns" ]; then
    echo "ERROR: ${BUILD_DIR}/${CIRCUIT_NAME}.wtns not found. Please run proof-c3.sh first."
    exit 1
fi

if [ ! -f "${BUILD_DIR}/${CIRCUIT_NAME}.vkey.json" ]; then
    echo "ERROR: ${BUILD_DIR}/${CIRCUIT_NAME}.vkey.json not found. Please run proof-c3.sh first."
    exit 1
fi

# Perf logging
TIMESTAMP=$(date +%s)
UTC_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
PERF_FILE="${BUILD_DIR}/perf_${CIRCUIT_NAME}_loop_${TIMESTAMP}.json"
perf_log=()

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
echo "Starting performance measurements..."
echo

for i in $(seq 1 $LOOPS); do
    echo "Iteration $i/$LOOPS"

    # Generate proof with Rapidsnark
    echo "  Generating proof with Rapidsnark..."
    time_step "generate_proof_rapidsnark" $i \
      prover \
        "${BUILD_DIR}/${CIRCUIT_NAME}.zkey" \
        "${BUILD_DIR}/${CIRCUIT_NAME}.wtns" \
        "${BUILD_DIR}/${CIRCUIT_NAME}_loop_${i}.proof.bin" \
        "${BUILD_DIR}/${CIRCUIT_NAME}_loop_${i}.public.json"

    # Verify proof with Rapidsnark
    echo "  Verifying proof with Rapidsnark..."
    time_step "verify_proof_rapidsnark" $i \
      verifier \
        "${BUILD_DIR}/${CIRCUIT_NAME}.vkey.json" \
        "${BUILD_DIR}/${CIRCUIT_NAME}_loop_${i}.public.json" \
        "${BUILD_DIR}/${CIRCUIT_NAME}_loop_${i}.proof.bin"

    echo "  ✓ Iteration $i completed"
    echo
done

###############################################################################
# Calculate statistics
###############################################################################
echo "Calculating performance statistics..."

# Extract proof generation times
prove_times=$(echo "${perf_log[@]}" | grep -o '"step":"generate_proof_rapidsnark"[^}]*"seconds":[0-9.]*' | grep -o '[0-9.]*$')
# Extract verification times
verify_times=$(echo "${perf_log[@]}" | grep -o '"step":"verify_proof_rapidsnark"[^}]*"seconds":[0-9.]*' | grep -o '[0-9.]*$')

# Calculate averages using awk
prove_avg=$(echo "$prove_times" | awk '{sum+=$1; count++} END {print sum/count}')
verify_avg=$(echo "$verify_times" | awk '{sum+=$1; count++} END {print sum/count}')

# Calculate min/max
prove_min=$(echo "$prove_times" | awk 'NR==1{min=$1} {if($1<min) min=$1} END {print min}')
prove_max=$(echo "$prove_times" | awk 'NR==1{max=$1} {if($1>max) max=$1} END {print max}')
verify_min=$(echo "$verify_times" | awk 'NR==1{min=$1} {if($1<min) min=$1} END {print min}')
verify_max=$(echo "$verify_times" | awk 'NR==1{max=$1} {if($1>max) max=$1} END {print max}')

###############################################################################
# Write perf log
###############################################################################
{
  echo "{"
  echo "  \"circuit\": \"${CIRCUIT_NAME}\","
  echo "  \"timestamp\": ${TIMESTAMP},"
  echo "  \"timestamp_utc\": \"${UTC_TIME}\","
  echo "  \"iterations\": ${LOOPS},"
  echo "  \"statistics\": {"
  echo "    \"prove_gen\": {"
  echo "      \"avg_seconds\": $prove_avg,"
  echo "      \"min_seconds\": $prove_min,"
  echo "      \"max_seconds\": $prove_max"
  echo "    },"
  echo "    \"verify\": {"
  echo "      \"avg_seconds\": $verify_avg,"
  echo "      \"min_seconds\": $verify_min,"
  echo "      \"max_seconds\": $verify_max"
  echo "    }"
  echo "  },"
  echo "  \"detailed_measurements\": ["
  (IFS=,; echo "    ${perf_log[*]}")
  echo "  ]"
  echo "}"
} > "$PERF_FILE"

###############################################################################
# Summary
###############################################################################
echo "------------------------------------------------------"
echo " Performance Summary for ${CIRCUIT_NAME}"
echo "------------------------------------------------------"
echo "Iterations: ${LOOPS}"
echo
echo "Proof Generation (Rapidsnark):"
echo "  Average: ${prove_avg}s"
echo "  Min:     ${prove_min}s"
echo "  Max:     ${prove_max}s"
echo
echo "Proof Verification (Rapidsnark):"
echo "  Average: ${verify_avg}s"
echo "  Min:     ${verify_min}s"
echo "  Max:     ${verify_max}s"
echo
echo "Detailed performance log saved to: $PERF_FILE"
echo "------------------------------------------------------"

###############################################################################
# Cleanup temporary files
###############################################################################
echo "Cleaning up temporary proof files..."
rm -f ${BUILD_DIR}/${CIRCUIT_NAME}_loop_*.proof.bin
rm -f ${BUILD_DIR}/${CIRCUIT_NAME}_loop_*.public.json
echo "✓ Cleanup completed"
echo