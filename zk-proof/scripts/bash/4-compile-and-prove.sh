#!/usr/bin/env bash
set -euo pipefail

USER_ID=$1
MODE=${2:-1}  # Optional fallback
BUILD_DIR="build"
INPUT_DIR="input/prepared"
POT_FILE="powersOfTau28_hez_final_22.ptau"
CIRCOM_LIBS="../../circom-libs"
SNARKJS_DEBUG=1
export SNARKJS_DEBUG

function msg() {
  echo -e "\n\033[1;36m$*\033[0m"
}

# Determine circuit name based on mode
case "$MODE" in
  1)  CIRCUIT_NAME="monolith" ;;
  3)  CIRCUIT_NAME="cred-bind" ;;
  4)  CIRCUIT_NAME="key-bind" ;;
  5)
    # Attempt to infer from existing prepared input
    SUB_FILE=$(find "$INPUT_DIR" -name "${USER_ID}-*.json" | head -n 1)
    if [[ -z "$SUB_FILE" ]]; then
      echo "No input file found for sub-proof (user: $USER_ID)"
      exit 1
    fi
    CIRCUIT_NAME=$(basename "$SUB_FILE" | cut -d '-' -f2 | cut -d '.' -f1)
    ;;
  *) echo "Unsupported mode: $MODE"; exit 1 ;;
esac

INPUT_FILE="${INPUT_DIR}/${USER_ID}-${CIRCUIT_NAME}.json"

# Validate
if [[ ! -f "$INPUT_FILE" ]]; then
  echo "Input file not found: $INPUT_FILE"
  exit 1
fi

mkdir -p "$BUILD_DIR"

# Step 1: Compile circuit
msg "1/6  Compile circuit: $CIRCUIT_NAME"
circom "circuits/${CIRCUIT_NAME}.circom" \
       --r1cs --wasm --sym \
       -l "$CIRCOM_LIBS" \
       -l node_modules \
       -o "$BUILD_DIR"

# Step 2: Generate witness
msg "2/6  Generate witness..."
pushd "$BUILD_DIR" >/dev/null
node "${CIRCUIT_NAME}_js/generate_witness.js" \
     "${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm" \
     "../${INPUT_FILE}" \
     "witness.wtns"

# Step 3: Setup Groth16
msg "3/6  Setup Groth16..."
snarkjs groth16 setup \
        "${CIRCUIT_NAME}.r1cs" \
        "../${POT_FILE}" \
        "${CIRCUIT_NAME}_final.zkey"

# Step 4: Export verification key
msg "4/6  Export verification key..."
snarkjs zkey export verificationkey \
        "${CIRCUIT_NAME}_final.zkey" \
        "verification_key.json"

# Step 5: Generate proof
msg "5/6  Generate proof..."
snarkjs groth16 prove \
        "${CIRCUIT_NAME}_final.zkey" \
        "witness.wtns" \
        "proof.json" \
        "public.json"

# Step 6: Verify proof
msg "6/6  Verify proof..."
snarkjs groth16 verify \
        "verification_key.json" \
        "public.json" \
        "proof.json"

popd >/dev/null
msg "DONE: Proof generated and verified for '$CIRCUIT_NAME'"
