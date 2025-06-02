#!/usr/bin/env bash
set -euo pipefail

# Configuration
CIRCUIT_NAME="ecdsa-verify"
BUILD_DIR="build"
INPUT_FILE="input/prepared-input.json"
POT_FILE="powersOfTau28_hez_final_22.ptau"
CIRCOM_LIBS="../../circom-libs"

# Helper
function msg() { echo -e "\n\033[1;36m$*\033[0m"; }   # Cyan-fett

# 1. Compile circuit
msg "1/6  Compile circuit..."
circom "circuits/${CIRCUIT_NAME}.circom" \
       --r1cs --wasm --sym \
       -l "$CIRCOM_LIBS" \
       -l node_modules \
       -o "$BUILD_DIR"

# 2. Generate witness
msg "2/6  Generate witness..."
pushd "$BUILD_DIR" >/dev/null
node "${CIRCUIT_NAME}_js/generate_witness.js" \
     "${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm" \
     "../${INPUT_FILE}" \
     "witness.wtns"

# 3. Setup Groth16
msg "3/6  Setup Groth16..."
snarkjs groth16 setup \
        "${CIRCUIT_NAME}.r1cs" \
        "../${POT_FILE}" \
        "${CIRCUIT_NAME}_final.zkey"

# 4. Export verification-key
msg "4/6  Export verification-key..."
snarkjs zkey export verificationkey \
        "${CIRCUIT_NAME}_final.zkey" \
        "verification_key.json"

# 5. Generate proof
msg "5/6  Generate proof..."
snarkjs groth16 prove \
        "${CIRCUIT_NAME}_final.zkey" \
        "witness.wtns" \
        "proof.json" \
        "public.json"

# 6. Verify proof
msg "6/6  Verify proof..."
snarkjs groth16 verify \
        "verification_key.json" \
        "public.json" \
        "proof.json"

popd >/dev/null
msg "DONE: Circuit, witness, proof & verification successfull!"
