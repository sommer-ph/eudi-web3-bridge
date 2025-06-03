#!/bin/bash

set -e

CIRCUIT_NAME=ecdsa-verify
BUILD_DIR=build
INPUT_FILE=input/prepared-input.json
POT_FILE=powersOfTau28_hez_final_10.ptau

# 0. Setup (nur beim ersten Mal nötig)
if [ ! -f $POT_FILE ]; then
  echo "🔧 Lade Powers of Tau (ptau)..."
  curl -o $POT_FILE https://hermez.s3-eu-west-1.amazonaws.com/$POT_FILE
fi

# 1. Compile
circom circuits/$CIRCUIT_NAME.circom \
  --r1cs --wasm --sym \
  -l node_modules \
  -l ../../circom-libs \
  -o $BUILD_DIR

# 2. Witness generieren
cd $BUILD_DIR
node ${CIRCUIT_NAME}_js/generate_witness.js ${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm ../$INPUT_FILE witness.wtns

# 3. Setup Phase 2
snarkjs groth16 setup ${CIRCUIT_NAME}.r1cs ../$POT_FILE ${CIRCUIT_NAME}_final.zkey

# 4. Export Verification Key
snarkjs zkey export verificationkey ${CIRCUIT_NAME}_final.zkey verification_key.json

# 5. Proof erzeugen
snarkjs groth16 prove ${CIRCUIT_NAME}_final.zkey witness.wtns proof.json public.json

# 6. Proof verifizieren
snarkjs groth16 verify verification_key.json public.json proof.json


#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Konfiguration
###############################################################################
CIRCUIT_NAME="ecdsa-verify"
BUILD_DIR="build"
INPUT_FILE="input/prepared-input.json"
POT_FILE="powersOfTau28_hez_final_10.ptau"
CIRCOM_LIBS="../../circom-libs"  # nur die Circom-2-Lib

###############################################################################
# Helper
###############################################################################
function msg() { echo -e "\n\033[1;36m$*\033[0m"; }   # Cyan-fett

###############################################################################
# 0. Powers-of-Tau einmalig laden
###############################################################################
if [[ ! -f $POT_FILE ]]; then
  msg "🔧  Lade Powers of Tau ..."
  curl -L -o "$POT_FILE" \
       "https://hermez.s3-eu-west-1.amazonaws.com/${POT_FILE}"
fi

###############################################################################
# 1. Circuit kompilieren  (~30-60 s)
###############################################################################
msg "🛠️  1/6  Compiliere Circuit …"
circom "circuits/${CIRCUIT_NAME}.circom" \
       --r1cs --wasm --sym \
       -l "$CIRCOM_LIBS" \
       -o "$BUILD_DIR"

###############################################################################
# 2. Witness generieren  (mehrere Minuten)
###############################################################################
msg "🧮  2/6  Generiere Witness … (kann 2-10 min dauern)"
pushd "$BUILD_DIR" >/dev/null
node "${CIRCUIT_NAME}_js/generate_witness.js" \
     "${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm" \
     "../${INPUT_FILE}" \
     "witness.wtns"

###############################################################################
# 3. Groth16-Setup  (~1 min)
###############################################################################
msg "⚙️  3/6  Groth16 Setup Phase 2 …"
snarkjs groth16 setup \
        "${CIRCUIT_NAME}.r1cs" \
        "../${POT_FILE}" \
        "${CIRCUIT_NAME}_final.zkey"

###############################################################################
# 4. Verification-Key exportieren
###############################################################################
msg "🔑  4/6  Exportiere Verification Key …"
snarkjs zkey export verificationkey \
        "${CIRCUIT_NAME}_final.zkey" \
        "verification_key.json"

###############################################################################
# 5. Proof erzeugen  (kann 5-15 min dauern)
###############################################################################
msg "📜  5/6  Erzeuge Proof … (kann 5-15 min dauern)"
snarkjs groth16 prove \
        "${CIRCUIT_NAME}_final.zkey" \
        "witness.wtns" \
        "proof.json" \
        "public.json"

###############################################################################
# 6. Proof verifizieren  (Sekunden)
###############################################################################
msg "✅  6/6  Verifiziere Proof …"
snarkjs groth16 verify \
        "verification_key.json" \
        "public.json" \
        "proof.json"

popd >/dev/null
msg "🎉  Fertig – Circuit, Witness, Proof & Verifikation erfolgreich!"
