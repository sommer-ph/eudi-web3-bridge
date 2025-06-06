#!/usr/bin/env bash
# ----------------------------------------------------
# 4-compile-and-prove.sh
#  – Compile Circom circuit, generate witness,
#    create Groth16 proof, and verify it.
# ----------------------------------------------------
set -euo pipefail

###############################################################################
#  Resolve directories
#   SCRIPT_DIR : .../zk-proof/scripts/bash
#   ROOT_DIR   : .../zk-proof
###############################################################################
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ROOT_DIR="$( realpath "${SCRIPT_DIR}/../.." )"

###############################################################################
#  Styling helpers
###############################################################################
C_OK="\033[32m"; C_INFO="\033[36m"; C_ERR="\033[31m"; C_RESET="\033[0m"
info() { echo -e "${C_INFO}$*${C_RESET}"; }
ok()   { echo -e "${C_OK}✓${C_RESET} $*"; }
die()  { echo -e "${C_ERR}✗${C_RESET} $*" >&2; exit 1; }

###############################################################################
#  Argument parsing
###############################################################################
USER_ID="${1:-}"; MODE="${2:-1}"
[[ -n "$USER_ID" ]] || die "Usage: $0 <USER_ID> <MODE>"

###############################################################################
#  Paths / constants
###############################################################################
CIRCUIT_DIR="${ROOT_DIR}/circuits"
BUILD_DIR="${ROOT_DIR}/build"
INPUT_DIR="${ROOT_DIR}/input/prepared"
POT_NAME="powersOfTau28_hez_final_22.ptau"
POT_FILE="${ROOT_DIR}/../ptau/${POT_NAME}"
# circom_libs lives one level above zk-proof
CIRCOM_LIBS="$( realpath "${ROOT_DIR}/../circom_libs" )"

mkdir -p "${BUILD_DIR}"
export SNARKJS_DEBUG=1   # helpful when things break

###############################################################################
#  Determine CIRCUIT_NAME based on MODE
###############################################################################
case "$MODE" in
  1) CIRCUIT_NAME="monolithic-composition" ;;
  3) CIRCUIT_NAME="cred-bind" ;;
  4) CIRCUIT_NAME="key-bind" ;;
  5) # Individual sub-proof → derive from first matching input file
     SUB_FILE="$( find "${INPUT_DIR}" -maxdepth 1 -name "${USER_ID}-*.json" | head -n1 )"
     [[ -n "$SUB_FILE" ]] || die "No prepared input file found for sub-proof."
     CIRCUIT_NAME="$( basename "$SUB_FILE" | sed -E "s/^${USER_ID}-//;s/\.json$//" )"
     ;;
  *) die "Unsupported MODE '$MODE'" ;;
esac

INPUT_FILE="${INPUT_DIR}/${USER_ID}-${CIRCUIT_NAME}.json"
[[ -f "$INPUT_FILE" ]] || die "Input file missing: $INPUT_FILE"

###############################################################################
#  Map logical CIRCUIT_NAME → real .circom file
###############################################################################
CIRCUIT_SRC="${CIRCUIT_DIR}/${CIRCUIT_NAME}.circom"  # default

case "$CIRCUIT_NAME" in
  credbind-c3)
    CIRCUIT_SRC="${CIRCUIT_DIR}/cred-bind/c3/verify-p256-signature.circom"
    CIRCUIT_NAME="verify-p256-signature"
    ;;
  # Add further mappings as soon as those circuits exist:
  # credbind-c1) CIRCUIT_SRC="${CIRCUIT_DIR}/cred-bind/c1/<file>.circom" ;;
  # credbind-c2) CIRCUIT_SRC="${CIRCUIT_DIR}/cred-bind/c2/<file>.circom" ;;
  # credbind-c4) CIRCUIT_SRC="${CIRCUIT_DIR}/cred-bind/c4/<file>.circom" ;;
  # keybind-k1)  CIRCUIT_SRC="${CIRCUIT_DIR}/key-bind/k1/<file>.circom"  ;;
esac

[[ -f "$CIRCUIT_SRC" ]] || die "Circuit file not found: $CIRCUIT_SRC"

###############################################################################
#  Proof artefact filenames (timestamped → easier debugging)
###############################################################################
TIMESTAMP="$(date +%s)"
PROOF_PREFIX="${CIRCUIT_NAME}_${USER_ID}_${TIMESTAMP}"

WITNESS_FILE="witness_${PROOF_PREFIX}.wtns"
ZKEY_FILE="${CIRCUIT_NAME}_${PROOF_PREFIX}.zkey"
PROOF_JSON="proof_${PROOF_PREFIX}.json"
PUBLIC_JSON="public_${PROOF_PREFIX}.json"
VK_JSON="verification_key_${PROOF_PREFIX}.json"

info "------------------------------------------------------"
info "  Circuit:  ${CIRCUIT_NAME}"
info "  User-ID:  ${USER_ID}"
info "  Mode:     ${MODE}"
info "  Source:   ${CIRCUIT_SRC#${ROOT_DIR}/}"
info "------------------------------------------------------"

###############################################################################
# 1) Compile circuit
###############################################################################
ok "1/6  Compile circuit"
circom "${CIRCUIT_SRC}" \
       --r1cs --wasm --sym \
       -l "${CIRCOM_LIBS}" \
       -l node_modules \
       -o "${BUILD_DIR}"

###############################################################################
# 2) Generate witness
###############################################################################
ok "2/6  Generate witness"
pushd "${BUILD_DIR}" >/dev/null
node "${CIRCUIT_NAME}_js/generate_witness.js" \
     "${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm" \
     "${INPUT_FILE}" \
     "${WITNESS_FILE}"

###############################################################################
# 3) Groth16 setup
###############################################################################
ok "3/6  Groth16 setup"
snarkjs groth16 setup \
        "${CIRCUIT_NAME}.r1cs" \
        "${POT_FILE}" \
        "${ZKEY_FILE}"

###############################################################################
# 4) Export verification key
###############################################################################
ok "4/6  Export verification key"
snarkjs zkey export verificationkey \
        "${ZKEY_FILE}" \
        "${VK_JSON}"

###############################################################################
# 5) Generate proof
###############################################################################
ok "5/6  Generate proof"
snarkjs groth16 prove \
        "${ZKEY_FILE}" \
        "${WITNESS_FILE}" \
        "${PROOF_JSON}" \
        "${PUBLIC_JSON}"

###############################################################################
# 6) Verify proof
###############################################################################
ok "6/6  Verify proof"
snarkjs groth16 verify \
        "${VK_JSON}" \
        "${PUBLIC_JSON}" \
        "${PROOF_JSON}"

popd >/dev/null
ok "DONE: proof + verification successful  →  ${PROOF_PREFIX}"
