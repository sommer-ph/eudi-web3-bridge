#!/usr/bin/env bash
# ----------------------------------------------------
# 2-sync-from-backend.sh
#  – Copy all JSON artefacts from zk-backend → zk-proof/input/raw
# ----------------------------------------------------
set -euo pipefail

###############################################################################
#  Resolve directories
#  - SCRIPT_DIR : absolute path of this script          (.../scripts/bash)
#  - ROOT_DIR   : zk-proof project root                 (.../zk-proof)
###############################################################################
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ROOT_DIR="$( realpath "${SCRIPT_DIR}/../.." )"

# Backend lives *next to* zk-proof
BACKEND_BASE="$( realpath "${ROOT_DIR}/../zk-backend/data" )"

# Where we store the raw inputs for the circuits
RAW_INPUT_DIR="${ROOT_DIR}/input/raw"
mkdir -p "${RAW_INPUT_DIR}"

###############################################################################
#  Styling helpers
###############################################################################
C_OK="\033[32m"; C_WARN="\033[33m"; C_ERR="\033[31m"; C_RESET="\033[0m"
ok()   { echo -e "${C_OK}✓${C_RESET} $*"; }
warn() { echo -e "${C_WARN}⚠${C_RESET} $*"; }
die()  { echo -e "${C_ERR}✗${C_RESET} $*" >&2; exit 1; }

###############################################################################
#  Argument parsing
###############################################################################
USER_ID="${1:-}"
MODE="${2:-}"
SUBPROOF="${3:-0}"   # used only for mode 5

[[ -n "$USER_ID" && -n "$MODE" ]] \
  || die "Usage: $0 <USER_ID> <MODE> [SUBPROOF]"

echo "------------------------------------------------------"
echo " Syncing data for user: ${USER_ID} (mode ${MODE})"
echo "------------------------------------------------------"

###############################################################################
#  Copy wallet JSONs (new naming scheme)
#    eudi-wallets/<uid>-eudi-wallet.json
#    blockchain-wallets/<uid>-blockchain-wallet.json
###############################################################################
for FILE in \
  "${USER_ID}-eudi-wallet.json" \
  "${USER_ID}-blockchain-wallet.json"
do
  # Choose directory based on suffix before first dash
  #   eudi-wallet          → eudi-wallets
  #   blockchain-wallet    → blockchain-wallets
  DIR_SUFFIX="${FILE#*-}"           # e.g. "eudi-wallet.json"
  DIR_SUFFIX="${DIR_SUFFIX%.json}"  # → "eudi-wallet"
  DIR="${DIR_SUFFIX}s"              # → "eudi-wallets"

  SRC="${BACKEND_BASE}/${DIR}/${FILE}"
  if [[ -f "$SRC" ]]; then
    cp -f "$SRC" "${RAW_INPUT_DIR}/"
    ok "Copied $(basename "$SRC")"
  else
    warn "Missing wallet file: $SRC"
  fi
done

###############################################################################
#  Helper – copy one proof-prep JSON (suffix without userId / .json)
###############################################################################
copy_proof_file() {
  local SUFFIX="$1"   # e.g. eudi-credential-verification
  local FILE="${BACKEND_BASE}/proof-preparation/${USER_ID}-${SUFFIX}.json"
  if [[ -f "$FILE" ]]; then
    cp -f "$FILE" "${RAW_INPUT_DIR}/"
    ok "Copied $(basename "$FILE")"
  else
    warn "Missing proof-prep file: $FILE"
  fi
}

###############################################################################
#  Mode-specific selection of proof-prep artefacts
###############################################################################
case "$MODE" in
  1)  # Monolithic
      for f in \
        eudi-key-derivation           \
        eudi-cred-pubkey              \
        eudi-credential-verification  \
        blockchain-master-derivation  \
        blockchain-child-derivation
      do copy_proof_file "$f"; done
      ;;
  3)  # CredBind only
      for f in \
        eudi-key-derivation           \
        eudi-cred-pubkey              \
        eudi-credential-verification  \
        blockchain-master-derivation
      do copy_proof_file "$f"; done
      ;;
  4)  # KeyBind only
      copy_proof_file "blockchain-child-derivation"
      ;;
  5)  # Single sub-proof
      case "$SUBPROOF" in
        1) copy_proof_file "eudi-key-derivation" ;;
        2) copy_proof_file "eudi-cred-pubkey" ;;
        3) copy_proof_file "eudi-credential-verification" ;;
        4) copy_proof_file "blockchain-master-derivation" ;;
        5) copy_proof_file "blockchain-child-derivation" ;;
        *) die "Unknown sub-proof id '$SUBPROOF' for mode 5" ;;
      esac
      ;;
  *) die "Unknown mode '$MODE'" ;;
esac

echo -e "\nAll syncing steps completed."
