#!/bin/bash

USER_ID=$1
MODE=$2
SUBPROOF=$3  # only relevant for MODE 5

if [[ -z "$USER_ID" || -z "$MODE" ]]; then
  echo "Missing arguments. Usage: ./sync-from-backend.sh <USER_ID> <MODE> [SUBPROOF]"
  exit 1
fi

echo "Syncing data for user ID: $USER_ID ..."

BACKEND_BASE="../../../zk-backend/data"
RAW_INPUT_DIR="../../../zk-proof/input/raw"
mkdir -p "$RAW_INPUT_DIR"

# Always copy wallets
for wallet_type in eudi-wallets blockchain-wallets; do
  SRC="$BACKEND_BASE/$wallet_type/$USER_ID.json"
  if [[ -f "$SRC" ]]; then
    cp "$SRC" "$RAW_INPUT_DIR"
    echo "Copied data for $USER_ID from $wallet_type"
  else
    echo "Missing data for $USER_ID from $wallet_type"
  fi
done

# Helper to copy proof-prep file
copy_proof_file() {
  local suffix=$1
  local file="$BACKEND_BASE/proof-preparation/$USER_ID-$suffix.json"
  if [[ -f "$file" ]]; then
    cp "$file" "$RAW_INPUT_DIR"
    echo "Copied data for $USER_ID from $(basename "$file")"
  else
    echo "Missing proof-preparation file: $file"
  fi
}

# Determine what to copy
case "$MODE" in
  1)  # Monolithic
    copy_proof_file "eudi-key-derivation"
    copy_proof_file "eudi-cred-pubkey"
    copy_proof_file "eudi-credential-verification"
    copy_proof_file "blockchain-master-derivation"
    copy_proof_file "blockchain-child-derivation"
    ;;

  3)  # Cred-Bind only
    copy_proof_file "eudi-key-derivation"
    copy_proof_file "eudi-cred-pubkey"
    copy_proof_file "eudi-credential-verification"
    copy_proof_file "blockchain-master-derivation"
    ;;

  4)  # Key-Bind only
    copy_proof_file "blockchain-child-derivation"
    ;;

  5)  # Individual Sub-Proof
    case "$SUBPROOF" in
      1) copy_proof_file "eudi-key-derivation" ;;
      2) copy_proof_file "eudi-cred-pubkey" ;;
      3) copy_proof_file "eudi-credential-verification" ;;
      4) copy_proof_file "blockchain-master-derivation" ;;
      5) copy_proof_file "blockchain-child-derivation" ;;
      *) echo "Unknown subproof selected: $SUBPROOF" ;;
    esac
    ;;

  *)
    echo "Unknown mode: $MODE"
    exit 1
    ;;
esac

echo "Sync completed."
