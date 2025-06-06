#!/usr/bin/env bash
# ----------------------------------------------------
# 3-prepare-input.sh
#  – Build / merge JSON inputs for Circom circuits
# ----------------------------------------------------
set -euo pipefail

###############################################################################
#  Resolve directories
#  - SCRIPT_DIR : absolute path of this script          (.../scripts/bash)
#  - ROOT_DIR   : zk-proof project root                 (.../zk-proof)
###############################################################################
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ROOT_DIR="$( realpath "${SCRIPT_DIR}/../.." )"

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
USER_ID="${1:-}"; MODE="${2:-}"; SUB="${3:-0}"
C1="${4:-0}"; C2="${5:-0}"; C3="${6:-0}"
C4="${7:-0}"; K1="${8:-0}"

[[ -n "$USER_ID" && -n "$MODE" ]] \
  || die "Usage: $0 <USER_ID> <MODE> [SUB] [C1] [C2] [C3] [C4] [K1]"

###############################################################################
#  Directories for raw and prepared inputs
###############################################################################
RAW_DIR="${ROOT_DIR}/input/raw"
PREP_DIR="${ROOT_DIR}/input/prepared"
mkdir -p "${PREP_DIR}"

echo "------------------------------------------------------"
echo " Preparing circuit input  (user=${USER_ID}  mode=${MODE})"
echo "------------------------------------------------------"

###############################################################################
#  Helper: run a single JS preparation script
###############################################################################
prepare_constraint () {
  local NAME="$1"   # e.g. credbind-c1
  local IMPL="$2"
  [[ "$IMPL" != "0" ]] || { warn "→ $NAME: impl=0 (skipped)"; return; }

  local JS="${ROOT_DIR}/scripts/js/prepare-${NAME}-${IMPL}.js"
  if [[ -f "$JS" ]]; then
    ok "→ ${NAME} (impl ${IMPL})"
    node "$JS" "$USER_ID" "$RAW_DIR" "$PREP_DIR"
  else
    warn "Missing JS script: $JS (skipped)"
  fi
}

###############################################################################
#  Helper: merge several prepared JSONs into one
###############################################################################
merge_inputs () {
  local OUT_NAME="$1"   # e.g. monolithic-composition
  shift
  local PATTERNS=("$@")

  local OUT_FILE="${PREP_DIR}/${USER_ID}-${OUT_NAME}.json"
  ok "→ Merging (${PATTERNS[*]})  ➜  $(basename "$OUT_FILE")"

  node - <<'NODE' "$USER_ID" "$PREP_DIR" "$OUT_FILE" "${PATTERNS[@]}"
const fs      = require('fs');
const uid     = process.argv[2];
const dir     = process.argv[3];
const outFile = process.argv[4];
const pats    = process.argv.slice(5).map(p => new RegExp(p));

const files = fs.readdirSync(dir).filter(f =>
  f.startsWith(uid + '-') && pats.some(r => r.test(f))
);

if (files.length === 0) {
  console.error("No matching input files to merge."); process.exit(1);
}

const merged = files.reduce((acc, f) =>
  Object.assign(acc, JSON.parse(fs.readFileSync(`${dir}/${f}`))), {});

fs.writeFileSync(outFile, JSON.stringify(merged, null, 2));
console.log("Merged files:", files.join(', '));
NODE
}

###############################################################################
#  Mode-specific processing
###############################################################################
case "$MODE" in
  1)  # Monolithic: CredBind + KeyBind
      prepare_constraint "credbind-c1" "$C1"
      prepare_constraint "credbind-c2" "$C2"
      prepare_constraint "credbind-c3" "$C3"
      prepare_constraint "credbind-c4" "$C4"
      prepare_constraint "keybind"     "$K1"
      merge_inputs "monolithic-composition" "credbind" "keybind"
      ;;
  3)  # CredBind only
      prepare_constraint "credbind-c1" "$C1"
      prepare_constraint "credbind-c2" "$C2"
      prepare_constraint "credbind-c3" "$C3"
      prepare_constraint "credbind-c4" "$C4"
      merge_inputs "credbind" "credbind"
      ;;
  4)  # KeyBind only
      prepare_constraint "keybind" "$K1"
      ;;
  5)  # Single sub-proof
      case "$SUB" in
        1) prepare_constraint "credbind-c1" "$C1" ;;
        2) prepare_constraint "credbind-c2" "$C2" ;;
        3) prepare_constraint "credbind-c3" "$C3" ;;
        4) prepare_constraint "credbind-c4" "$C4" ;;
        5) prepare_constraint "keybind"     "$K1" ;;
        *) die "Unknown sub-proof id '$SUB' for mode 5" ;;
      esac
      ;;
  *) die "Unsupported mode '$MODE'" ;;
esac

echo -e "\n$(ok "Input preparation completed.")"
