#!/usr/bin/env bash
set -euo pipefail

# ----------------------------------------------------
# 1-main.sh  –  zk-SNARK CLI (EUDI-Web3)
# ----------------------------------------------------

###############################################################################
# Resolve key directories
#   SCRIPT_DIR : .../zk-proof/scripts/bash
#   ROOT_DIR   : .../zk-proof
###############################################################################
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ROOT_DIR="$( realpath "${SCRIPT_DIR}/../.." )"

###############################################################################
# Styling helpers
###############################################################################
C_BOLD="\033[1m"; C_CYAN="\033[36m"; C_RED="\033[31m"; C_RESET="\033[0m"
log() { echo -e "${C_CYAN}${C_BOLD}$*${C_RESET}"; }
die() { echo -e "${C_RED}Error:${C_RESET} $*" >&2; exit 1; }

###############################################################################
# Prompt helpers
###############################################################################
prompt_choice() {                # var msg default
  local _var="$1" _msg="$2" _def="$3" _in
  read -rp "$_msg" _in
  printf -v "$_var" '%s' "${_in:-$_def}"
}

choose_impl() {                  # var msg [x-y] opts default
  local _var="$1" _msg="$2" _rng="$3" _opts="$4" _def="$5"
  echo "$_msg"; echo -e "$_opts"
  prompt_choice "${_var}" "Enter choice ${_rng}: " "${_def}"
}

###############################################################################
# Optional CLI flags
###############################################################################
USER_ID=""; MODE=""
while getopts "u:m:h" opt; do
  case "$opt" in
    u) USER_ID="$OPTARG" ;;
    m) MODE="$OPTARG"   ;;
    h) echo "Usage: $0 [-u USER_ID] [-m MODE]"; exit 0 ;;
    *) exit 1 ;;
  esac
done
shift $((OPTIND-1))

###############################################################################
# Intro banner
###############################################################################
clear
log "------------------------------------------------------"
log "  zk-SNARK CLI – EUDI-Web3"
log "------------------------------------------------------"
echo

###############################################################################
# Ask for user ID
###############################################################################
if [[ -z "$USER_ID" ]]; then
  prompt_choice USER_ID "Enter user ID: " ""
  [[ -z "$USER_ID" ]] && die "No user ID provided."
fi
log "User ID: $USER_ID"
echo

###############################################################################
# Choose proof mode
###############################################################################
if [[ -z "$MODE" ]]; then
  cat <<EOF
Select proof composition / sub-proof mode:
  1) Monolithic (CredBind + KeyBind)
  2) Recursive (TBI)
  3) Cred-Bind only
  4) Key-Bind only
  5) Individual sub-proof
EOF
  prompt_choice MODE "Enter choice [1-5]: " ""
fi
[[ "$MODE" =~ ^[1-5]$ ]] || die "Invalid mode."
echo

###############################################################################
# Implementation flags (defaults)
###############################################################################
C1_IMPL=1 C2_IMPL=1 C3_IMPL=1 C4_IMPL=1 K1_IMPL=1 SUBPROOF=0

###############################################################################
# Mode-specific logic
###############################################################################
case "$MODE" in
  2)
    log "Recursive composition (TBI) – exiting."
    exit 0
    ;;

  1)  # Monolithic
    log "Monolithic composition chosen."
    choose_impl C1_IMPL "Cred-Bind C1 implementation" "[1-2]" \
       "  1) Dummy 1\n  2) Dummy 2" 1
    choose_impl C2_IMPL "Cred-Bind C2 implementation" "[1-2]" \
       "  1) Dummy 1\n  2) Dummy 2" 1
    choose_impl C3_IMPL "Cred-Bind C3 implementation" "[1-4]" \
       "  1) In-circuit\n  2) Off-SHA\n  3) Off-Poseidon\n  4) Dummy" 1
    choose_impl C4_IMPL "Cred-Bind C4 implementation" "[1-2]" \
       "  1) Dummy 1\n  2) Dummy 2" 1
    choose_impl K1_IMPL "Key-Bind implementation"     "[1-2]" \
       "  1) Dummy 1\n  2) Dummy 2" 1
    ;;

  3)  # Cred-Bind only
    log "Cred-Bind proof only chosen."
    choose_impl C1_IMPL "Cred-Bind C1 implementation" "[1-2]" "  1) Dummy 1\n  2) Dummy 2" 1
    choose_impl C2_IMPL "Cred-Bind C2 implementation" "[1-2]" "  1) Dummy 1\n  2) Dummy 2" 1
    choose_impl C3_IMPL "Cred-Bind C3 implementation" "[1-4]" "  1) In-circuit\n  2) Off-SHA\n  3) Off-Poseidon\n  4) Dummy" 1
    choose_impl C4_IMPL "Cred-Bind C4 implementation" "[1-2]" "  1) Dummy 1\n  2) Dummy 2" 1
    ;;

  4)  # Key-Bind only
    log "Key-Bind proof only chosen."
    choose_impl K1_IMPL "Key-Bind implementation" "[1-2]" "  1) Dummy 1\n  2) Dummy 2" 1
    ;;

  5)  # Individual sub-proof
    log "Individual sub-proof chosen."
    cat <<EOF
  1) Cred-Bind C1
  2) Cred-Bind C2
  3) Cred-Bind C3
  4) Cred-Bind C4
  5) Key-Bind
EOF
    prompt_choice SUBPROOF "Enter choice [1-5]: " ""
    [[ "$SUBPROOF" =~ ^[1-5]$ ]] || die "Invalid sub-proof."

    case "$SUBPROOF" in
      1) choose_impl C1_IMPL "C1 implementation" "[1-2]" "  1) Dummy 1\n  2) Dummy 2" 1 ;;
      2) choose_impl C2_IMPL "C2 implementation" "[1-2]" "  1) Dummy 1\n  2) Dummy 2" 1 ;;
      3) choose_impl C3_IMPL "C3 implementation" "[1-4]" "  1) In-circuit\n  2) Off-SHA\n  3) Off-Poseidon\n  4) Dummy" 1 ;;
      4) choose_impl C4_IMPL "C4 implementation" "[1-2]" "  1) Dummy 1\n  2) Dummy 2" 1 ;;
      5) choose_impl K1_IMPL "Key-Bind implementation" "[1-2]" "  1) Dummy 1\n  2) Dummy 2" 1 ;;
    esac
    ;;
esac
echo

###############################################################################
# Sync data & build input
###############################################################################
log "Copying relevant data from backend …"
"${SCRIPT_DIR}/2-sync-from-backend.sh" "$USER_ID" "$MODE" "$SUBPROOF"

log "Preparing circuit input …"
"${SCRIPT_DIR}/3-prepare-input.sh" \
  "$USER_ID" "$MODE" "$SUBPROOF" \
  "$C1_IMPL" "$C2_IMPL" "$C3_IMPL" "$C4_IMPL" "$K1_IMPL"

log "Input preparation complete."
echo

###############################################################################
# Optional compile + prove step
###############################################################################
read -rp "Compile circuit & generate proof now? [y/N]: " CONFIRM
if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
  log "Starting compilation + proving …"
  "${SCRIPT_DIR}/4-compile-and-prove.sh" "$USER_ID" "$MODE"
else
  log "Aborted – compile/prove step skipped."
fi
