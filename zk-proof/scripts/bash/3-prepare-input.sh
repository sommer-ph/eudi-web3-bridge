#!/bin/bash

# Script: 3-prepare-input.sh
# Purpose: Prepare circuit input JSONs for selected proofs
# --------------------------------------------

USER_ID=$1
MODE=$2
SUBPROOF=$3
C1_IMPL=$4
C2_IMPL=$5
C3_IMPL=$6
C4_IMPL=$7
K1_IMPL=$8

PREPARED_DIR="input/prepared"

if [[ -z "$USER_ID" || -z "$MODE" ]]; then
  echo "Missing required parameters. Exiting."
  exit 1
fi

echo "Preparing circuit input for user '$USER_ID' (Mode: $MODE)..."

prepare_input_for_constraint() {
  local constraint=$1
  local impl=$2
  local js_script="./scripts/js/prepare-${constraint}-${impl}.js"

  if [[ -f "$js_script" ]]; then
    echo "→ Preparing input for $constraint (impl $impl)..."
    node "$js_script" "$USER_ID"
  else
    echo "Missing JS script: $js_script (skipped)"
  fi
}

merge_inputs() {
  local output_name=$1
  local pattern=$2
  local output_file="${PREPARED_DIR}/${USER_ID}-${output_name}.json"

  echo "→ Merging input files matching pattern '${pattern}' into: $output_file"

  node -e "
    const fs = require('fs');
    const path = '${PREPARED_DIR}';
    const files = fs.readdirSync(path).filter(f => f.startsWith('${USER_ID}-') && f.match(/${pattern}/));
    if (files.length === 0) {
      console.error('No input files found to merge for pattern: ${pattern}');
      process.exit(1);
    }
    const merged = files.reduce((acc, file) => {
      const data = JSON.parse(fs.readFileSync(\`\${path}/\${file}\`));
      return Object.assign(acc, data);
    }, {});
    fs.writeFileSync('${output_file}', JSON.stringify(merged, null, 2));
    console.log('Merged files:', files.join(', '));
  "
}

case "$MODE" in
  1)
    echo "Mode: Monolithic (CredBind + KeyBind)"
    prepare_input_for_constraint "credbind-c1" "$C1_IMPL"
    prepare_input_for_constraint "credbind-c2" "$C2_IMPL"
    prepare_input_for_constraint "credbind-c3" "$C3_IMPL"
    prepare_input_for_constraint "credbind-c4" "$C4_IMPL"
    prepare_input_for_constraint "keybind" "$K1_IMPL"

    merge_inputs "monolith" "credbind|keybind"
    ;;

  3)
    echo "Mode: CredBind only"
    prepare_input_for_constraint "credbind-c1" "$C1_IMPL"
    prepare_input_for_constraint "credbind-c2" "$C2_IMPL"
    prepare_input_for_constraint "credbind-c3" "$C3_IMPL"
    prepare_input_for_constraint "credbind-c4" "$C4_IMPL"

    merge_inputs "credbind" "credbind"
    ;;

  4)
    echo "Mode: KeyBind only"
    prepare_input_for_constraint "keybind" "$K1_IMPL"
    # keine Merge nötig
    ;;

  5)
    echo "Mode: Sub-Proof"
    case "$SUBPROOF" in
      1) prepare_input_for_constraint "credbind-c1" "$C1_IMPL" ;;
      2) prepare_input_for_constraint "credbind-c2" "$C2_IMPL" ;;
      3) prepare_input_for_constraint "credbind-c3" "$C3_IMPL" ;;
      4) prepare_input_for_constraint "credbind-c4" "$C4_IMPL" ;;
      5) prepare_input_for_constraint "keybind" "$K1_IMPL" ;;
      *) echo "Invalid sub-proof number: $SUBPROOF"; exit 1 ;;
    esac
    # keine Merge nötig
    ;;

  *)
    echo "Unsupported mode: $MODE"
    exit 1
    ;;
esac

echo ""
echo "Input preparation completed for user '$USER_ID'."
