#!/bin/bash

# ----------------------------------------------------
# Main CLI script for zk-SNARK proof orchestration
# ----------------------------------------------------

clear
echo "------------------------------------------------------"
echo "  zk-SNARK service to bridge EUDI and Web3 started..."
echo "------------------------------------------------------"
echo ""
echo "Gathering user input..."
echo ""

# Enter userId
read -p "Enter user ID: " USER_ID

if [[ -z "$USER_ID" ]]; then
  echo "No user ID provided. Exiting."
  exit 1
fi

echo ""
echo "User ID set to: $USER_ID"
echo ""

# Select operation mode
echo "Select proof composition or sub-proof mode:"
echo "1) Monolithic composition (CredBind + KeyBind)"
echo "2) Recursive composition (TBI)"
echo "3) Cred-bind proof only"
echo "4) Key-bind proof only"
echo "5) Individual sub-proof"
read -p "Enter choice [1-5]: " MODE

echo ""

case "$MODE" in
  "2")
    echo "Recursive composition selected. (To be implemented)"
    exit 0
    ;;

  "1")
    echo "Monolithic composition selected. All constraints will be configured."
    echo ""

    # CRED-BIND Constraints (1–4)
    echo "Cred-Bind Constraint 1: PK_C = KeyDer(SK_C)"
    echo "1) Dummy Impl 1"
    echo "2) Dummy Impl 2"
    read -p "Choice [1-2]: " C1_IMPL

    echo ""
    echo "Cred-Bind Constraint 2: Confirm PK_C in cnf section"
    echo "1) Dummy Impl 1"
    echo "2) Dummy Impl 2"
    read -p "Choice [1-2]: " C2_IMPL

    echo ""
    echo "Cred-Bind Constraint 3: Verify Signature SIG_C"
    echo "1) In-circuit ECDSA (P256)"
    echo "2) Off-circuit ECDSA + SHA-256 check"
    echo "3) Off-circuit ECDSA + Poseidon check"
    echo "4) Dummy Impl 4"
    read -p "Choice [1-4]: " C3_IMPL

    echo ""
    echo "Cred-Bind Constraint 4: PK_0 = KeyDer(SK_0)"
    echo "1) Dummy Impl 1"
    echo "2) Dummy Impl 2"
    read -p "Choice [1-2]: " C4_IMPL

    # KEY-BIND Constraint
    echo ""
    echo "Key-Bind Constraint: PK_1 = KeyDer(PK_0, CC_0, i)"
    echo "1) Dummy Impl 1"
    echo "2) Dummy Impl 2"
    read -p "Choice [1-2]: " K1_IMPL
    ;;

  "3")
    echo "Cred-Bind proof only selected (4 constraints)."
    echo ""

    echo "Cred-Bind Constraint 1: PK_C = KeyDer(SK_C)"
    echo "1) Dummy Impl 1"
    echo "2) Dummy Impl 2"
    read -p "Choice [1-2]: " C1_IMPL

    echo ""
    echo "Cred-Bind Constraint 2: Confirm PK_C in cnf section"
    echo "1) Dummy Impl 1"
    echo "2) Dummy Impl 2"
    read -p "Choice [1-2]: " C2_IMPL

    echo ""
    echo "Cred-Bind Constraint 3: Verify Signature SIG_C"
    echo "1) In-circuit ECDSA (P256)"
    echo "2) Off-circuit ECDSA + SHA-256 check"
    echo "3) Off-circuit ECDSA + Poseidon check"
    echo "4) Dummy Impl 4"
    read -p "Choice [1-4]: " C3_IMPL

    echo ""
    echo "Cred-Bind Constraint 4: PK_0 = KeyDer(SK_0)"
    echo "1) Dummy Impl 1"
    echo "2) Dummy Impl 2"
    read -p "Choice [1-2]: " C4_IMPL
    ;;

  "4")
    echo "Key-Bind proof only selected (1 constraint)."
    echo ""
    echo "Key-Bind Constraint: PK_1 = KeyDer(PK_0, CC_0, i)"
    echo "1) Dummy Impl 1"
    echo "2) Dummy Impl 2"
    read -p "Choice [1-2]: " K1_IMPL
    ;;

  "5")
    echo "Individual Sub-Proof selected."
    echo "Which high-level constraint do you want to execute?"
    echo "1) Cred-Bind Constraint 1 - PK_C = KeyDer(SK_C)"
    echo "2) Cred-Bind Constraint 2 - Confirm PK_C in cnf section"
    echo "3) Cred-Bind Constraint 3 - Verify Signature SIG_C"
    echo "4) Cred-Bind Constraint 4 - PK_0 = KeyDer(SK_0)"
    echo "5) Key-Bind Constraint - PK_1 = KeyDer(PK_0, CC_0, i)"
    read -p "Choice [1-5]: " SUBPROOF

    echo ""

    case "$SUBPROOF" in
      "1")
        echo "Configuring Cred-Bind Constraint 1 - PK_C = KeyDer(SK_C)"
        echo "1) Dummy Impl 1"
        echo "2) Dummy Impl 2"
        read -p "Choice [1-2]: " C1_IMPL
        ;;
      "2")
        echo "Configuring Cred-Bind Constraint 2 - Confirm PK_C in cnf section"
        echo "1) Dummy Impl 1"
        echo "2) Dummy Impl 2"
        read -p "Choice [1-2]: " C2_IMPL
        ;;
      "3")
        echo "Configuring Cred-Bind Constraint 3 - Verify Signature SIG_C"
        echo "1) In-circuit ECDSA (P256)"
        echo "2) Off-circuit ECDSA + SHA-256 check"
        echo "3) Off-circuit ECDSA + Poseidon check"
        echo "4) Dummy Impl 4"
        read -p "Choice [1-4]: " C3_IMPL
        ;;
      "4")
        echo "Configuring Cred-Bind Constraint 4 - PK_0 = KeyDer(SK_0)"
        echo "1) Dummy Impl 1"
        echo "2) Dummy Impl 2"
        read -p "Choice [1-2]: " C4_IMPL
        ;;
      "5")
        echo "Configuring Key-Bind Constraint - PK_1 = KeyDer(PK_0, CC_0, i)"
        echo "1) Dummy Impl 1"
        echo "2) Dummy Impl 2"
        read -p "Choice [1-2]: " K1_IMPL
        ;;
      *)
        echo "Invalid sub-proof choice. Exiting."
        exit 1
        ;;
    esac
    ;;

  *)
    echo "Invalid mode selected. Exiting."
    exit 1
    ;;
esac

echo ""
echo "Copying relevant data from backend..."
bash ./scripts/bash/2-sync-from-backend.sh "$USER_ID" "$MODE" "$SUBPROOF"

echo ""
echo "Preparing circuit input for selected mode..."
bash ./scripts/bash/3-prepare-input.sh "$USER_ID" "$MODE" "${SUBPROOF:-0}" "${C1_IMPL:-0}" "${C2_IMPL:-0}" "${C3_IMPL:-0}" "${C4_IMPL:-0}" "${K1_IMPL:-0}"

echo ""
echo "Data preparation complete for user '$USER_ID'."
echo ""

read -p "Do you want to compile the circuit and generate the proof now? [y/N]: " COMPILE_CONFIRMATION

if [[ "$COMPILE_CONFIRMATION" =~ ^[Yy]$ ]]; then
  echo ""
  echo "Starting compilation and proving process..."
  bash ./scripts/bash/4-compile-and-prove.sh "$USER_ID" "$MODE"
else
  echo ""
  echo "Exiting CLI. You can manually run the compilation and proving process later."
  exit 0
fi
