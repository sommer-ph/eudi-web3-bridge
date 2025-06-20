pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";

/*
 * Validates that the provided Poseidon commitment hash matches
 * the derived master public key pk_0 on secp256k1.
 *
 * ┌ Inputs ──────────────────────────────────────────────────┐
 * │ pk_0[2][4]  – Public key limbs                           │
 * │ h_0         – Public commitment hash                     │
 * └──────────────────────────────────────────────────────────┘
 *
 * Note: 64-bit limb representation, 4 limbs per 256-bit integer.
 */

template BlockchainCommitmentCheck() {

    // Inputs
    signal input pk_0[2][4];
    signal input h_0;

    // Flatten pk_0 into one array for Poseidon input
    signal flat[8];
    for (var i = 0; i < 4; i++) {
        flat[i]     <== pk_0[0][i];  // X
        flat[i + 4] <== pk_0[1][i];  // Y
    }

    // Poseidon hash over 8 inputs
    component H = Poseidon(8);
    for (var i = 0; i < 8; i++) {
        H.inputs[i] <== flat[i];
    }

    // Enforce equality to provided commitment
    H.out === h_0;
}
