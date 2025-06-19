pragma circom 2.1.0;

include "circom-ecdsa-p256/circuits/ecdsa.circom";

/*
 * Compares the public key computed in c1 with the key
 * stored inside the EUDI credential (cnf.jwk).
 *
 * ┌ Inputs  ────────────────────────────────────────────────────┐
 * │ pk_c[2][6]      – public key from c1 (X and Y)              │
 * │ pk_cred[2][6]   – public key from credential (X and Y)      │
 * └─────────────────────────────────────────────────────────────┘
 *
 * No outputs are required as the circuit will fail if any limb mismatches.
 *
 * Note: 43-bit limb representation, 6 limbs per 256-bit integer
 */

template CredentialPKCheck () {

    // ---------- Inputs ----------
    signal input pk_c[2][6];
    signal input pk_cred[2][6];

    // ---------- Constraints ----------
    for (var i = 0; i < 6; i++) {
        pk_c[0][i] === pk_cred[0][i];
        pk_c[1][i] === pk_cred[1][i];
    }
}

// -----------------------------------------------------------------------------
// main is a standalone component for isolated circuit testing
// In compositions this template will be instantiated explicitly.
component main = CredentialPKCheck();

// Note: Currently only pk_c === pk_cred is checked.
// Note: Construction requires extracting the pk_cred from the credential.