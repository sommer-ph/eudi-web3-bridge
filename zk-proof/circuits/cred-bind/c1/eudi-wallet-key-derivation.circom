pragma circom 2.1.0;

include "circom-ecdsa-p256/circuits/ecdsa.circom";

/*
 * Computes the ECDSA public key on curve secp256r1 from a given secret key.
 * 
 * ┌ Inputs  ──────────────────────────────────────────────┐
 * │ sk_c[6]   – Secret key (private witness) (43-bit limbs)
 * └───────────────────────────────────────────────────────┘
 * ┌ Outputs ──────────────────────────────────────────────┐
 * │ pk_c[2][6] – Public key (X and Y coordinates)         │
 * └───────────────────────────────────────────────────────┘
 *
 * Note: 43-bit limb representation, 6 limbs per 256-bit integer
 */

template EudiWalletKeyDerivation () {

    // ---------- Inputs ----------
    signal input sk_c[6];

    // ---------- Outputs ----------
    signal output pk_c[2][6];

    // ---------- Public Key Derivation ----------
    // Use ECDSAPrivToPub from circom-ecdsa-p256 library
    // This computes sk * G on secp256r1 (P-256)
    component privToPub = ECDSAPrivToPub(43, 6);

    for (var i = 0; i < 6; i++) {
        privToPub.privkey[i] <== sk_c[i];
    }

    for (var i = 0; i < 6; i++) {
        pk_c[0][i] <== privToPub.pubkey[0][i];
        pk_c[1][i] <== privToPub.pubkey[1][i];
    }
}

// -----------------------------------------------------------------------------
// main is a standalone component for isolated circuit testing
// In compositions this template will be instantiated explicitly.
component main = EudiWalletKeyDerivation();