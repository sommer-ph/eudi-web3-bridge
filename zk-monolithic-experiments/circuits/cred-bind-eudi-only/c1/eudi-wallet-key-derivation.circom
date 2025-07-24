pragma circom 2.2.0;

include "circom-ecdsa-p256/circuits/ecdsa.circom";

/*
 * Computes the ECDSA public key on curve secp256r1 from a given secret key.
 * 
 * ┌ Inputs  ──────────────────────────────────────────────┐
 * │ sk_c[6]    – EUDI wallet secret key                   │
 * └───────────────────────────────────────────────────────┘
 * ┌ Outputs ──────────────────────────────────────────────┐
 * │ pk_c[2][6] – EUDI wallet public key                   │
 * └───────────────────────────────────────────────────────┘
 *
 * Note: 43-bit limb representation, 6 limbs per 256-bit integer
 */

template EudiWalletKeyDerivation () {

    // Inputs
    signal input sk_c[6];

    // Outputs
    signal output pk_c[2][6];

    // Public key derivation
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
