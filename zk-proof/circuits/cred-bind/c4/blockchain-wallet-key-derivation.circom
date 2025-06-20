pragma circom 2.1.0;

include "circom-ecdsa/circuits/ecdsa.circom";

/*
 * Derives the blockchain master public key on curve secp256k1 from the secret key.
 *
 * ┌ Inputs ────────────────────────────────────────────────────────┐
 * │ sk_0[4]    – Master secret key                                 │
 * └────────────────────────────────────────────────────────────────┘
 * ┌ Outputs ───────────────────────────────────────────────────────┐
 * │ pk_0[2][4] – Master public key                                 │
 * └────────────────────────────────────────────────────────────────┘
 *
 * Note: 64-bit limb representation, 4 limbs per 256-bit integer.
 */

template BlockchainWalletKeyDerivation () {

    // Inputs
    signal input sk_0[4];

    // Outputs
    signal output pk_0[2][4];

    // Public key derivation
    // Uses ECDSAPrivToPub from circom-ecdsa library
    // This computes sk * G on secp256k1
    component keyDer = ECDSAPrivToPub(64, 4);

    for (var i = 0; i < 4; i++) {
        keyDer.privkey[i] <== sk_0[i];
    }

    for (var i = 0; i < 4; i++) {
        pk_0[0][i] <== keyDer.pubkey[0][i];
        pk_0[1][i] <== keyDer.pubkey[1][i];
    }
}
