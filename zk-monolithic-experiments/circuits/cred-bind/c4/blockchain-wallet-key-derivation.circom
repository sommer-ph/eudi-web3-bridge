pragma circom 2.2.0;

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
    signal input pk_0[8];

    // Internal signal
    signal pk_0_struct[2][4];

    for (var i = 0; i < 4; i++) {
        pk_0_struct[0][i] <== pk_0[i];
        pk_0_struct[1][i] <== pk_0[i + 4];
    }

    // Public key derivation
    // Uses K1_ECDSAPrivToPub from circom-ecdsa library
    // This computes sk * G on secp256k1
    component keyDer = K1_ECDSAPrivToPub(64, 4);

    for (var i = 0; i < 4; i++) {
        keyDer.privkey[i] <== sk_0[i];
    }

    for (var i = 0; i < 4; i++) {
        pk_0_struct[0][i] === keyDer.pubkey[0][i];
        pk_0_struct[1][i] === keyDer.pubkey[1][i];
    }
}

component main { public [ pk_0 ] } = BlockchainWalletKeyDerivation();