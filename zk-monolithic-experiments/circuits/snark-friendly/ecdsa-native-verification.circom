pragma circom 2.2.0;

// Use the ECDSA implementation for the Baby Jubjub curve from circom-ecdsa
include "../../circom_libs/circom-ecdsa/circuits/ecdsa_babyjub.circom";

// This circuit verifies an ECDSA signature on the Baby Jubjub curve.
// The inputs are provided in 4 limbs of 64 bits each as expected by
// the BJJ_ECDSAVerify template from circom-ecdsa.
template ECDSANativeVerify() {
    signal input r[4];
    signal input s[4];
    signal input msghash[4];
    signal input pubkey[2][4];
    signal output isValid;

    component verifier = BJJ_ECDSAVerify(64, 4);
    for (var i = 0; i < 4; i++) {
        verifier.r[i] <== r[i];
        verifier.s[i] <== s[i];
        verifier.msghash[i] <== msghash[i];
        verifier.pubkey[0][i] <== pubkey[0][i];
        verifier.pubkey[1][i] <== pubkey[1][i];
    }
    isValid <== verifier.result;
}

// Expose all inputs as public for easy testing
component main {public [r, s, msghash, pubkey]} = ECDSANativeVerify();
