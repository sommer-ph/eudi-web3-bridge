pragma circom 2.2.0;

include "circom-ecdsa/circuits/ecdsa_babyjub.circom";

// This circuit verifies an ECDSA signature on the BabyJubjub curve.
template ECDSANativeVerify() {
    signal input r[4];
    signal input s[4];
    signal input msghash[4];
    signal input pubkey[2][4];

    component v = BJJ_ECDSAVerify(64, 4);
    for (var i = 0; i < 4; i++) {
        v.r[i] <== r[i];
        v.s[i] <== s[i];
        v.msghash[i] <== msghash[i];
        v.pubkey[0][i] <== pubkey[0][i];
        v.pubkey[1][i] <== pubkey[1][i];
    }
    v.result === 1;
}

component main {public [ pubkey ]} = ECDSANativeVerify();