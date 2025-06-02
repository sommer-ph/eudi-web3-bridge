pragma circom 2.1.0;

include "circom-ecdsa-p256/circuits/ecdsa.circom";

/*  P-256-ECDSA-Verify  (n = 43 bit, k = 6 limbs, little-endian)  */
template P256SignatureVerify() {
    // Private witnesses
    signal input msghash[6];          // SHA-256-hash (6 × 43 bit)
    signal input r[6];                // Signature-r
    signal input s[6];                // Signature-s
    signal input dummy;               // Not used (required by the circuit)

    // Public statements
    signal input pk_I[2][6];           // [xLimbs, yLimbs]

    // Public output
    signal output pk_I_out[2][6];      // [xLimbs, yLimbs]

    component v = ECDSAVerifyNoPubkeyCheck(43, 6);

    for (var i = 0; i < 6; i++) {
        v.msghash[i]    <== msghash[5 - i];   // BE
        v.r[i]          <== r[5 - i];
        v.s[i]          <== s[5 - i];
        v.pubkey[0][i]  <== pk_I[0][5 - i];
        v.pubkey[1][i]  <== pk_I[1][5 - i];

        pk_I_out[0][i] <== pk_I[0][1];
        pk_I_out[1][i] <== pk_I[1][i];
    }

    // Signature needs to be valid
    v.result === 1;
}

component main = P256SignatureVerify();
