pragma circom 2.1.0;

include "circom-ecdsa-p256/circuits/ecdsa.circom";

/*  P-256-ECDSA-Verify  (n = 43 Bit, k = 6 Limbs, little-endian)  */
template P256VerifyLimbs() {
    // ---------- Eingaben ----------
    signal input msghash[6];          // SHA-256-Hash (6 × 43 Bit)
    signal input r[6];                // Signatur-r
    signal input s[6];                // Signatur-s
    signal input pub[2][6];           // [xLimbs, yLimbs]
    signal input dummy;               // bleibt ungenutzt

    // ---------- ECDSA-Verifikation ----------
    component v = ECDSAVerifyNoPubkeyCheck(43, 6);

    for (var i = 0; i < 6; i++) {
        v.msghash[i]    <== msghash[5 - i];   // BE
        v.r[i]          <== r[5 - i];
        v.s[i]          <== s[5 - i];
        v.pubkey[0][i]  <== pub[0][5 - i];
        v.pubkey[1][i]  <== pub[1][5 - i];
    }

    // Signatur muss gültig sein
    v.result === 1;
}

component main = P256VerifyLimbs();
