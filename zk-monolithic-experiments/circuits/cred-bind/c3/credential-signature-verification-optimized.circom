pragma circom 2.2.0;

include "circom-ecdsa-p256/circuits/ecdsa.circom";

/*
 * Verifies the ECDSA signature over curve NIST P-256 of the EUDI credential.
 *
 * ┌ Inputs ───────────────────────────────────────────────────────┐
 * │ msghash[6]   – SHA-256 digest of credential                   │
 * │ r[6]         – signature component r                          │
 * │ s[6]         – signature component s                          │
 * │ pk_I[2][6]   – issuer public key                              │
 * └───────────────────────────────────────────────────────────────┘
 *
 * Note: 43-bit limb representation, 6 limbs per 256-bit integer.
 * No outputs: the circuit will fail if the signature is invalid.
 */

template CredentialSignatureVerification () {

    // Inputs
    signal input msghash[6];
    signal input r[6];
    signal input s[6];

    // Verification component
    component v = ECDSAVerifyFixedPubkey(43, 6);

    for (var i = 0; i < 6; i++) {
        v.msghash[i]   <== msghash[i];
        v.r[i]         <== r[i];
        v.s[i]         <== s[i];
    }

    // Require signature to be valid
    v.result === 1;
}

component main = CredentialSignatureVerification();