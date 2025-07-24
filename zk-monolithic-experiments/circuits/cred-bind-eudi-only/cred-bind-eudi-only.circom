pragma circom 2.2.0;

include "circom-ecdsa-p256/circuits/ecdsa.circom";
include "circom-ecdsa/circuits/ecdsa.circom";

include "./c1/eudi-wallet-key-derivation.circom";
include "./c2/credential-public-key-check.circom";
//include "./c3/credential-signature-verification.circom";
include "./c3/credential-signature-verification-optimized.circom";

/*
 * EUDI Credential Wallet Binding Circuit
 *
 * This circuit implements zero-knowledge proof of credential wallet binding
 * for the European Digital Identity (EUDI) framework.
 *
 * The circuit proves:
 * 1. The prover knows the private key corresponding to a credential public key
 * 2. The credential was validly signed by a trusted issuer
 * 3. The prover controls the credential wallet
 *
 * Components:
 * - C1: Derives EUDI wallet public key from private key (P-256)  
 * - C2: Verifies computed public key matches credential
 * - C3: Verifies credential signature by trusted issuer
 *
 * This enables privacy-preserving credential presentation while maintaining
 * cryptographic binding between digital identity.
 */

template CredentialWalletBinding() {
    // Public inputs
    signal input pk_I[2][6]; // Keep pk_I as root of trust even if pk_I is not used in the circuit (optimized version)

    // Private witnesses
    signal input sk_c[6];
    signal input pk_c[2][6]; // extracted from c.cnf.jwk in preprocessing
    signal input msghash[6];
    signal input r[6];
    signal input s[6];

    // C1: EudiWalletKeyDerivation (pk_c = KeyDer(sk_c))
    // Proves knowledge of private key sk_c by deriving the corresponding public key
    component c1 = EudiWalletKeyDerivation();
    for (var i = 0; i < 6; i++) {
        c1.sk_c[i] <== sk_c[i];
    }

    // C2: CredentialPKCheck (pk_c_computed === pk_c (extracted from c.cnf.jwk))
    // Ensures the derived public key matches the key stored in the credential
    component c2 = CredentialPKCheck();
    for (var i = 0; i < 6; i++) {
        c2.pk_c[0][i] <== c1.pk_c[0][i];
        c2.pk_c[1][i] <== c1.pk_c[1][i];
        c2.pk_cred[0][i] <== pk_c[0][i];
        c2.pk_cred[1][i] <== pk_c[1][i];
    }

    // C3: CredentialSignatureVerification (VerifySig(pk_I, msghash, r, s) === 1)
    // Verifies that the credential was validly signed by a trusted issuer
    // Version using ECDSA verification with dynamic public key
    /*
    component c3 = CredentialSignatureVerification();
    for (var i = 0; i < 6; i++) {
        c3.msghash[i] <== msghash[i];
        c3.r[i] <== r[i];
        c3.s[i] <== s[i];
        c3.pk_I[0][i] <== pk_I[0][i];
        c3.pk_I[1][i] <== pk_I[1][i];
    }
    */
    // Version using optimized ECDSA verification with static public key
    component c3 = CredentialSignatureVerification();
    for (var i = 0; i < 6; i++) {
        c3.msghash[i] <== msghash[i];
        c3.r[i] <== r[i];
        c3.s[i] <== s[i];
    }

}

component main { public [ pk_I ] } = CredentialWalletBinding();