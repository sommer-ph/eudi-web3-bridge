pragma circom 2.2.0;

include "circom-ecdsa-p256/circuits/ecdsa.circom";
include "circom-ecdsa/circuits/ecdsa.circom";

include "./c1/eudi-wallet-key-derivation.circom";
include "./c2/credential-public-key-check.circom";
//include "./c3/credential-signature-verification.circom";
include "./c3/credential-signature-verification-optimized.circom";
include "./c4/blockchain-wallet-key-derivation.circom";

/*
 * EUDI Credential Wallet Binding Circuit
 *
 * This circuit implements zero-knowledge proof of credential wallet binding
 * for the European Digital Identity (EUDI) framework.
 *
 * The circuit proves:
 * 1. The prover knows the private key corresponding to a credential public key
 * 2. The credential was validly signed by a trusted issuer
 * 3. The prover controls both the credential wallet and blockchain wallet
 *
 * Components:
 * - C1: Derives EUDI wallet public key from private key (P-256)  
 * - C2: Verifies computed public key matches credential
 * - C3: Verifies credential signature by trusted issuer
 * - C4: Derives blockchain wallet public key from private key (secp256k1)
 *
 * This enables privacy-preserving credential presentation while maintaining
 * cryptographic binding between digital identity and blockchain assets.
 */

template CredentialWalletBinding() {
    // Public inputs
    signal input pk_I[2][6]; // Keep pk_I as root of trust even if pk_I is not used in the circuit (optimized version)
    signal input pk_0[2][4];

    // Private witnesses
    signal input sk_c[6];
    signal input pk_c[2][6]; // extracted from c.cnf.jwk in preprocessing
    signal input msghash[6];
    signal input r[6];
    signal input s[6];
    signal input sk_0[4];

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

    // C4: BlockchainWalletKeyDerivation (pk_0 = KeyDer(sk_0))
    // Proves knowledge of blockchain wallet private key by deriving public key
    component c4 = BlockchainWalletKeyDerivation();
    for (var i = 0; i < 4; i++) {
        c4.sk_0[i] <== sk_0[i];
    }

    // Verify that computed pk_0 matches the public input
    // This creates the binding between private key knowledge and public identity
    for (var i = 0; i < 4; i++) {
        c4.pk_0[0][i] === pk_0[0][i];
        c4.pk_0[1][i] === pk_0[1][i];
    }

}

component main { public [pk_I, pk_0] } = CredentialWalletBinding();