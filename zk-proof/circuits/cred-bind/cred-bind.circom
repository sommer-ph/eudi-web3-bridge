pragma circom 2.2.0;

include "circom-ecdsa-p256/circuits/ecdsa.circom";
include "circom-ecdsa/circuits/ecdsa.circom";

include "./c1/eudi-wallet-key-derivation.circom";
include "./c2/credential-public-key-check.circom";
include "./c3/credential-signature-verification.circom";
include "./c4/blockchain-wallet-key-derivation.circom";

template CredentialWalletBinding() {
    // Public inputs
    signal input pk_I[2][6];
    signal input pk_0[2][4];

    // Private witnesses
    signal input sk_c[6];
    signal input pk_c[2][6]; // extracted from c.cnf.jwk in preprocessing
    signal input msghash[6];
    signal input r[6];
    signal input s[6];
    signal input sk_0[4];

    // C1: EudiWalletKeyDerivation (pk_c = KeyDer(sk_c))
    component c1 = EudiWalletKeyDerivation();
    for (var i = 0; i < 6; i++) {
        c1.sk_c[i] <== sk_c[i];
    }

    // C2: CredentialPKCheck (pk_c_computed === pk_c (extracted from c.cnf.jwk))
    component c2 = CredentialPKCheck();
    for (var i = 0; i < 6; i++) {
        c2.pk_c[0][i] <== c1.pk_c[0][i];
        c2.pk_c[1][i] <== c1.pk_c[1][i];
        c2.pk_cred[0][i] <== pk_c[0][i];
        c2.pk_cred[1][i] <== pk_c[1][i];
    }

    // C3: CredentialSignatureVerification (VerifySig(pk_I, msghash, r, s) === 1)
    component c3 = CredentialSignatureVerification();
    for (var i = 0; i < 6; i++) {
        c3.msghash[i] <== msghash[i];
        c3.r[i] <== r[i];
        c3.s[i] <== s[i];
        c3.pk_I[0][i] <== pk_I[0][i];
        c3.pk_I[1][i] <== pk_I[1][i];
    }

    // C4: BlockchainWalletKeyDerivation (pk_0 = KeyDer(sk_0))
    component c4 = BlockchainWalletKeyDerivation();
    for (var i = 0; i < 4; i++) {
        c4.sk_0[i] <== sk_0[i];
    }

    // Check that computed pk_0 matches input pk_0
    for (var i = 0; i < 4; i++) {
        c4.pk_0[0][i] === pk_0[0][i];
        c4.pk_0[1][i] === pk_0[1][i];
    }

}

component main { public [pk_I, pk_0] } = CredentialWalletBinding();