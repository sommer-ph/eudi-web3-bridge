pragma circom 2.2.0;

include "circom-ecdsa-p256/circuits/ecdsa.circom";
include "circom-ecdsa/circuits/ecdsa.circom";

include "../cred-bind-eudi-only/c1/eudi-wallet-key-derivation.circom";
include "../cred-bind-eudi-only/c2/credential-public-key-check.circom";
//include "../cred-bind-eudi-only/c3/credential-signature-verification.circom";
include "../cred-bind-eudi-only/c3/credential-signature-verification-optimized.circom";

/*
 * Nova Credential Wrapper Circuit
 *
 * This wrapper makes the existing monolithic credential binding circuit
 * compatible with Nova's folding verification by adding the required
 * z_i -> z_{i+1} state transformation pattern.
 *
 * The wrapper:
 * 1. Accepts Nova state input z_i (single field element)
 * 2. Performs the existing credential verification unchanged
 * 3. Outputs updated state z_{i+1} = z_i + 1 to indicate successful verification
 *
 * This allows Nova to verify the credential proof while maintaining
 * the existing circuit logic and constraints.
 */

template NovaCredBindWrapper() {
    // Nova state interface (required for folding)
    signal input z_i[1];        // Input state from previous folding step
    signal output z_out[1];     // Output state for next folding step
    
    // Original credential circuit inputs (unchanged)
    signal input pk_I[2][6];    // Issuer public key
    signal input sk_c[6];       // Credential private key
    signal input pk_c[2][6];    // Credential public key (from JWT)
    signal input msghash[6];    // Message hash to verify
    signal input r[6];          // ECDSA signature r component
    signal input s[6];          // ECDSA signature s component
    
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
    
    // Nova state transformation: z_{i+1} = z_i + 1
    // This simple transformation indicates successful verification
    // and provides the state continuity required by Nova folding
    z_out[0] <== z_i[0] + 1;
}

// z_i is public to enable Nova folding verification
component main { public [ z_i ] } = NovaCredBindWrapper();