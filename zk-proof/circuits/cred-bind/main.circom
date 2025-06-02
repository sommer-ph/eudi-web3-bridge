// Main circuit for proof pi_cred-bind

pragma circom 2.0.0;

include "./cred-bind/check_credential_ownership.circom";
include "./cred-bind/derive_eudi_key.circom";
include "./cred-bind/derive_blockchain_key.circom";
include "./cred-bind/verify_credential.circom";

template CredentialWalletBinding() {
    // PUBLIC INPUTS (EC points as arrays)
    signal input pk_I[2];    // Issuer public key (x, y)
    signal input pk_0[2];    // Blockchain wallet public key (x, y)

    // PRIVATE WITNESS
    signal input sk_c;       // EUDI secret key
    signal input sk_0;       // Blockchain secret key
    signal input credential[3]; // Structured credential parts (jwk, payload, signature)

    // Constraint 1: Derive pk_c from sk_c
    component deriveEudiKey = DeriveEudiKey();
    deriveEudiKey.sk <== sk_c;

    // Constraint 2: Check pk_c matches credential's cnf.jwk
    component credentialOwnershipCheck = CheckCredentialOwnership();
    credentialOwnershipCheck.pk_c <== deriveEudiKey.pk;
    credentialOwnershipCheck.jwk <== credential[0];

    // Constraint 3: Verify credential signature
    component verifyCredential = VerifyCredential();
    verifyCredential.pk_I <== pk_I;
    verifyCredential.message <== credential[1];
    verifyCredential.signature <== credential[2];

    // Constraint 4: Derive pk_0 from sk_0
    component deriveBcKey = DeriveBlockchainKey();
    deriveBcKey.sk <== sk_0;
    deriveBcKey.pk[0] <== pk_0[0]; // Compare x-coordinate
    deriveBcKey.pk[1] <== pk_0[1]; // Compare y-coordinate
}

component main = CredentialWalletBinding();
