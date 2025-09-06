package com.sommerph.zkbackend.repository.proofPreparation;

import com.sommerph.zkbackend.model.proofPreparation.monolithic.*;


public interface ProofPreparationRegistry {

    // C1: pk_c = KeyDer(sk_c)
    void saveEudiWalletKeyDerivation(EudiKeyDerivation data);
    EudiKeyDerivation loadEudiWalletKeyDerivation(String userId);
    boolean existsEudiWalletKeyDerivation(String userId);

    // C2: pk_c = c.cnf.jwk
    void saveCredentialPKCheck(EudiCredentialPublicKeyCheck data);
    EudiCredentialPublicKeyCheck loadCredentialPKCheck(String userId);
    boolean existsCredentialPKCheck(String userId);

    // C3: VerifySig(pk_I, c) = 1
    void saveCredentialSignatureVerification(EudiCredentialVerification data);
    EudiCredentialVerification loadCredentialSignatureVerification(String userId);
    boolean existsCredentialSignatureVerification(String userId);

    // C3 Extended with JWS binding data
    void saveCredentialSignatureVerificationExtended(EudiCredentialVerificationExtended data);
    EudiCredentialVerificationExtended loadCredentialSignatureVerificationExtended(String userId);
    boolean existsCredentialSignatureVerificationExtended(String userId);

    // C4: pk_0 = KeyDer(sk_0)
    void saveBlockchainWalletKeyDerivation(BlockchainKeyDerivation data);
    BlockchainKeyDerivation loadBlockchainWalletKeyDerivation(String userId);
    boolean existsBlockchainWalletKeyDerivation(String userId);

    // For every new model in proofPreparation that represents a high-level constraint, add methods for save, load, and exists.
}
