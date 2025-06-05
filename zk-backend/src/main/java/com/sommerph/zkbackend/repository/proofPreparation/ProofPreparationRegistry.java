package com.sommerph.zkbackend.repository.proofPreparation;

import com.sommerph.zkbackend.model.proofPreparation.EudiCredentialVerification;

public interface ProofPreparationRegistry {

    void saveEudiCredentialVerification(EudiCredentialVerification data);

    EudiCredentialVerification loadEudiCredentialVerification(String userId);

    boolean existsEudiCredentialVerification(String userId);

    // For every new model in proofPreparation, add methods for save, load, and exists.

}
