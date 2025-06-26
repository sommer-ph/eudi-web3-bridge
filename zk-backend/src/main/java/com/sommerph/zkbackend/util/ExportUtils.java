package com.sommerph.zkbackend.util;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.sommerph.zkbackend.config.ProofPreparationProperties;
import com.sommerph.zkbackend.model.proofPreparation.monolithic.*;
import com.sommerph.zkbackend.repository.proofPreparation.ProofPreparationRegistry;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.io.File;
import java.math.BigInteger;
import java.util.Arrays;

@Component
@RequiredArgsConstructor
public class ExportUtils {

    private final ProofPreparationProperties properties;

    public CredentialWalletBinding createCredentialWalletBinding(String userId, ProofPreparationRegistry registry) {
        if (!registry.existsEudiWalletKeyDerivation(userId)) {
            throw new RuntimeException("Missing preparation data: C1 - EUDI Wallet Key Derivation");
        }
        if (!registry.existsCredentialPKCheck(userId)) {
            throw new RuntimeException("Missing preparation data: C2 - Credential Public Key Check");
        }
        if (!registry.existsCredentialSignatureVerification(userId)) {
            throw new RuntimeException("Missing preparation data: C3 - Credential Signature Verification");
        }
        if (!registry.existsBlockchainWalletKeyDerivation(userId)) {
            throw new RuntimeException("Missing preparation data: C4 - Blockchain Wallet Key Derivation");
        }

        EudiKeyDerivation c1 = registry.loadEudiWalletKeyDerivation(userId);
        EudiCredentialPublicKeyCheck c2 = registry.loadCredentialPKCheck(userId);
        EudiCredentialVerification c3 = registry.loadCredentialSignatureVerification(userId);
        BlockchainKeyDerivation c4 = registry.loadBlockchainWalletKeyDerivation(userId);

        return new CredentialWalletBinding(
                toBigIntArray2D(c3.getPk_I()),
                toBigIntArray2D(c4.getPk_0()),
                toBigIntArray(c1.getSk_c()),
                toBigIntArray2D(c2.getPk_cred()),
                toBigIntArray(c3.getMsghash()),
                toBigIntArray(c3.getR()),
                toBigIntArray(c3.getS()),
                toBigIntArray(c4.getSk_0())
        );
    }

    private BigInteger[] toBigIntArray(String[] input) {
        return Arrays.stream(input).map(BigInteger::new).toArray(BigInteger[]::new);
    }

    private BigInteger[][] toBigIntArray2D(String[][] input) {
        return Arrays.stream(input).map(this::toBigIntArray).toArray(BigInteger[][]::new);
    }

    public void writeCredBindDataToFile(CredentialWalletBinding binding, String userId) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(SerializationFeature.INDENT_OUTPUT);
            // For Circom input we must preserve exact limb values.
            // Write BigInteger values as strings to avoid loss of precision
            // when the JSON is later parsed by Node.js during witness generation.
            mapper.getFactory().configure(JsonGenerator.Feature.WRITE_NUMBERS_AS_STRINGS, true);

            String path = properties.getStorage().getPath() + "/" + userId + "-credential-wallet-binding.json";
            mapper.writeValue(new File(path), binding);
        } catch (Exception e) {
            throw new RuntimeException("Failed to write cred-bind export file", e);
        }
    }

}
