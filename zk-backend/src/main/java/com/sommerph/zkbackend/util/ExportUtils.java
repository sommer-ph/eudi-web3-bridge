package com.sommerph.zkbackend.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.sommerph.zkbackend.config.ProofPreparationProperties;
import com.sommerph.zkbackend.model.proofPreparation.monolithic.*;
import com.sommerph.zkbackend.model.proofPreparation.recursive.*;
import com.sommerph.zkbackend.repository.proofPreparation.ProofPreparationRegistry;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.io.File;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

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
            Map<String, Object> json = new LinkedHashMap<>();
            json.put("pk_I", toStringArray2D(binding.getPk_I()));
            json.put("pk_0", toStringArray2D(binding.getPk_0()));
            json.put("sk_c", toStringArray(binding.getSk_c()));
            json.put("pk_c", toStringArray2D(binding.getPk_c()));
            json.put("msghash", toStringArray(binding.getMsghash()));
            json.put("r", toStringArray(binding.getR()));
            json.put("s", toStringArray(binding.getS()));
            json.put("sk_0", toStringArray(binding.getSk_0()));
            String path = properties.getStorage().getPath() + "/" + userId + "-credential-wallet-binding.json";
            mapper.writeValue(new File(path), json);
        } catch (Exception e) {
            throw new RuntimeException("Failed to write cred-bind export file", e);
        }
    }

    private String[] toStringArray(BigInteger[] input) {
        return Arrays.stream(input).map(BigInteger::toString).toArray(String[]::new);
    }

    private String[][] toStringArray2D(BigInteger[][] input) {
        return Arrays.stream(input).map(this::toStringArray).toArray(String[][]::new);
    }


    public void writeRecursiveProofToFile(RecursiveProofInput recursiveProof, String userId) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(SerializationFeature.INDENT_OUTPUT);
            
            Map<String, Object> json = new LinkedHashMap<>();
            
            // pk_issuer
            Map<String, Object> pkIssuer = new LinkedHashMap<>();
            pkIssuer.put("x", recursiveProof.getPk_issuer().getX());
            pkIssuer.put("y", recursiveProof.getPk_issuer().getY());
            json.put("pk_issuer", pkIssuer);
            
            // msg
            json.put("msg", recursiveProof.getMsg());
            
            // signature
            Map<String, Object> signature = new LinkedHashMap<>();
            signature.put("r", recursiveProof.getSignature().getR());
            signature.put("s", recursiveProof.getSignature().getS());
            json.put("signature", signature);
            
            // pk_c
            Map<String, Object> pkC = new LinkedHashMap<>();
            pkC.put("x", recursiveProof.getPk_c().getX());
            pkC.put("y", recursiveProof.getPk_c().getY());
            json.put("pk_c", pkC);
            
            // sk_c
            json.put("sk_c", recursiveProof.getSk_c());
            
            // sk_0
            json.put("sk_0", recursiveProof.getSk_0());
            
            // pk_0
            Map<String, Object> pk0 = new LinkedHashMap<>();
            pk0.put("x", recursiveProof.getPk_0().getX());
            pk0.put("y", recursiveProof.getPk_0().getY());
            json.put("pk_0", pk0);
            
            // cc_0
            json.put("cc_0", recursiveProof.getCc_0());
            
            // derivation_index
            json.put("derivation_index", recursiveProof.getDerivation_index());
            
            // pk_i
            Map<String, Object> pkI = new LinkedHashMap<>();
            pkI.put("x", recursiveProof.getPk_i().getX());
            pkI.put("y", recursiveProof.getPk_i().getY());
            json.put("pk_i", pkI);
            
            // cc_i
            json.put("cc_i", recursiveProof.getCc_i());
            
            String path = properties.getStorage().getPath() + "/" + userId + "_recursive.json";
            mapper.writeValue(new File(path), json);
        } catch (Exception e) {
            throw new RuntimeException("Failed to write recursive proof export file", e);
        }
    }

    public CredentialWalletBindingExtended createCredentialWalletBindingExtended(String userId, ProofPreparationRegistry registry) {
        if (!registry.existsEudiWalletKeyDerivation(userId)) {
            throw new RuntimeException("Missing preparation data: C1 - EUDI Wallet Key Derivation");
        }
        if (!registry.existsCredentialPKCheck(userId)) {
            throw new RuntimeException("Missing preparation data: C2 - Credential Public Key Check");
        }
        if (!registry.existsCredentialSignatureVerificationExtended(userId)) {
            throw new RuntimeException("Missing preparation data: C3 Extended - Credential Signature Verification Extended");
        }
        if (!registry.existsBlockchainWalletKeyDerivation(userId)) {
            throw new RuntimeException("Missing preparation data: C4 - Blockchain Wallet Key Derivation");
        }

        EudiKeyDerivation c1 = registry.loadEudiWalletKeyDerivation(userId);
        EudiCredentialPublicKeyCheck c2 = registry.loadCredentialPKCheck(userId);
        EudiCredentialVerificationExtended c3Extended = registry.loadCredentialSignatureVerificationExtended(userId);
        BlockchainKeyDerivation c4 = registry.loadBlockchainWalletKeyDerivation(userId);

        return new CredentialWalletBindingExtended(
                toBigIntArray2D(c3Extended.getPk_I()),               // pk_I
                toBigIntArray2D(c4.getPk_0()),                       // pk_0
                toBigIntArray(c1.getSk_c()),                         // sk_c
                toBigIntArray2D(c2.getPk_cred()),                    // pk_c
                toBigIntArray(c3Extended.getMsghash()),              // msghash
                toBigIntArray(c3Extended.getR()),                    // r
                toBigIntArray(c3Extended.getS()),                    // s
                toBigIntArray(c4.getSk_0()),                         // sk_0
                toBigIntArray(c3Extended.getHeaderB64()),            // headerB64
                new BigInteger(c3Extended.getHeaderB64Length()),     // headerB64Length
                toBigIntArray(c3Extended.getPayloadB64()),           // payloadB64
                new BigInteger(c3Extended.getPayloadB64Length()),    // payloadB64Length
                c3Extended.getOffXB64() != null ? new BigInteger(c3Extended.getOffXB64()) : null,  // offXB64
                c3Extended.getLenXB64() != null ? new BigInteger(c3Extended.getLenXB64()) : null,  // lenXB64
                c3Extended.getDropX()  != null ? new BigInteger(c3Extended.getDropX())  : null,    // dropX
                c3Extended.getLenXInner() != null ? new BigInteger(c3Extended.getLenXInner()) : null, // lenXInner
                c3Extended.getOffYB64() != null ? new BigInteger(c3Extended.getOffYB64()) : null,  // offYB64
                c3Extended.getLenYB64() != null ? new BigInteger(c3Extended.getLenYB64()) : null,  // lenYB64
                c3Extended.getDropY()  != null ? new BigInteger(c3Extended.getDropY())  : null,    // dropY
                c3Extended.getLenYInner() != null ? new BigInteger(c3Extended.getLenYInner()) : null   // lenYInner
        );
    }

    public void writeCredBindExtendedDataToFile(CredentialWalletBindingExtended binding, String userId) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(SerializationFeature.INDENT_OUTPUT);
            Map<String, Object> json = new LinkedHashMap<>();
            
            // Basic fields
            json.put("pk_I", toStringArray2D(binding.getPk_I()));
            json.put("pk_0", toStringArray2D(binding.getPk_0()));
            json.put("sk_c", toStringArray(binding.getSk_c()));
            json.put("pk_c", toStringArray2D(binding.getPk_c()));
            json.put("msghash", toStringArray(binding.getMsghash()));
            json.put("r", toStringArray(binding.getR()));
            json.put("s", toStringArray(binding.getS()));
            json.put("sk_0", toStringArray(binding.getSk_0()));
            
            // Extended JWS fields
            json.put("headerB64", toStringArray(binding.getHeaderB64()));
            json.put("headerB64Length", binding.getHeaderB64Length().toString());
            json.put("payloadB64", toStringArray(binding.getPayloadB64()));
            json.put("payloadB64Length", binding.getPayloadB64Length().toString());
            
            // Aligned Base64url coordinate slice + inner selection fields
            if (binding.getOffXB64() != null) {
                json.put("offXB64", binding.getOffXB64().toString());
                json.put("lenXB64", binding.getLenXB64().toString());
                json.put("dropX", binding.getDropX().toString());
                json.put("lenXInner", binding.getLenXInner().toString());
                json.put("offYB64", binding.getOffYB64().toString());
                json.put("lenYB64", binding.getLenYB64().toString());
                json.put("dropY", binding.getDropY().toString());
                json.put("lenYInner", binding.getLenYInner().toString());
            }
            
            String path = properties.getStorage().getPath() + "/" + userId + "-credential-wallet-binding-extended.json";
            mapper.writeValue(new File(path), json);
        } catch (Exception e) {
            throw new RuntimeException("Failed to write extended cred-bind export file", e);
        }
    }

}
