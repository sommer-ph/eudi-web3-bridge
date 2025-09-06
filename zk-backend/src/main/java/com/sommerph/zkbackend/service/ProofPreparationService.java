package com.sommerph.zkbackend.service;

import com.sommerph.zkbackend.model.eudi.EudiWallet;
import com.sommerph.zkbackend.model.eudi.EudiCredential;
import com.sommerph.zkbackend.model.blockchain.BlockchainWallet;
import com.sommerph.zkbackend.model.proofPreparation.monolithic.*;
import com.sommerph.zkbackend.model.proofPreparation.recursive.*;
import com.sommerph.zkbackend.repository.proofPreparation.ProofPreparationRegistry;
import com.sommerph.zkbackend.service.eudi.EudiKeyManagementService;
import com.sommerph.zkbackend.service.eudi.EudiWalletService;
import com.sommerph.zkbackend.service.blockchain.BlockchainKeyManagementService;
import com.sommerph.zkbackend.service.blockchain.BlockchainWalletService;
import com.sommerph.zkbackend.util.ExportUtils;
import com.sommerph.zkbackend.util.JwsUtils;
import com.sommerph.zkbackend.util.SignatureUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bitcoinj.crypto.DeterministicKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class ProofPreparationService {

    private final EudiWalletService eudiWalletService;
    private final BlockchainWalletService blockchainWalletService;
    private final EudiKeyManagementService eudiKeyManagementService;
    private final BlockchainKeyManagementService blockchainKeyManagementService;
    private final ProofPreparationRegistry proofPreparationRegistry;
    private final ExportUtils exportUtils;
    
    @Value("${proof.extended.computeOffsets:true}")
    private boolean computeOffsets;

    public void prepareCredBindProof(String userId) {
        log.info("Prepare data for cred-bind proof for user: {}", userId);
        prepareEudiWalletKeyDerivation(userId);
        prepareEudiCredentialPublicKeyCheck(userId);
        prepareEudiCredentialVerification(userId);
        // prepareBlockchainWalletMasterKeyDerivation(userId);
        prepareBlockchainWalletChildKeyDerivation(userId, 0);

        log.info("Export cred-bind proof data for user: {}", userId);
        try {
            CredentialWalletBinding binding = exportUtils.createCredentialWalletBinding(userId, proofPreparationRegistry);
            exportUtils.writeCredBindDataToFile(binding, userId);
        } catch (Exception e) {
            throw new RuntimeException("Failed to export cred-bind proof data for user: " + userId, e);
        }
    }

    public void prepareCredBindExtendedProof(String userId) {
        log.info("Prepare extended data for cred-bind proof for user: {}", userId);
        prepareEudiWalletKeyDerivation(userId);
        prepareEudiCredentialPublicKeyCheck(userId);
        prepareEudiCredentialVerificationExtended(userId);
        prepareBlockchainWalletChildKeyDerivation(userId, 0);

        log.info("Export extended cred-bind proof data for user: {}", userId);
        try {
            CredentialWalletBindingExtended bindingExtended = exportUtils.createCredentialWalletBindingExtended(userId, proofPreparationRegistry);
            exportUtils.writeCredBindExtendedDataToFile(bindingExtended, userId);
        } catch (Exception e) {
            throw new RuntimeException("Failed to export extended cred-bind proof data for user: " + userId, e);
        }
    }

    // C1
    public void prepareEudiWalletKeyDerivation(String userId) {
        log.info("Prepare data for EUDI wallet key derivation for user: {}", userId);
        try {
            EudiWallet wallet = eudiWalletService.loadWallet(userId);
            String[] skLimbs = eudiKeyManagementService.getUserCredentialSecretKeyLimbs(wallet.getBase64SecretKey());

            EudiKeyDerivation data = new EudiKeyDerivation(
                    userId,
                    skLimbs
            );
            proofPreparationRegistry.saveEudiWalletKeyDerivation(data);
        } catch (Exception e) {
            throw new RuntimeException("Error preparing EUDI wallet key derivation data for user: " + userId, e);
        }
    }

    // C2
    public void prepareEudiCredentialPublicKeyCheck(String userId) {
        log.info("Prepare data for EUDI credential public key check for user: {}", userId);
        try {
            EudiWallet wallet = eudiWalletService.loadWallet(userId);

            Object cnfObj = wallet.getCredentials().get(0).getPayload().get("cnf");
            if (!(cnfObj instanceof Map)) {
                throw new RuntimeException("CNF field is not a valid map");
            }
            Map<String, Object> cnfMap = (Map<String, Object>) cnfObj;
            Object jwkObj = cnfMap.get("jwk");
            if (!(jwkObj instanceof Map)) {
                throw new RuntimeException("JWK field is not a valid map");
            }
            Map<String, Object> jwkMap = (Map<String, Object>) jwkObj;
            String[][] pkLimbs = eudiKeyManagementService.getCredentialBindingKeyJwkLimbs(jwkMap);

            EudiCredentialPublicKeyCheck data = new EudiCredentialPublicKeyCheck(
                    userId,
                    pkLimbs
            );
            proofPreparationRegistry.saveCredentialPKCheck(data);
        } catch (Exception e) {
            throw new RuntimeException("Error preparing credential public key check data for user: " + userId, e);
        }
    }

    // C3
    public void prepareEudiCredentialVerification(String userId) {
        log.info("Prepare data for EUDI credential verification for user: {}", userId);
        try {
            EudiWallet wallet = eudiWalletService.loadWallet(userId);
            EudiCredential credential = wallet.getCredentials().get(0);

            String[][] pkILimbs = eudiKeyManagementService.getIssuerPublicKeyLimbs();
            String[] msgHashLimbs = eudiKeyManagementService.computeCredentialMsgHashLimbs(
                    credential.getHeader(),
                    credential.getPayload()
            );
            Map<String, String[]> sigLimbs = eudiKeyManagementService.extractCredentialSignatureLimbs(
                    java.util.Base64.getUrlDecoder().decode(credential.getSignature())
            );

            EudiCredentialVerification data = new EudiCredentialVerification(
                    userId,
                    pkILimbs,
                    msgHashLimbs,
                    sigLimbs.get("r"),
                    sigLimbs.get("s")
            );
            proofPreparationRegistry.saveCredentialSignatureVerification(data);
        } catch (Exception e) {
            throw new RuntimeException("Error preparing credential verification data for user: " + userId, e);
        }
    }

    // C3 Extended
    public void prepareEudiCredentialVerificationExtended(String userId) {
        log.info("Prepare extended data for EUDI credential verification for user: {}", userId);

        try {
            EudiWallet wallet = eudiWalletService.loadWallet(userId);
            EudiCredential credential = wallet.getCredentials().get(0);

            // Convert header/payload maps to Base64url strings like in existing service method
            ObjectMapper mapper = new ObjectMapper();
            String headerB64 = SignatureUtils.base64url(mapper.writeValueAsBytes(credential.getHeader()));
            String payloadB64 = SignatureUtils.base64url(mapper.writeValueAsBytes(credential.getPayload()));

            // Validate Base64url strings
            if (!JwsUtils.isValidBase64UrlAscii(headerB64)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Invalid Base64url characters in credential header");
            }
            if (!JwsUtils.isValidBase64UrlAscii(payloadB64)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Invalid Base64url characters in credential payload");
            }

            // Get existing limb data
            String[][] pkILimbs = eudiKeyManagementService.getIssuerPublicKeyLimbs();
            String[] msgHashLimbs = eudiKeyManagementService.computeCredentialMsgHashLimbs(credential.getHeader(), credential.getPayload());
            Map<String, String[]> sigLimbs = eudiKeyManagementService.extractCredentialSignatureLimbs(
                    Base64.getUrlDecoder().decode(credential.getSignature()));

            // Convert Base64url strings to ASCII byte arrays (for SHA-256)
            String[] headerB64Bytes = JwsUtils.base64UrlToAsciiBytesString(headerB64);
            String[] payloadB64Bytes = JwsUtils.base64UrlToAsciiBytesString(payloadB64);

            // Compute Base64url coordinate offsets if enabled
            String offXB64 = null, lenXB64 = null, offYB64 = null, lenYB64 = null;
            if (computeOffsets) {
                try {
                    JwsUtils.Base64UrlOffsetResult offsetResult = JwsUtils.findJwkXYOffsetsInBase64url(payloadB64);

                    if (!offsetResult.found) {
                        throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,
                                "JWK x/y coordinates not found in Base64url payload when computeOffsets is enabled");
                    }

                    offXB64 = String.valueOf(offsetResult.offXB64);
                    lenXB64 = String.valueOf(offsetResult.lenXB64);
                    offYB64 = String.valueOf(offsetResult.offYB64);
                    lenYB64 = String.valueOf(offsetResult.lenYB64);
                    
                    // Validate extracted coordinates match original credential
                    JwsUtils.validateBase64urlCoordinates(payloadB64, offsetResult, credential.getPayload());
                } catch (Exception e) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                            "Error processing Base64url payload: " + e.getMessage());
                }
            }

            EudiCredentialVerificationExtended data = new EudiCredentialVerificationExtended(
                    userId,
                    pkILimbs,
                    msgHashLimbs,
                    sigLimbs.get("r"),
                    sigLimbs.get("s"),
                    headerB64Bytes,
                    String.valueOf(headerB64.length()),
                    payloadB64Bytes,
                    String.valueOf(payloadB64.length()),
                    offXB64,
                    lenXB64,
                    offYB64,
                    lenYB64
            );

            proofPreparationRegistry.saveCredentialSignatureVerificationExtended(data);

        } catch (ResponseStatusException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Error preparing extended EUDI credential verification for user: " + userId, e);
        }
    }

    // C4
    public void prepareBlockchainWalletMasterKeyDerivation(String userId) {
        prepareBlockchainWalletKeyDerivation(userId, false, 0);
    }

    public void prepareBlockchainWalletChildKeyDerivation(String userId, int index) {
        prepareBlockchainWalletKeyDerivation(userId, true, index);
    }

    private void prepareBlockchainWalletKeyDerivation(String userId, boolean useChild, int index) {
        log.info("Prepare data for blockchain wallet key derivation for user: {}, useChild: {}, index: {}", userId, useChild, index);
        try {
            BlockchainWallet wallet = blockchainWalletService.loadWallet(userId);
            DeterministicKey key;
            if (useChild) {
                key = blockchainKeyManagementService.deriveChildKey(wallet.getMnemonic(), index);
            } else {
                key = blockchainKeyManagementService.deriveMasterKey(wallet.getMnemonic());
            }
            String[] skLimbs = blockchainKeyManagementService.getSecretKeyLimbs(key);
            String[][] pkLimbs = blockchainKeyManagementService.getPublicKeyLimbs(key);
            BlockchainKeyDerivation data = new BlockchainKeyDerivation(
                    userId,
                    skLimbs,
                    pkLimbs
            );
            proofPreparationRegistry.saveBlockchainWalletKeyDerivation(data);
        } catch (Exception e) {
            throw new RuntimeException("Error preparing blockchain key derivation for user: " + userId, e);
        }
    }

    // Recursive proof input with all EUDI attributes
    public void prepareRecursiveProofInput(String userId, int derivationIndex) {
        log.info("Prepare recursive proof input data for user: {} with derivation index: {}", userId, derivationIndex);
        try {
            // EUDI wallet and credential data
            EudiWallet eudiWallet = eudiWalletService.loadWallet(userId);
            EudiCredential credential = eudiWallet.getCredentials().get(0);

            // Blockchain wallet data
            BlockchainWallet blockchainWallet = blockchainWalletService.loadWallet(userId);
            DeterministicKey masterKey = blockchainKeyManagementService.deriveMasterKey(blockchainWallet.getMnemonic());
            DeterministicKey childKey = blockchainKeyManagementService.deriveChildKey(blockchainWallet.getMnemonic(), derivationIndex);

            // Extract issuer public key (pk_issuer)
            Map<String, String> pkIssuerHex = eudiKeyManagementService.getIssuerPublicKeyHex();
            RecursiveProofInput.PublicKeyPoint pkIssuer = new RecursiveProofInput.PublicKeyPoint(
                    pkIssuerHex.get("x"),
                    pkIssuerHex.get("y")
            );

            // Extract message hash (msg)
            String msg = eudiKeyManagementService.getCredentialMsgHashHex(
                    credential.getHeader(),
                    credential.getPayload()
            );

            // Extract signature
            Map<String, String> signatureHex = eudiKeyManagementService.extractCredentialSignatureHex(
                    java.util.Base64.getUrlDecoder().decode(credential.getSignature())
            );
            RecursiveProofInput.Signature signature = new RecursiveProofInput.Signature(
                    signatureHex.get("r"),
                    signatureHex.get("s")
            );

            // Extract credential public key (pk_c)
            Object cnfObj = credential.getPayload().get("cnf");
            Map<String, Object> cnfMap = (Map<String, Object>) cnfObj;
            Map<String, Object> jwkMap = (Map<String, Object>) cnfMap.get("jwk");
            Map<String, String> pkCredHex = eudiKeyManagementService.getCredentialBindingKeyJwkHex(jwkMap);
            RecursiveProofInput.PublicKeyPoint pkC = new RecursiveProofInput.PublicKeyPoint(
                    pkCredHex.get("x"),
                    pkCredHex.get("y")
            );

            // Extract credential secret key (sk_c)
            String skC = eudiKeyManagementService.getUserCredentialSecretKeyHex(eudiWallet.getBase64SecretKey());

            // Extract master secret key (sk_0)
            String sk0 = blockchainKeyManagementService.getSecretKeyHex(masterKey);

            // Extract master public key (pk_0)
            Map<String, String> pkMasterHex = blockchainKeyManagementService.getPublicKeyHex(masterKey);
            RecursiveProofInput.PublicKeyPoint pk0 = new RecursiveProofInput.PublicKeyPoint(
                    pkMasterHex.get("x"),
                    pkMasterHex.get("y")
            );

            // Extract master chain code (cc_0)
            String cc0 = blockchainKeyManagementService.getChainCodeHex(masterKey);

            // Extract child public key (pk_i)
            Map<String, String> pkChildHex = blockchainKeyManagementService.getPublicKeyHex(childKey);
            RecursiveProofInput.PublicKeyPoint pkI = new RecursiveProofInput.PublicKeyPoint(
                    pkChildHex.get("x"),
                    pkChildHex.get("y")
            );

            // Extract child chain code (cc_i)
            String ccI = blockchainKeyManagementService.getChainCodeHex(childKey);

            // Create recursive proof input
            RecursiveProofInput recursiveInput = new RecursiveProofInput(
                    pkIssuer, msg, signature, pkC, skC, sk0, pk0, cc0, derivationIndex, pkI, ccI
            );

            // Export to file
            exportUtils.writeRecursiveProofToFile(recursiveInput, userId);

        } catch (Exception e) {
            throw new RuntimeException("Error preparing recursive proof input data for user: " + userId, e);
        }
    }

}
