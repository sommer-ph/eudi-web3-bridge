package com.sommerph.zkbackend.service.eudi;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sommerph.zkbackend.config.EudiCredentialConfigProperties;
import com.sommerph.zkbackend.config.KeyConfigProperties;
import com.sommerph.zkbackend.model.eudi.EudiCredential;
import com.sommerph.zkbackend.model.eudi.EudiWallet;
import com.sommerph.zkbackend.util.SignatureUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.Signature;
import java.time.Instant;
import java.util.*;

import static java.nio.charset.StandardCharsets.UTF_8;

@Slf4j
@Service
@RequiredArgsConstructor
public class EudiCredentialService {

    private final EudiKeyManagementService keyService;
    private final EudiWalletService walletService;
    private final EudiCredentialConfigProperties config;
    private final KeyConfigProperties keyConfig;

    // Toggle to switch signing mode without adding a new endpoint.
    // false = RFC-conform (sign headerB64 "." payloadB64)
    // true  = ZK-padded (sign fixed-length padded header/payload bytes as used by the circuit)
    private static final boolean SIGN_ZK_PADDED = false;

    public EudiCredential issueCredential(String userId, Map<String, String> attributeValues) {
        log.info("Issue new SD-JWT credential for user: {}", userId);
        try {
            EudiWallet wallet = walletService.loadWallet(userId);

            KeyPair bindingKey;
            if (keyConfig.getCredential().getBinding().isGeneratePerCredential()) {
                bindingKey = keyService.generateKeyPair();
            } else {
                bindingKey = keyService.decodeKeyPair(
                        wallet.getBase64SecretKey(),
                        wallet.getBase64PublicKey()
                );
            }

            List<Map<String, String>> disclosures = new ArrayList<>();
            List<String> sdHashes = new ArrayList<>();

            for (String claim : config.getClaims()) {
                String value = attributeValues.get(claim);
                String salt = UUID.randomUUID().toString();
                disclosures.add(Map.of("salt", salt, "key", claim, "value", value));
                String disclosureJson = new ObjectMapper().writeValueAsString(List.of(salt, claim, value));
                byte[] hash = SignatureUtils.hash(disclosureJson);
                sdHashes.add(SignatureUtils.base64url(hash));
            }

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("iss", "issuer:123");
            payload.put("sub", "subject:" + wallet.getUserId());
            payload.put("iat", Instant.now().getEpochSecond());
            payload.put("exp", Instant.now().plusSeconds(3600).getEpochSecond());
            payload.put("_sd_alg", "sha-256");
            payload.put("_sd", sdHashes);
            payload.put("cnf", Map.of("jwk", keyService.toJwk(bindingKey.getPublic())));

            Map<String, Object> header = Map.of("alg", "ES256", "typ", "SD-JWT");

            ObjectMapper mapper = new ObjectMapper();
            String encodedHeader = SignatureUtils.base64url(mapper.writeValueAsBytes(header));
            String encodedPayload = SignatureUtils.base64url(mapper.writeValueAsBytes(payload));

            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(keyService.getIssuerKeyPair().getPrivate());
            if (SIGN_ZK_PADDED) {
                // Sign the exact fixed-length byte layout that the circuit hashes
                byte[] padded = keyService.buildCredentialPaddedSigningInput(header, payload);
                signer.update(padded);
            } else {
                // RFC-conform signing input (Base64url(header) + '.' + Base64url(payload))
                String signingInput = encodedHeader + "." + encodedPayload;
                signer.update(signingInput.getBytes(UTF_8));
            }
            String signature = SignatureUtils.base64url(signer.sign());

            EudiCredential credential = new EudiCredential(
                    header,
                    payload,
                    signature,
                    disclosures
            );

            walletService.addCredential(userId, credential);
            return credential;
        } catch (Exception e) {
            log.error("Failed to issue credential for user: {}", userId, e);
            throw new RuntimeException("Credential issuance failed for user: " + userId, e);
        }
    }

}
