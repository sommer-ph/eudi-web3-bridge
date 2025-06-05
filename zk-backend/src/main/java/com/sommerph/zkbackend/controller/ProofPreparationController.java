package com.sommerph.zkbackend.controller;

import com.sommerph.zkbackend.service.ProofPreparationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@Slf4j
@Validated
@RestController
@RequestMapping("/api/proof/preparation")
@RequiredArgsConstructor
@Tag(name = "Proof Preparation", description = "Endpoints for preparing data for zk-SNARK proof generation")
public class ProofPreparationController {

    private final ProofPreparationService proofService;

    // Proof composition endpoints

    @Operation(summary = "Prepare all inputs for cred-bind proof")
    @PostMapping("/cred-bind/{userId}")
    public ResponseEntity<?> prepareCredBindProof(@PathVariable @NotBlank String userId) {
        log.info("Prepare cred-bind proof for user: {}", userId);
        try {
            proofService.prepareCredBindProof(userId);
            return ResponseEntity.ok("Cred-bind proof prepared for user: " + userId);
        } catch (Exception e) {
            log.error("Failed to prepare cred-bind proof for user: {}", userId, e);
            return ResponseEntity.internalServerError().body("Error preparing cred-bind proof: " + e.getMessage());
        }
    }

    @Operation(summary = "Prepare all inputs for monolithic proof composition")
    @PostMapping("/monolithic-composition/{userId}")
    public ResponseEntity<?> prepareMonolithicProof(@PathVariable @NotBlank String userId) {
        log.info("Prepare monolithic proof for user: {}", userId);
        try {
            proofService.prepareMonolithicProof(userId);
            return ResponseEntity.ok("Monolithic proof prepared for user: " + userId);
        } catch (Exception e) {
            log.error("Failed to prepare monolithic proof for user: {}", userId, e);
            return ResponseEntity.internalServerError().body("Error preparing monolithic proof: " + e.getMessage());
        }
    }

    @Operation(summary = "Prepare all inputs for recursive proof composition")
    @PostMapping("/recursive-composition/{userId}")
    public ResponseEntity<?> prepareRecursiveProof(@PathVariable @NotBlank String userId) {
        log.info("Prepare recursive proof for user: {}", userId);
        try {
            proofService.prepareRecursiveProof(userId);
            return ResponseEntity.ok("Recursive proof prepared for user: " + userId);
        } catch (Exception e) {
            log.error("Failed to prepare recursive proof for user: {}", userId, e);
            return ResponseEntity.internalServerError().body("Error preparing recursive proof: " + e.getMessage());
        }
    }

    // Sub-proof endpoints

    @Operation(summary = "Prepare EUDI key derivation proof inputs")
    @PostMapping("/eudi-key-derivation/{userId}")
    public ResponseEntity<?> prepareEudiKeyDerivation(@PathVariable @NotBlank String userId) {
        log.info("Prepare EUDI key derivation proof for user: {}", userId);
        try {
            proofService.prepareEudiKeyDerivationProof(userId);
            return ResponseEntity.ok("EUDI key derivation proof prepared for user: " + userId);
        } catch (Exception e) {
            log.error("Failed to prepare EUDI key derivation proof for user: {}", userId, e);
            return ResponseEntity.internalServerError().body("Error preparing EUDI key derivation proof: " + e.getMessage());
        }
    }

    @Operation(summary = "Prepare EUDI credential public key inclusion proof inputs")
    @PostMapping("/eudi-cred-pubkey/{userId}")
    public ResponseEntity<?> prepareEudiCredPubKeyProof(@PathVariable @NotBlank String userId) {
        log.info("Prepare EUDI credential public key inclusion proof for user: {}", userId);
        try {
            proofService.prepareEudiCredentailPubKeyProof(userId);
            return ResponseEntity.ok("EUDI credential public key inclusion proof prepared for user: " + userId);
        } catch (Exception e) {
            log.error("Failed to prepare EUDI credential public key inclusion proof for user: {}", userId, e);
            return ResponseEntity.internalServerError().body("Error preparing EUDI credential public key inclusion proof: " + e.getMessage());
        }
    }

    @Operation(summary = "Prepare EUDI credential verification proof inputs")
    @PostMapping("/eudi-cred-verification/{userId}")
    public ResponseEntity<?> prepareEudiCredentialVerification(@PathVariable @NotBlank String userId) {
        log.info("Prepare EUDI credential verification proof for user: {}", userId);
        try {
            proofService.prepareEudiCredentialVerificationProof(userId);
            return ResponseEntity.ok("EUDI credential verification proof prepared for user: " + userId);
        } catch (Exception e) {
            log.error("Failed to prepare EUDI credential verification proof for user: {}", userId, e);
            return ResponseEntity.internalServerError().body("Error preparing EUDI credential verification proof: " + e.getMessage());
        }
    }

    @Operation(summary = "Prepare blockchain master key derivation proof inputs")
    @PostMapping("/blockchain-master-derivation/{userId}")
    public ResponseEntity<?> prepareBlockchainMasterKeyDerivation(@PathVariable @NotBlank String userId) {
        log.info("Prepare blockchain master key derivation proof for user: {}", userId);
        try {
            proofService.prepareBlockchainMasterKeyDerivationProof(userId);
            return ResponseEntity.ok("Blockchain master key derivation proof prepared for user: " + userId);
        } catch (Exception e) {
            log.error("Failed to prepare blockchain master key derivation proof for user: {}", userId, e);
            return ResponseEntity.internalServerError().body("Error preparing blockchain master key derivation proof: " + e.getMessage());
        }
    }

    @Operation(summary = "Prepare blockchain child key derivation proof inputs")
    @PostMapping("/blockchain-child-derivation/{userId}")
    public ResponseEntity<?> prepareBlockchainChildKeyDerivation(@PathVariable @NotBlank String userId) {
        log.info("Prepare blockchain child key derivation proof for user: {}", userId);
        try {
            proofService.prepareBlockchainChildKeyDerivationProof(userId);
            return ResponseEntity.ok("Blockchain child key derivation proof prepared for user: " + userId);
        } catch (Exception e) {
            log.error("Failed to prepare blockchain child key derivation proof for user: {}", userId, e);
            return ResponseEntity.internalServerError().body("Error preparing blockchain child key derivation proof: " + e.getMessage());
        }
    }

}
