package com.sommerph.zkbackend.controller;

import com.sommerph.zkbackend.service.ProofPreparationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Min;
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

    @Operation(summary = "Prepare all data for credential-wallet binding proof (monolithic circuit)")
    @PostMapping("/cred-bind/{userId}")
    public ResponseEntity<?> prepareCredBindProof(@PathVariable @NotBlank String userId) {
        log.info("Prepare credential-wallet binding proof for user: {}", userId);
        try {
            proofService.prepareCredBindProof(userId);
            return ResponseEntity.ok("Credential-wallet binding proof data prepared for user: " + userId);
        } catch (Exception e) {
            log.error("Failed to prepare credential-wallet binding proof for user: {}", userId, e);
            return ResponseEntity.internalServerError().body("Error preparing proof: " + e.getMessage());
        }
    }

    @Operation(summary = "Prepare EUDI wallet key derivation data")
    @PostMapping("/eudi-key-derivation/{userId}")
    public ResponseEntity<?> prepareEudiKeyDerivation(@PathVariable @NotBlank String userId) {
        log.info("Prepare EUDI wallet key derivation for user: {}", userId);
        try {
            proofService.prepareEudiWalletKeyDerivation(userId);
            return ResponseEntity.ok("EUDI wallet key derivation data prepared for user: " + userId);
        } catch (Exception e) {
            log.error("Failed to prepare EUDI wallet key derivation for user: {}", userId, e);
            return ResponseEntity.internalServerError().body("Error: " + e.getMessage());
        }
    }

    @Operation(summary = "Prepare EUDI credential public key check data")
    @PostMapping("/eudi-cred-pubkey/{userId}")
    public ResponseEntity<?> prepareEudiCredentialPublicKeyCheck(@PathVariable @NotBlank String userId) {
        log.info("Prepare EUDI credential public key check for user: {}", userId);
        try {
            proofService.prepareEudiCredentialPublicKeyCheck(userId);
            return ResponseEntity.ok("EUDI credential public key check data prepared for user: " + userId);
        } catch (Exception e) {
            log.error("Failed to prepare EUDI credential public key check for user: {}", userId, e);
            return ResponseEntity.internalServerError().body("Error: " + e.getMessage());
        }
    }

    @Operation(summary = "Prepare EUDI credential signature verification data")
    @PostMapping("/eudi-cred-verification/{userId}")
    public ResponseEntity<?> prepareEudiCredentialVerification(@PathVariable @NotBlank String userId) {
        log.info("Prepare EUDI credential signature verification for user: {}", userId);
        try {
            proofService.prepareEudiCredentialVerification(userId);
            return ResponseEntity.ok("EUDI credential verification data prepared for user: " + userId);
        } catch (Exception e) {
            log.error("Failed to prepare EUDI credential verification for user: {}", userId, e);
            return ResponseEntity.internalServerError().body("Error: " + e.getMessage());
        }
    }

    @Operation(summary = "Prepare Blockchain master key derivation data")
    @PostMapping("/blockchain-master-derivation/{userId}")
    public ResponseEntity<?> prepareBlockchainMasterKeyDerivation(@PathVariable @NotBlank String userId) {
        log.info("Prepare Blockchain master key derivation for user: {}", userId);
        try {
            proofService.prepareBlockchainWalletMasterKeyDerivation(userId);
            return ResponseEntity.ok("Blockchain master key derivation data prepared for user: " + userId);
        } catch (Exception e) {
            log.error("Failed to prepare Blockchain master key derivation for user: {}", userId, e);
            return ResponseEntity.internalServerError().body("Error: " + e.getMessage());
        }
    }

    @Operation(summary = "Prepare Blockchain child key derivation data")
    @PostMapping("/blockchain-child-derivation/{userId}/{index}")
    public ResponseEntity<?> prepareBlockchainChildKeyDerivation(
            @PathVariable @NotBlank String userId,
            @PathVariable @Min(0) int index) {
        log.info("Prepare Blockchain child key derivation for user: {}, index: {}", userId, index);
        try {
            proofService.prepareBlockchainWalletChildKeyDerivation(userId, index);
            return ResponseEntity.ok("Blockchain child key derivation data prepared for user: " + userId + ", index: " + index);
        } catch (Exception e) {
            log.error("Failed to prepare Blockchain child key derivation for user: {}, index: {}", userId, index, e);
            return ResponseEntity.internalServerError().body("Error: " + e.getMessage());
        }
    }

    @Operation(summary = "Prepare all recursive proof data (inner and outer)")
    @PostMapping("/recursive/all/{userId}")
    public ResponseEntity<?> prepareRecursiveProofs(@PathVariable @NotBlank String userId) {
        log.info("Prepare all recursive proofs for user: {}", userId);
        try {
            proofService.prepareRecursiveProofs(userId);
            return ResponseEntity.ok("All recursive proof data prepared for user: " + userId);
        } catch (Exception e) {
            log.error("Failed to prepare recursive proofs for user: {}", userId, e);
            return ResponseEntity.internalServerError().body("Error: " + e.getMessage());
        }
    }

    @Operation(summary = "Prepare inner proof data for recursive proof generation")
    @PostMapping("/recursive/inner/{userId}")
    public ResponseEntity<?> prepareInnerProof(@PathVariable @NotBlank String userId) {
        log.info("Prepare inner proof for recursive proof for user: {}", userId);
        try {
            proofService.prepareInnerProof(userId);
            return ResponseEntity.ok("Inner proof data prepared for user: " + userId);
        } catch (Exception e) {
            log.error("Failed to prepare inner proof for user: {}", userId, e);
            return ResponseEntity.internalServerError().body("Error: " + e.getMessage());
        }
    }

    @Operation(summary = "Prepare outer proof data for recursive proof generation")
    @PostMapping("/recursive/outer/{userId}")
    public ResponseEntity<?> prepareOuterProof(@PathVariable @NotBlank String userId) {
        log.info("Prepare outer proof for recursive proof for user: {}", userId);
        try {
            proofService.prepareOuterProof(userId);
            return ResponseEntity.ok("Outer proof data prepared for user: " + userId);
        } catch (Exception e) {
            log.error("Failed to prepare outer proof for user: {}", userId, e);
            return ResponseEntity.internalServerError().body("Error: " + e.getMessage());
        }
    }

}
