package com.sommerph.zkbackend.controller;

import com.sommerph.zkbackend.service.ProofPreparationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@Validated
@RestController
@RequestMapping("/api/proof/preparation")
@RequiredArgsConstructor
@Tag(name = "Proof Preparation", description = "Endpoints for preparing data for zk-SNARK implementation")
public class ProofPreparationController {

    private final ProofPreparationService proofPreparationService;

    @Operation(summary = "Prepare credential-wallet binding proof for the given user")
    @PostMapping("/cred-bind/{userId}")
    public ResponseEntity<?> prepareCredBindProof(String userId) {
        log.info("Prepare credential-wallet binding proof for user: {}", userId);
        return ResponseEntity.ok("Proof data prepared for user: " + userId);
    }

    @Operation(summary = "Prepare monolithic derived key binding proof for the given user")
    @PostMapping("/key-bind-monolithic/{userId}")
    public ResponseEntity<?> prepareKeyBindMonolithicProof(String userId) {
        log.info("Prepare monolithic derived key binding proof for user: {}", userId);
        return ResponseEntity.ok("Proof data prepared for user: " + userId);
    }

    @Operation(summary = "Prepare recursive derived key binding proof for the given user")
    @PostMapping("/key-bind-recursive/{userId}")
    public ResponseEntity<?> prepareKeyBindRecursiveProof(String userId) {
        log.info("Prepare recursive derived key binding proof for user: {}", userId);
        return ResponseEntity.ok("Proof data prepared for user: " + userId);
    }

}
