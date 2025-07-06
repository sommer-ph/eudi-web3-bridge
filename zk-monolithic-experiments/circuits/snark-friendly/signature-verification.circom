pragma circom 2.2.0;

include "circomlib/circuits/eddsamimc.circom";

template MySignatureCheck() {
    signal input message;
    signal input publicKeyX;
    signal input publicKeyY;
    signal input signatureR8x;
    signal input signatureR8y;
    signal input signatureS;
    
    signal output isValid;
    
    component verifier = EdDSAMiMCVerifier();
    verifier.enabled <== 1;
    verifier.Ax <== publicKeyX;
    verifier.Ay <== publicKeyY;
    verifier.R8x <== signatureR8x;
    verifier.R8y <== signatureR8y;
    verifier.S <== signatureS;
    verifier.M <== message;
    
    isValid <== 1;
}

component main = MySignatureCheck();