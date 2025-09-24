pragma circom 2.2.0;

include "circomlib/circuits/sha256/sha256.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/multiplexer.circom";
include "circom-ecdsa-p256/circuits/ecdsa.circom";

include "../utils/base64-decoder.circom";

template C3WithHash() {
    var MAX_HEADER = 64;
    var MAX_PAYLOAD = 1024;
    var MAX_TOTAL = MAX_HEADER + 1 + MAX_PAYLOAD; // +1 for dot separator
    
    // Inputs
    signal input headerB64[MAX_HEADER];
    signal input headerB64Length;
    signal input payloadB64[MAX_PAYLOAD];
    signal input payloadB64Length;
    signal input msghash[6];
    signal input r[6];
    signal input s[6];
    // signal input pk_I[2][6]; // Commented out for optimized variant with fixed pk
    
    // Declare components
    component headerCheck[MAX_HEADER];
    component payloadCheck[MAX_PAYLOAD];
    component limb2num[6];
    
    // Part 1. Message hash
    
    // Step 1. Create concatenated array header dot payload
    signal combined[MAX_TOTAL];
    
    // Copy header (with length check)
    for (var i = 0; i < MAX_HEADER; i++) {
        headerCheck[i] = LessThan(8);
        headerCheck[i].in[0] <== i;
        headerCheck[i].in[1] <== headerB64Length;
        
        combined[i] <== headerCheck[i].out * headerB64[i];
    }
    
    // Insert dot separator which is ASCII code forty six
    combined[MAX_HEADER] <== 46;
    
    // Copy payload (with length check)
    for (var i = 0; i < MAX_PAYLOAD; i++) {
        payloadCheck[i] = LessThan(10);
        payloadCheck[i].in[0] <== i;
        payloadCheck[i].in[1] <== payloadB64Length;
        
        combined[MAX_HEADER + 1 + i] <== payloadCheck[i].out * payloadB64[i];
    }
    
    // Step 2. Compute SHA 256
    component sha = Sha256(MAX_TOTAL * 8);
    component byte2bits[MAX_TOTAL];
    
    for (var i = 0; i < MAX_TOTAL; i++) {
        byte2bits[i] = Num2Bits(8);
        byte2bits[i].in <== combined[i];
        // Feed bytes from most significant bit to least significant bit to match standard SHA 256 byte semantics
        for (var j = 0; j < 8; j++) {
            sha.in[i * 8 + j] <== byte2bits[i].out[7 - j];
        }
    }
    
    // Step 3. Convert SHA 256 result to forty three bit limbs in little endian order
    signal computedHash[6];
    
    for (var i = 0; i < 6; i++) {
        limb2num[i] = Bits2Num(43);
        for (var j = 0; j < 43; j++) {
            var bitPos = i * 43 + j;
            if (bitPos < 256) {
                // sha.out is most significant bit first. Reverse to obtain least significant bit first numeric interpretation
                limb2num[i].in[j] <== sha.out[255 - bitPos];
            } else {
                limb2num[i].in[j] <== 0;
            }
        }
        computedHash[i] <== limb2num[i].out;
    }
    
    // Step 4. Compare with expected hash
    for (var i = 0; i < 6; i++) {
        computedHash[i] === msghash[i];
    }

    // Part 2. ECDSA Signature Verification (Optimized variant with fixed pk)
    component ecdsaVerify = ECDSAVerifyFixedPubkey(43, 6);

    for (var i = 0; i < 6; i++) {
        ecdsaVerify.msghash[i] <== msghash[i];
        ecdsaVerify.r[i] <== r[i];
        ecdsaVerify.s[i] <== s[i];
    }

    // Require signature to be valid
    ecdsaVerify.result === 1;

    // Part 2. ECDSA Signature Verification (Original variant - commented out)
    // component ecdsaVerify = ECDSAVerifyNoPubkeyCheck(43, 6);
    //
    // for (var i = 0; i < 6; i++) {
    //     ecdsaVerify.msghash[i] <== msghash[i];
    //     ecdsaVerify.r[i] <== r[i];
    //     ecdsaVerify.s[i] <== s[i];
    //     ecdsaVerify.pubkey[0][i] <== pk_I[0][i];
    //     ecdsaVerify.pubkey[1][i] <== pk_I[1][i];
    // }
    //
    // // Require signature to be valid
    // ecdsaVerify.result === 1;
}

component main { public [ msghash ] } = C3WithHash();
