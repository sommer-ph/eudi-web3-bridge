pragma circom 2.2.0;

include "circomlib/circuits/sha256/sha256.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/multiplexer.circom";

include "../utils/base64-decoder.circom";

template MsgPkcBinding() {
    var MAX_HEADER = 64;
    var MAX_PAYLOAD = 1024;
    var MAX_JSON_PAYLOAD = 512; // Max JSON payload length
    var MAX_TOTAL = MAX_HEADER + 1 + MAX_PAYLOAD; // +1 for dot separator
    var MAX_COORD_LEN = 44; // Max Base64url coordinate length
    
    // Inputs
    signal input headerB64[MAX_HEADER];
    signal input headerB64Length;
    signal input payloadB64[MAX_PAYLOAD]; 
    signal input payloadB64Length;
    // Aligned Base64url slice parameters and inner extraction info
    signal input offXB64;     // aligned start (multiple of 4)
    signal input lenXB64;     // aligned length (<=64)
    signal input dropX;       // bytes to drop after outer decode (0..2)
    signal input lenXInner;   // inner ascii length (43 or 44)
    signal input offYB64;     // aligned start (multiple of 4)
    signal input lenYB64;     // aligned length (<=64)
    signal input dropY;       // bytes to drop after outer decode (0..2)
    signal input lenYInner;   // inner ascii length (43 or 44)
    signal input msghash[6];
    signal input pk_c[2][6];
    
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
    
// Part 2. Extract and compare pk_c
    
    // Declare components for Part 2
    var MAX_OUTER = 64;
    component lt_i_lenX[MAX_OUTER];
    component lt_i_lenY[MAX_OUTER];
    

    // Step A. Bounds and coarse length checks for the outer slice
    component lt_offX   = LessThan(16);
    component lt_lenX   = LessThan(16);
    component lt_sumX   = LessThan(16);
    component lt_offY   = LessThan(16);
    component lt_lenY   = LessThan(16);
    component lt_sumY   = LessThan(16);

    lt_offX.in[0] <== offXB64;
    lt_offX.in[1] <== payloadB64Length;
    lt_lenX.in[0] <== lenXB64;
    lt_lenX.in[1] <== 64; // aligned slice up to 64 chars (16 blocks)
    signal sumX <== offXB64 + lenXB64;
    lt_sumX.in[0] <== sumX;
    lt_sumX.in[1] <== payloadB64Length;

    lt_offY.in[0] <== offYB64;
    lt_offY.in[1] <== payloadB64Length;
    lt_lenY.in[0] <== lenYB64;
    lt_lenY.in[1] <== 64;
    signal sumY <== offYB64 + lenYB64;
    lt_sumY.in[0] <== sumY;
    lt_sumY.in[1] <== payloadB64Length;

    signal inBoundsX1 <== lt_offX.out * lt_lenX.out;
    signal inBoundsX <== inBoundsX1 * lt_sumX.out;
    signal inBoundsY1 <== lt_offY.out * lt_lenY.out;
    signal inBoundsY <== inBoundsY1 * lt_sumY.out;
    signal inBoundsXY <== inBoundsX * inBoundsY;
    component inBoundsCheck = IsEqual();
    inBoundsCheck.in[0] <== inBoundsXY;
    inBoundsCheck.in[1] <== 1;

    // Step B. Slice outer Base64url substrings X and Y
    signal x_outer[MAX_OUTER];
    signal y_outer[MAX_OUTER];
    signal selX_idx[MAX_OUTER];
    signal selY_idx[MAX_OUTER];
    signal x_selected[MAX_OUTER];
    signal y_selected[MAX_OUTER];
    
    // Create selector components
    component selX[MAX_OUTER];
    component selY[MAX_OUTER];
    component selX_check[MAX_OUTER];
    component selY_check[MAX_OUTER];
    // Gate with two to one multiplexers to enforce selected inside bounds and padding outside bounds
    component gateX[MAX_OUTER];
    component gateY[MAX_OUTER];

    for (var i = 0; i < MAX_OUTER; i++) {
        // Bounds guard i less than length
        lt_i_lenX[i] = LessThan(8);
        lt_i_lenX[i].in[0] <== i;
        lt_i_lenX[i].in[1] <== lenXB64;
        lt_i_lenY[i] = LessThan(8);
        lt_i_lenY[i].in[0] <== i;
        lt_i_lenY[i].in[1] <== lenYB64;

        // Use Multiplexer to select the correct byte
        selX[i] = Multiplexer(1, MAX_PAYLOAD);
        selY[i] = Multiplexer(1, MAX_PAYLOAD);
        
        // Connect the payload array
        for (var j = 0; j < MAX_PAYLOAD; j++) {
            selX[i].inp[j][0] <== payloadB64[j];
            selY[i].inp[j][0] <== payloadB64[j];
        }
        
        // Set the selector (offset + i) with bounds checking
        selX_idx[i] <== offXB64 + i;
        selY_idx[i] <== offYB64 + i;
        
        // Ensure selector is within bounds
        selX_check[i] = LessThan(16);
        selX_check[i].in[0] <== selX_idx[i];
        selX_check[i].in[1] <== MAX_PAYLOAD;
        selY_check[i] = LessThan(16);
        selY_check[i].in[0] <== selY_idx[i];
        selY_check[i].in[1] <== MAX_PAYLOAD;
        
        selX[i].sel <== selX_idx[i];
        selY[i].sel <== selY_idx[i];
        
        // Always capture selected byte
        x_selected[i] <== selX[i].out[0];
        y_selected[i] <== selY[i].out[0];

        // Gate with a 2:1 multiplexer (sel = lt_i_len?.out): 0 vs selected
        gateX[i] = Multiplexer(1, 2);
        gateY[i] = Multiplexer(1, 2);
        gateX[i].sel <== lt_i_lenX[i].out;
        gateY[i].sel <== lt_i_lenY[i].out;
        gateX[i].inp[0][0] <== 61;           // equal sign padding when out of bounds
        gateX[i].inp[1][0] <== x_selected[i];
        gateY[i].inp[0][0] <== 61;           // equal sign padding when out of bounds
        gateY[i].inp[1][0] <== y_selected[i];
        x_outer[i] <== gateX[i].out[0];
        y_outer[i] <== gateY[i].out[0];
    }

    // Step C. Inner length flags 43 or 44
    component isX43 = IsEqual();
    isX43.in[0] <== lenXInner;
    isX43.in[1] <== 43;
    component isX44 = IsEqual();
    isX44.in[0] <== lenXInner;
    isX44.in[1] <== 44;
    component isY43 = IsEqual();
    isY43.in[0] <== lenYInner;
    isY43.in[1] <== 43;
    component isY44 = IsEqual();
    isY44.in[0] <== lenYInner;
    isY44.in[1] <== 44;
    // Sanity check
    component oneX = IsEqual();
    oneX.in[0] <== isX43.out + isX44.out;
    oneX.in[1] <== 1;
    component oneY = IsEqual();
    oneY.in[0] <== isY43.out + isY44.out;
    oneY.in[1] <== 1;

    // Step D. Decode aligned outer slice to JSON ASCII
    component decOutX = Base64Decode(48);
    component decOutY = Base64Decode(48);
    for (var i = 0; i < 64; i++) {
        decOutX.in[i] <== x_outer[i];
        decOutY.in[i] <== y_outer[i];
    }

    // Step E. Build inner ASCII of length 43 or 44 from decoded outer using drop and length
    signal x_inner[44];
    signal y_inner[44];
    signal xi_pad[44];
    signal yi_pad[44];
    component lt_i_lenXInner[44];
    component lt_i_lenYInner[44];
    component eq_i_lenXInner[44];
    component eq_i_lenYInner[44];
    component selXInner[44];
    component selYInner[44];
    signal selXInner_idx[44];
    signal selYInner_idx[44];

    for (var i = 0; i < 44; i++) {
        selXInner[i] = Multiplexer(1, 48);
        selYInner[i] = Multiplexer(1, 48);
        for (var j = 0; j < 48; j++) {
            selXInner[i].inp[j][0] <== decOutX.out[j];
            selYInner[i].inp[j][0] <== decOutY.out[j];
        }
        selXInner_idx[i] <== dropX + i;
        selYInner_idx[i] <== dropY + i;
        selXInner[i].sel <== selXInner_idx[i];
        selYInner[i].sel <== selYInner_idx[i];

        lt_i_lenXInner[i] = LessThan(8);
        lt_i_lenXInner[i].in[0] <== i;
        lt_i_lenXInner[i].in[1] <== lenXInner;
        lt_i_lenYInner[i] = LessThan(8);
        lt_i_lenYInner[i].in[0] <== i;
        lt_i_lenYInner[i].in[1] <== lenYInner;

        eq_i_lenXInner[i] = IsEqual();
        eq_i_lenXInner[i].in[0] <== i;
        eq_i_lenXInner[i].in[1] <== lenXInner;
        eq_i_lenYInner[i] = IsEqual();
        eq_i_lenYInner[i].in[0] <== i;
        eq_i_lenYInner[i].in[1] <== lenYInner;

        xi_pad[i] <== isX43.out * eq_i_lenXInner[i].out * 61;
        yi_pad[i] <== isY43.out * eq_i_lenYInner[i].out * 61;

        x_inner[i] <== lt_i_lenXInner[i].out * selXInner[i].out[0] + xi_pad[i];
        y_inner[i] <== lt_i_lenYInner[i].out * selYInner[i].out[0] + yi_pad[i];
    }

    // Step F. Convert inner ASCII of length 43 or 44 to bytes and normalize to 32
    // X: 43→32  |  44→33 (possibly leading 0x00)
    component decInX32 = Base64Decode(32);
    component decInX33 = Base64Decode(33);
    // Both templates expect 44 input characters. x_inner is already length 44 after padding with the equal sign when required
    for (var i = 0; i < 44; i++) {
        decInX32.in[i] <== x_inner[i];
        decInX33.in[i] <== x_inner[i];
    }

    // Y analog
    component decInY32 = Base64Decode(32);
    component decInY33 = Base64Decode(33);
    for (var i = 0; i < 44; i++) {
        decInY32.in[i] <== y_inner[i];
        decInY33.in[i] <== y_inner[i];
    }

    // Select a 32 byte result. In the 44 case which yields 33 bytes we drop byte 0
    signal x_bytes[32];
    signal y_bytes[32];
    signal x58_bytes[32];
    signal x59_bytes[32];
    signal y58_bytes[32];
    signal y59_bytes[32];
    
    for (var i = 0; i < 32; i++) {
        x58_bytes[i] <== isX43.out * decInX32.out[i];
        x59_bytes[i] <== isX44.out * decInX33.out[i+1];
        x_bytes[i] <== x58_bytes[i] + x59_bytes[i];
        
        y58_bytes[i] <== isY43.out * decInY32.out[i];
        y59_bytes[i] <== isY44.out * decInY33.out[i+1];
        y_bytes[i] <== y58_bytes[i] + y59_bytes[i];
    }

    // Step G. Convert bytes to bits
    component xBits[32];
    component yBits[32];
    signal x_bits[256];
    signal y_bits[256];
    // First instantiate and feed all byte to bits components
    for (var i = 0; i < 32; i++) {
        xBits[i] = Num2Bits(8);
        xBits[i].in <== x_bytes[i];
        yBits[i] = Num2Bits(8);
        yBits[i].in <== y_bytes[i];
    }
    // Then assign bit arrays with reversed byte order so that bits are global LSB first
    for (var i = 0; i < 32; i++) {
        for (var j = 0; j < 8; j++) {
            x_bits[i*8 + j] <== xBits[31 - i].out[j];
            y_bits[i*8 + j] <== yBits[31 - i].out[j];
        }
    }

    // Step H. Build 6 limbs of 43 bits from 256 bit vectors using LSB first
    component xLimb[6];
    component yLimb[6];
    signal x_limbs[6];
    signal y_limbs[6];
    for (var i = 0; i < 6; i++) {
        xLimb[i] = Bits2Num(43);
        yLimb[i] = Bits2Num(43);
        for (var j = 0; j < 43; j++) {
            var bitPos = i*43 + j;
            if (bitPos < 256) {
                xLimb[i].in[j] <== x_bits[bitPos];
                yLimb[i].in[j] <== y_bits[bitPos];
            } else {
                xLimb[i].in[j] <== 0;
                yLimb[i].in[j] <== 0;
            }
        }
        x_limbs[i] <== xLimb[i].out;
        y_limbs[i] <== yLimb[i].out;
    }

    // Step I. Compare against pk_c and assert all equal
    component eqX[6];
    component eqY[6];
    signal eq_all[12];
    for (var i = 0; i < 6; i++) {
        eqX[i] = IsEqual();
        eqX[i].in[0] <== x_limbs[i];
        eqX[i].in[1] <== pk_c[0][i];
        eq_all[i] <== eqX[i].out;
        eqY[i] = IsEqual();
        eqY[i].in[0] <== y_limbs[i];
        eqY[i].in[1] <== pk_c[1][i];
        eq_all[6+i] <== eqY[i].out;
    }
    // Chain all equality checks (each multiplication remains quadratic)
    signal prod[13];
    prod[0] <== 1;
    for (var i = 0; i < 12; i++) {
        prod[i+1] <== prod[i] * eq_all[i];
    }
    
    // Enforce all equalities by asserting that the product equals one
    prod[12] === 1;
    
}
