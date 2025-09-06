pragma circom 2.2.0;

include "circomlib/circuits/sha256/sha256.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/multiplexer.circom";

include "../utils/base64-decoder.circom";

template JWSMonolithic() {
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
    signal input offXB64;
    signal input lenXB64;
    signal input offYB64;
    signal input lenYB64;
    signal input msghash[6];
    signal input pk_c[2][6];
    
    // Outputs
    signal output pk_c_extracted_equals_pk_c;
    
    // Declare components
    component headerCheck[MAX_HEADER];
    component payloadCheck[MAX_PAYLOAD];
    component limb2num[6];
    component hashEq[6];
    
    // === PART 1: MSG = SHA-256(HEADER.PAYLOAD) ===
    
    // Step 1: Create concatenated array header.payload
    signal combined[MAX_TOTAL];
    
    // Copy header (with length check)
    for (var i = 0; i < MAX_HEADER; i++) {
        headerCheck[i] = LessThan(8);
        headerCheck[i].in[0] <== i;
        headerCheck[i].in[1] <== headerB64Length;
        
        combined[i] <== headerCheck[i].out * headerB64[i];
    }
    
    // Add dot separator (ASCII 46)
    combined[MAX_HEADER] <== 46;
    
    // Copy payload (with length check)
    for (var i = 0; i < MAX_PAYLOAD; i++) {
        payloadCheck[i] = LessThan(10);
        payloadCheck[i].in[0] <== i;
        payloadCheck[i].in[1] <== payloadB64Length;
        
        combined[MAX_HEADER + 1 + i] <== payloadCheck[i].out * payloadB64[i];
    }
    
    // Step 2: Compute SHA-256
    component sha = Sha256(MAX_TOTAL * 8);
    component byte2bits[MAX_TOTAL];
    
    for (var i = 0; i < MAX_TOTAL; i++) {
        byte2bits[i] = Num2Bits(8);
        byte2bits[i].in <== combined[i];
        for (var j = 0; j < 8; j++) {
            sha.in[i * 8 + j] <== byte2bits[i].out[j];
        }
    }
    
    // Step 3: Convert SHA-256 result to 43-bit limbs (little-endian)
    signal computedHash[6];
    
    for (var i = 0; i < 6; i++) {
        limb2num[i] = Bits2Num(43);
        for (var j = 0; j < 43; j++) {
            var bitPos = i * 43 + j;
            if (bitPos < 256) {
                limb2num[i].in[j] <== sha.out[bitPos];
            } else {
                limb2num[i].in[j] <== 0;
            }
        }
        computedHash[i] <== limb2num[i].out;
    }
    
    /*
    // Step 4: Output computed hash for debugging (before comparison)
    signal output computed_hash_debug[6];
    for (var i = 0; i < 6; i++) {
        computed_hash_debug[i] <== computedHash[i];
    }
    */
    
    // Step 5: Compare with expected hash
    for (var i = 0; i < 6; i++) {
        computedHash[i] === msghash[i];
    }
    
// === PART 2: PK_C = PK_C_EXTRACTED ===
    
    // Declare components for Part 2
    var MAX_OUTER = 60;
    component lt_i_lenX[MAX_OUTER];
    component lt_i_lenY[MAX_OUTER];
    component lt_i_43_X[44];
    component lt_i_44_X[44];
    component lt_i_43_Y[44]; 
    component lt_i_44_Y[44];
    component is_i_43_X[44];
    component is_i_43_Y[44];
    
    // Declare signals for Part 2
    signal xi43[44];
    signal xi44[44];
    signal yi43[44];
    signal yi44[44];
    signal padX[44];
    signal padY[44];

    // ---- Bounds & coarse length checks (outer) ----
    component lt_offX   = LessThan(16);
    component lt_lenX   = LessThan(16);
    component lt_sumX   = LessThan(16);
    component lt_offY   = LessThan(16);
    component lt_lenY   = LessThan(16);
    component lt_sumY   = LessThan(16);

    lt_offX.in[0] <== offXB64;
    lt_offX.in[1] <== payloadB64Length;
    lt_lenX.in[0] <== lenXB64;
    lt_lenX.in[1] <== 60; // 58/59 expected for Base64url P-256 coordinates
    signal sumX <== offXB64 + lenXB64;
    lt_sumX.in[0] <== sumX;
    lt_sumX.in[1] <== payloadB64Length;

    lt_offY.in[0] <== offYB64;
    lt_offY.in[1] <== payloadB64Length;
    lt_lenY.in[0] <== lenYB64;
    lt_lenY.in[1] <== 60;
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

    // ---- Slice outer Base64url substrings (X/Y) ----
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

    for (var i = 0; i < MAX_OUTER; i++) {
        // Guards: i < len?
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
        
        // Apply length constraint
        // Ensure we always have a valid signal even when out of bounds
        x_selected[i] <== selX[i].out[0];
        y_selected[i] <== selY[i].out[0];
        x_outer[i] <== lt_i_lenX[i].out * x_selected[i];
        y_outer[i] <== lt_i_lenY[i].out * y_selected[i];
    }

    // ---- Map outer length 58/59 -> inner length 43/44 ----
    component isX58 = IsEqual();
    isX58.in[0] <== lenXB64;
    isX58.in[1] <== 58;
    component isX59 = IsEqual();
    isX59.in[0] <== lenXB64;
    isX59.in[1] <== 59;
    component isY58 = IsEqual();
    isY58.in[0] <== lenYB64;
    isY58.in[1] <== 58;
    component isY59 = IsEqual();
    isY59.in[0] <== lenYB64;
    isY59.in[1] <== 59;

    // Sanity check: each length must match exactly one of the two valid values
    component oneX = IsEqual();
    oneX.in[0] <== isX58.out + isX59.out;
    oneX.in[1] <== 1;
    component oneY = IsEqual();
    oneY.in[0] <== isY58.out + isY59.out;
    oneY.in[1] <== 1;

    // ---- Stage A: OUTER decode -> INNER ASCII (43/44 chars) ----
    // X
    component decOutX58 = Base64Decode(43);
    component decOutX59 = Base64Decode(44);
    for (var i = 0; i < 60; i++) {
        decOutX58.in[i] <== x_outer[i];
        decOutX59.in[i] <== x_outer[i];
    }

    // Y
    component decOutY58 = Base64Decode(43);
    component decOutY59 = Base64Decode(44);
    for (var i = 0; i < 60; i++) {
        decOutY58.in[i] <== y_outer[i];
        decOutY59.in[i] <== y_outer[i];
    }

    // Select inner ASCII strings (padded to 44 for Stage B)
    signal x_inner[44];
    signal y_inner[44];
    signal xi43_padded[44];
    signal x58_part[44];
    signal x59_part[44];
    signal yi43_padded[44];
    signal y58_part[44];
    signal y59_part[44];

    for (var i = 0; i < 44; i++) {
        // For X: when 58→43 valid (index <43), when 59→44 valid (index <44)
        lt_i_43_X[i] = LessThan(8);
        lt_i_43_X[i].in[0] <== i;
        lt_i_43_X[i].in[1] <== 43;
        lt_i_44_X[i] = LessThan(8);
        lt_i_44_X[i].in[0] <== i;
        lt_i_44_X[i].in[1] <== 44;

        // Only access decOutX58.out[i] when i < 43
        if (i < 43) {
            xi43[i] <== lt_i_43_X[i].out * decOutX58.out[i];
        } else {
            xi43[i] <== 0; // Out of bounds, set to 0
        }
        // Only access decOutX59.out[i] when i < 44  
        if (i < 44) {
            xi44[i] <== lt_i_44_X[i].out * decOutX59.out[i];
        } else {
            xi44[i] <== 0; // Out of bounds, set to 0
        }

        // Padding character 'A' (ASCII 65) when 43-case and i==43
        is_i_43_X[i] = IsEqual();
        is_i_43_X[i].in[0] <== i;
        is_i_43_X[i].in[1] <== 43;
        padX[i] <== isX58.out * is_i_43_X[i].out * 65;

        xi43_padded[i] <== xi43[i] + padX[i];
        x58_part[i] <== isX58.out * xi43_padded[i];
        x59_part[i] <== isX59.out * xi44[i];
        x_inner[i] <== x58_part[i] + x59_part[i];

        // Y analogous
        lt_i_43_Y[i] = LessThan(8);
        lt_i_43_Y[i].in[0] <== i;
        lt_i_43_Y[i].in[1] <== 43;
        lt_i_44_Y[i] = LessThan(8);
        lt_i_44_Y[i].in[0] <== i;
        lt_i_44_Y[i].in[1] <== 44;

        // Only access decOutY58.out[i] when i < 43
        if (i < 43) {
            yi43[i] <== lt_i_43_Y[i].out * decOutY58.out[i];
        } else {
            yi43[i] <== 0; // Out of bounds, set to 0
        }
        // Only access decOutY59.out[i] when i < 44
        if (i < 44) {
            yi44[i] <== lt_i_44_Y[i].out * decOutY59.out[i];
        } else {
            yi44[i] <== 0; // Out of bounds, set to 0
        }

        is_i_43_Y[i] = IsEqual();
        is_i_43_Y[i].in[0] <== i;
        is_i_43_Y[i].in[1] <== 43;
        padY[i] <== isY58.out * is_i_43_Y[i].out * 65;

        yi43_padded[i] <== yi43[i] + padY[i];
        y58_part[i] <== isY58.out * yi43_padded[i];
        y59_part[i] <== isY59.out * yi44[i];
        y_inner[i] <== y58_part[i] + y59_part[i];
    }

    // ---- Stage B: INNER ASCII (43/44) -> BYTES (32/33), then normalize to 32 ----
    // X: 43→32  |  44→33 (possibly leading 0x00)
    component decInX32 = Base64Decode(32);
    component decInX33 = Base64Decode(33);
    // Both templates expect 44 input chars – x_inner is already 44-length (padded with 'A')
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

    // Select 32-byte result; in 44-case (33 bytes) we drop byte 0
    signal x_bytes[32];
    signal y_bytes[32];
    signal x58_bytes[32];
    signal x59_bytes[32];
    signal y58_bytes[32];
    signal y59_bytes[32];
    
    for (var i = 0; i < 32; i++) {
        x58_bytes[i] <== isX58.out * decInX32.out[i];
        x59_bytes[i] <== isX59.out * decInX33.out[i+1];
        x_bytes[i] <== x58_bytes[i] + x59_bytes[i];
        
        y58_bytes[i] <== isY58.out * decInY32.out[i];
        y59_bytes[i] <== isY59.out * decInY33.out[i+1];
        y_bytes[i] <== y58_bytes[i] + y59_bytes[i];
    }

    // ---- Bytes -> Bits ----
    component xBits[32];
    component yBits[32];
    signal x_bits[256];
    signal y_bits[256];
    for (var i = 0; i < 32; i++) {
        xBits[i] = Num2Bits(8);
        xBits[i].in <== x_bytes[i];
        yBits[i] = Num2Bits(8);
        yBits[i].in <== y_bytes[i];
        for (var j = 0; j < 8; j++) {
            x_bits[i*8 + j] <== xBits[i].out[j];
            y_bits[i*8 + j] <== yBits[i].out[j];
        }
    }

    // ---- 256 Bits -> 6×43-Bit Limbs (LSB-first) ----
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

    // ---- Compare against pk_c ----
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
    // Chain all equality checks
    signal prod[13];
    prod[0] <== 1;
    for (var i = 0; i < 12; i++) {
        prod[i+1] <== prod[i] * eq_all[i];
    }
    pk_c_extracted_equals_pk_c <== prod[12];

}

component main = JWSMonolithic();