pragma circom 2.2.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

// Maps a single URL-safe Base64 character (ASCII) -> 6-bit value (0..63).
// '=' (ASCII 61) is mapped to 0 as padding.
// Additionally: Validation constraint that the character falls into exactly ONE class.
template Base64Lookup() {
    signal input in;    // ASCII Code (0..255, practically 45,48-57,65-90,95,97-122,61)
    signal output out;  // 6-bit value (0..63), '=' -> 0

    // Character classes:
    // ['A','Z'] -> 0..25
    component le_Z = LessThan(8); 
    le_Z.in[0] <== in; 
    le_Z.in[1] <== 90+1;

    component ge_A = GreaterThan(8); 
    ge_A.in[0] <== in; 
    ge_A.in[1] <== 65-1;

    signal range_AZ <== ge_A.out * le_Z.out;
    signal val_AZ   <== range_AZ * (in - 65);  // 0..25

    // ['a','z'] -> 26..51
    component le_z = LessThan(8); 
    le_z.in[0] <== in; 
    le_z.in[1] <== 122+1;

    component ge_a = GreaterThan(8); 
    ge_a.in[0] <== in; 
    ge_a.in[1] <== 97-1;

    signal range_az <== ge_a.out * le_z.out;
    signal val_az   <== range_AZ + range_az * (in - 71); // 26 + (in-97)

    // ['0','9'] -> 52..61
    component le_9 = LessThan(8); 
    le_9.in[0] <== in; 
    le_9.in[1] <== 57+1;

    component ge_0 = GreaterThan(8); 
    ge_0.in[0] <== in; 
    ge_0.in[1] <== 48-1;

    signal range_09 <== ge_0.out * le_9.out;
    signal val_09   <== val_az + range_09 * (in + 4);    // 52 + (in-48)

    // '-' (ASCII 45) -> 62
    component is_dash = IsZero(); 
    is_dash.in <== in - 45;
    signal val_dash <== val_09 + is_dash.out * 62;

    // '_' (ASCII 95) -> 63
    component is_us = IsZero(); 
    is_us.in <== in - 95;
    signal val_us <== val_dash + is_us.out * 63;

    // '=' (ASCII 61) -> Padding -> 0
    component is_eq = IsZero(); 
    is_eq.in <== in - 61;
    signal val_eq <== val_us + is_eq.out * 0;

    // Output
    out <== val_eq;

    // --- Validation constraint: EXACTLY one class must match ---
    signal clsSum <== range_AZ + range_az + range_09 + is_dash.out + is_us.out + is_eq.out;
    component clsOk = IsEqual();
    clsOk.in[0] <== clsSum;
    clsOk.in[1] <== 1;

    // --- Range constraint to 6 bits (optional, but clean) ---
    // Decompose out into 6 bits to enforce out ∈ [0..63].
    component o6 = Num2Bits(6);
    o6.in <== out;
}

// Decodes N bytes from URL-safe Base64.
// Expects M = 4 * ((N+2) \ 3) characters (including '=' padding).
// Repacking per 4-character group: 4×6 bit -> 3×8 bit.
template Base64Decode(N) {
    var M = 4 * ((N + 2) \ 3);

    signal input in[M];   // ASCII Base64url chars (A-Z,a-z,0-9,'-','_','=')
    signal output out[N]; // N decoded bytes

    component bits_in[M\4][4];   // 4 sextets per block
    component bits_out[M\4][3];  // 3 bytes per block
    component translate[M\4][4]; // 4× lookup per block

    var idx = 0;
    for (var i = 0; i < M; i += 4) {
        // Outputs (3 bytes)
        for (var j = 0; j < 3; j++) {
            bits_out[i\4][j] = Bits2Num(8);
        }

        // Inputs (4 sextets, each 6 bits)
        for (var j = 0; j < 4; j++) {
            bits_in[i\4][j] = Num2Bits(6);
            translate[i\4][j] = Base64Lookup();
            translate[i\4][j].in  <== in[i + j];
            // Map value (0..63) is decomposed into 6 bits for range validation
            translate[i\4][j].out ==> bits_in[i\4][j].in;
        }

        // Repacking 4×6 Bit -> 3×8 Bit
        // Byte 0: [ sextet0 bits 5..0 -> pos 7..2 ] + [ sextet1 bits 5..4 -> pos 1..0 ]
        for (var b = 0; b < 6; b++) {
            bits_out[i\4][0].in[b + 2] <== bits_in[i\4][0].out[b];
        }
        bits_out[i\4][0].in[0] <== bits_in[i\4][1].out[4];
        bits_out[i\4][0].in[1] <== bits_in[i\4][1].out[5];

        // Byte 1: [ sextet1 bits 3..0 -> pos 7..4 ] + [ sextet2 bits 5..2 -> pos 3..0 ]
        for (var b1 = 0; b1 < 4; b1++) {
            bits_out[i\4][1].in[b1 + 4] <== bits_in[i\4][1].out[b1];
        }
        for (var b2 = 0; b2 < 4; b2++) {
            bits_out[i\4][1].in[b2] <== bits_in[i\4][2].out[b2 + 2];
        }

        // Byte 2: [ sextet2 bits 1..0 -> pos 7..6 ] + [ sextet3 bits 5..0 -> pos 5..0 ]
        bits_out[i\4][2].in[7] <== bits_in[i\4][2].out[1];
        bits_out[i\4][2].in[6] <== bits_in[i\4][2].out[0];
        for (var b3 = 0; b3 < 6; b3++) {
            bits_out[i\4][2].in[b3] <== bits_in[i\4][3].out[b3];
        }

        // Output 3 bytes as long as we don't exceed the N limit
        for (var j = 0; j < 3; j++) {
            if (idx + j < N) {
                out[idx + j] <== bits_out[i\4][j].out;
            }
        }
        idx += 3;
    }
}
