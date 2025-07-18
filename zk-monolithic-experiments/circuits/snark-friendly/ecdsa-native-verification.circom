pragma circom 2.2.0;

include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/escalarmulany.circom";

// Template for modular inverse witness
template ModInverse(n) {
    signal input in;
    signal input modulus;
    signal output out;
    signal quot;
    in * out - 1 === quot * modulus;
}

// Template for modular reduction
template ModReduce(n) {
    signal input in;
    signal input modulus;
    signal output out;
    
    // Witness the quotient and remainder
    signal quot <-- in / modulus;
    signal remainder <-- in % modulus;
    
    // Verify the relationship: in = quot * modulus + remainder
    in === quot * modulus + remainder;
    
    // Ensure remainder is in range [0, modulus)
    component lt = LessThan(252);
    lt.in[0] <== remainder;
    lt.in[1] <== modulus;
    lt.out === 1;
    
    // Ensure remainder is non-negative
    component geq = GreaterEqThan(252);
    geq.in[0] <== remainder;
    geq.in[1] <== 0;
    geq.out === 1;
    
    out <== remainder;
}

template ECDSANativeVerify() {
    // Inputs
    signal input message;
    signal input pubKeyX;
    signal input pubKeyY;
    signal input sigR;
    signal input sigS;

    signal output isValid;

    var ORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373040;

    // Enforce 0 < sigR < ORDER and 0 < sigS < ORDER
    component rRange = LessThan(252);
    rRange.in[0] <== sigR;
    rRange.in[1] <== ORDER;
    rRange.out === 1;

    component sRange = LessThan(252);
    sRange.in[0] <== sigS;
    sRange.in[1] <== ORDER;
    sRange.out === 1;

    component rNonZero = IsZero();
    rNonZero.in <== sigR;
    rNonZero.out === 0;

    component sNonZero = IsZero();
    sNonZero.in <== sigS;
    sNonZero.out === 0;

    // Calculate modular inverse of sigS
    component sInvCalc = ModInverse(252);
    sInvCalc.in <== sigS;
    sInvCalc.modulus <== ORDER;
    
    // Calculate u1 = message * sInv mod ORDER
    component u1Calc = ModReduce(252);
    u1Calc.in <== message * sInvCalc.out;
    u1Calc.modulus <== ORDER;

    // Calculate u2 = sigR * sInv mod ORDER  
    component u2Calc = ModReduce(252);
    u2Calc.in <== sigR * sInvCalc.out;
    u2Calc.modulus <== ORDER;

    // Compute point1 = u1 * Generator
    component mulBase = BabyPbk();
    mulBase.in <== u1Calc.out;

    // Compute point2 = u2 * pubKey
    component u2bits = Num2Bits(252);
    u2bits.in <== u2Calc.out;
    component mulPub = EscalarMulAny(252);
    for (var i = 0; i < 252; i++) {
        mulPub.e[i] <== u2bits.out[i];
    }
    mulPub.p[0] <== pubKeyX;
    mulPub.p[1] <== pubKeyY;

    // Add the two points
    component adder = BabyAdd();
    adder.x1 <== mulBase.Ax;
    adder.y1 <== mulBase.Ay;
    adder.x2 <== mulPub.out[0];
    adder.y2 <== mulPub.out[1];

    // Reduce result x-coordinate modulo ORDER
    component rCalc = ModReduce(252);
    rCalc.in <== adder.xout;
    rCalc.modulus <== ORDER;

    // Verify that calculated r matches signature r
    rCalc.out === sigR;

    isValid <== 1;
}

component main = ECDSANativeVerify();