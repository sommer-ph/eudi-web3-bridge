pragma circom 2.2.0;

include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

// ECDSA verification over the BabyJubJub curve using only native field operations.
// The curve order is fixed as constant ORDER.

template ECDSANativeVerify() {
    // Inputs
    signal input message;        // Message hashed to a field element
    signal input pubKeyX;
    signal input pubKeyY;
    signal input sigR;
    signal input sigS;

    signal output isValid;

    var ORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373040;

    // Enforce 0 < sigR < ORDER and 0 < sigS < ORDER
    component rlt = LessThan(253);
    rlt.in[0] <== sigR;
    rlt.in[1] <== ORDER;
    rlt.out === 1;

    component slt = LessThan(253);
    slt.in[0] <== sigS;
    slt.in[1] <== ORDER;
    slt.out === 1;

    component rzero = IsZero();
    rzero.in <== sigR;
    rzero.out === 0;

    component szero = IsZero();
    szero.in <== sigS;
    szero.out === 0;

    // Witness for inverse of sigS modulo ORDER
    signal sInv;
    signal sInvQuot;
    sigS * sInv - 1 === sInvQuot * ORDER;

    // Compute u1 = message * sInv mod ORDER
    signal u1;
    signal u1Quot;
    message * sInv - u1 === u1Quot * ORDER;

    component u1lt = LessThan(253);
    u1lt.in[0] <== u1;
    u1lt.in[1] <== ORDER;
    u1lt.out === 1;

    // Compute u2 = sigR * sInv mod ORDER
    signal u2;
    signal u2Quot;
    sigR * sInv - u2 === u2Quot * ORDER;

    component u2lt = LessThan(253);
    u2lt.in[0] <== u2;
    u2lt.in[1] <== ORDER;
    u2lt.out === 1;

    // Compute point1 = u1 * Generator (BabyJub subgroup generator)
    component mulBase = BabyPbk();
    mulBase.in <== u1;
    signal p1x = mulBase.Ax;
    signal p1y = mulBase.Ay;

    // Compute point2 = u2 * pubKey
    component u2bits = Num2Bits(253);
    u2bits.in <== u2;
    component mulPub = EscalarMulAny(253);
    for (var i = 0; i < 253; i++) {
        mulPub.e[i] <== u2bits.out[i];
    }
    mulPub.p[0] <== pubKeyX;
    mulPub.p[1] <== pubKeyY;

    // Add the two points
    component adder = BabyAdd();
    adder.x1 <== p1x;
    adder.y1 <== p1y;
    adder.x2 <== mulPub.out[0];
    adder.y2 <== mulPub.out[1];

    signal Rx = adder.xout;
    signal Ry = adder.yout;

    // Reduce Rx modulo ORDER and compare with sigR
    signal rCalc;
    signal rCalcQuot;
    Rx - rCalc === rCalcQuot * ORDER;

    component rcallt = LessThan(253);
    rcallt.in[0] <== rCalc;
    rcallt.in[1] <== ORDER;
    rcallt.out === 1;

    rCalc === sigR;

    isValid <== 1;
}

component main = ECDSANativeVerify();
