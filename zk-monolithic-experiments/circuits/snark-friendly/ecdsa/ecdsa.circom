pragma circom 2.1.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/*
 * ECDSA Verification Circuit for BN254 Curve
 *
 * This circuit implements ECDSA signature verification on the BN254 elliptic curve.
 * Key components:
 * - Point arithmetic templates (PointAdd, PointDouble, ScalarMul)
 * - Curve validation (PointOnCurve)
 * - ECDSA verification with precomputed quotients for efficiency
 *
 * Note: Uses quotients (q1, q2, q3) as inputs to handle modular arithmetic
 * efficiently in the zk-SNARK constraint system.
 */

function TestCurve_getGx() { return 1; }
function TestCurve_getGy() { return 2; }
function TestCurve_getN()  { 
    return 21888242871839275222246405745257275088548364400416034343698204186575808495617; 
}
function TestCurve_getP()  {
    return 21888242871839275222246405745257275088696311157297823662689037894645226208583;
}

/*
 * Elliptic curve point addition
 * Implements the standard EC point addition formula for distinct points
 * Fails if points are identical (use PointDouble) or if denominator is zero
 */
template PointAdd() {
    signal input x1; 
    signal input y1;
    signal input x2; 
    signal input y2;
    signal output x3; 
    signal output y3;

    signal num;  
    num <== y2 - y1;
    signal den;  
    den <== x2 - x1;
    component denNZ = IsZero(); 
    denNZ.in <== den; 
    denNZ.out === 0;

    signal lambda; 
    lambda <-- num / den;
    lambda * den === num;

    signal lambda_sq; 
    lambda_sq <== lambda * lambda;
    signal tmp_x;     
    tmp_x <== lambda_sq - x1;
    x3 <== tmp_x - x2;

    signal dx;       
    dx <== x1 - x3;
    signal lambda_dx;
    lambda_dx <== lambda * dx;
    y3 <== lambda_dx - y1;
}

/*
 * Elliptic curve point doubling
 * Implements point doubling for P + P using tangent line method
 * Used when adding a point to itself
 */
template PointDouble() {
    signal input x; 
    signal input y;
    signal output x3; 
    signal output y3;

    signal x_sq; 
    x_sq <== x * x;
    signal num;  
    num  <== 3 * x_sq;

    signal den;  
    den  <== 2 * y;
    component denNZ = IsZero(); 
    denNZ.in <== den; 
    denNZ.out === 0;

    signal lambda; 
    lambda <-- num / den;
    lambda * den === num;

    signal lambda_sq; 
    lambda_sq <== lambda * lambda;
    signal tmp_x;     
    tmp_x <== lambda_sq - x;
    x3 <== tmp_x - x;

    signal dx;      
    dx <== x - x3;
    signal lambda_dx;
    lambda_dx <== lambda * dx;
    y3 <== lambda_dx - y;
}

/*
 * Scalar multiplication using double-and-add algorithm
 * Computes k * P efficiently by processing k bit by bit
 * Uses conditional selection to avoid branching in the circuit
 */
template ScalarMul(bits) {
    assert(bits > 0); 
    assert(bits <= 254);

    signal input Px; 
    signal input Py; 
    signal input k;
    signal output Rx; 
    signal output Ry;

    component kBits = Num2Bits(bits); 
    kBits.in <== k;

    component dbl[bits-1]; 
    component add[bits-1];
    signal x[bits]; 
    signal y[bits];
    x[0] <== Px; 
    y[0] <== Py;

    signal b[bits-1];  
    signal ib[bits-1];
    signal t1x[bits-1], t2x[bits-1], selx[bits-1];
    signal t1y[bits-1], t2y[bits-1], sely[bits-1];

    for (var i = 0; i < bits-1; i++) { 
        dbl[i] = PointDouble(); add[i] = PointAdd(); 
    }

    for (var i = 0; i < bits-1; i++) {
        var idx = bits - 2 - i;

        dbl[i].x <== x[i]; 
        dbl[i].y <== y[i];

        add[i].x1 <== dbl[i].x3; 
        add[i].y1 <== dbl[i].y3;
        add[i].x2 <== Px;        
        add[i].y2 <== Py;

        b[i]  <== kBits.out[idx];
        ib[i] <== 1 - b[i];

        t1x[i] <== b[i]  * add[i].x3;
        t2x[i] <== ib[i] * dbl[i].x3;
        selx[i] <== t1x[i] + t2x[i];

        t1y[i] <== b[i]  * add[i].y3;
        t2y[i] <== ib[i] * dbl[i].y3;
        sely[i] <== t1y[i] + t2y[i];

        x[i+1] <== selx[i];
        y[i+1] <== sely[i];
    }

    Rx <== x[bits-1];
    Ry <== y[bits-1];
}

/*
 * Validates that a point lies on the BN254 curve
 * Checks the curve equation y² = x³ + 3
 * Critical for ensuring input points are valid
 */
template PointOnCurve() {
    signal input x; 
    signal input y; 

    signal x_sq; 
    x_sq <== x * x;
    signal x_cu; 
    x_cu <== x_sq * x;
    signal rhs;  
    rhs  <== x_cu + 3;
    signal lhs;  
    lhs  <== y * y;

    lhs === rhs;
}

/*
 * ECDSA signature verification template
 * 
 * Verifies an ECDSA signature using precomputed quotients for efficiency.
 * This is NOT standard ECDSA as quotients are provided as inputs rather
 * than computed internally, which is necessary for zk-SNARK optimization.
 *
 * WARNING: Providing quotients as inputs means this circuit cannot enforce
 * the full security properties of ECDSA verification.
 */
template ECDSAVerify(bits) {
    assert(bits == 254);

    signal input z;     // Message hash
    signal input Qx;    // pk.X
    signal input Qy;    // pk.Y
    signal input r;     // Signature r
    signal input s;     // Signature s
    signal input w;     // s⁻¹ mod n provided as input --> ECDSA-violation!
    signal input q1;    // Quotient q1 = floor((z * w) / n) provided as input --> ECDSA-violation!
    signal input q2;    // Quotient q2 = floor((r * w) / n) provided as input --> ECDSA-violation!
    signal input q3;    // provided as input --> ECDSA-violation!

    signal output valid;

    // Curve order (BN254)
    var n = TestCurve_getN();

    // Range checks
    component rBits = Num2Bits(bits); 
    rBits.in <== r;
    component sBits = Num2Bits(bits); 
    sBits.in <== s;

    // Point on curve check
    component pkChk = PointOnCurve(); 
    pkChk.x <== Qx; 
    pkChk.y <== Qy;

    // u1 = z * w mod n
    signal zw; 
    zw <== z * w;
    signal q1n; 
    q1n <== q1 * n;
    signal k1; 
    k1 <== zw - q1n;
    
    component k1Bits = Num2Bits(bits); 
    k1Bits.in <== k1;

    // u2 = r * w mod n
    signal rw; 
    rw <== r * w;
    signal q2n; 
    q2n <== q2 * n;
    signal k2; 
    k2 <== rw - q2n;

    component k2Bits = Num2Bits(bits); 
    k2Bits.in <== k2;

    // u1 * G
    var Gx = TestCurve_getGx(); 
    var Gy = TestCurve_getGy();
    component P1 = ScalarMul(bits); 
    P1.Px <== Gx; 
    P1.Py <== Gy; 
    P1.k <== k1;

    // u2 * Q
    component P2 = ScalarMul(bits); 
    P2.Px <== Qx; 
    P2.Py <== Qy; 
    P2.k <== k2;

    // R = P1 + P2
    component sum = PointAdd();
    sum.x1 <== P1.Rx; 
    sum.y1 <== P1.Ry;
    sum.x2 <== P2.Rx; 
    sum.y2 <== P2.Ry;

    // Check if r = R.x mod n
    signal q3n;
    q3n  <== q3 * n;
    signal rx_mod;
    rx_mod <== sum.x3 - q3n;
    //rx_mod === r;
    component isEqual = IsEqual();
    isEqual.in[0] <== rx_mod;
    isEqual.in[1] <== r;
    valid <== isEqual.out;
}
