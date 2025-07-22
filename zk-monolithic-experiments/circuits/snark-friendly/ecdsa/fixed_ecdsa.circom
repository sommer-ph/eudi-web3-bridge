pragma circom 2.1.0;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

// FIXED BN254 Curve parameters
function BN254_getGx() { return 1; }
function BN254_getGy() { return 2; }
function BN254_getN()  { 
    return 21888242871839275222246405745257275088548364400416034343698204186575808495617; 
}

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

// FIXED ScalarMul template that handles k=0 correctly
template ScalarMul(bits) {
    assert(bits > 0); 
    assert(bits <= 254);

    signal input Px; 
    signal input Py; 
    signal input k;
    signal output Rx; 
    signal output Ry;

    // Check if k is zero
    component kIsZero = IsZero();
    kIsZero.in <== k;
    
    // If k=0, return point at infinity representation (0,0)
    // Otherwise do normal scalar multiplication
    
    component kBits = Num2Bits(bits); 
    kBits.in <== k;

    component dbl[bits-1]; 
    component add[bits-1];
    signal x[bits]; 
    signal y[bits];
    
    // Start with the base point
    x[0] <== Px; 
    y[0] <== Py;

    signal b[bits-1];  
    signal ib[bits-1];
    signal t1x[bits-1], t2x[bits-1], selx[bits-1];
    signal t1y[bits-1], t2y[bits-1], sely[bits-1];

    for (var i = 0; i < bits-1; i++) { 
        dbl[i] = PointDouble(); 
        add[i] = PointAdd(); 
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

    // Handle k=0 case: if k=0, output (0,0), otherwise output computed result
    signal notZero;
    notZero <== 1 - kIsZero.out;
    
    Rx <== notZero * x[bits-1];
    Ry <== notZero * y[bits-1];
}

template PointOnCurve() {
    signal input x; 
    signal input y; 

    // Direct constraint: y² = x³ + 3 (uses Circom's field automatically)
    signal x_sq; 
    x_sq <== x * x;
    signal x_cu; 
    x_cu <== x_sq * x;
    signal rhs;  
    rhs  <== x_cu + 3;
    signal lhs;  
    lhs  <== y * y;

    // Direct equality constraint
    lhs === rhs;
}

template FixedECDSAVerify(bits) {
    assert(bits == 254);

    signal input z;     // Message hash
    signal input Qx;    // pk.X
    signal input Qy;    // pk.Y
    signal input r;     // Signature r
    signal input s;     // Signature s
    signal input w;     // s⁻¹ mod n
    signal input q1;    // Quotient q1 
    signal input q2;    // Quotient q2
    signal input q3;    // Quotient q3

    // Curve order (BN254 scalar field)
    var n = BN254_getN();

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

    // u1 * G (using fixed scalar mul)
    var Gx = BN254_getGx(); 
    var Gy = BN254_getGy();
    component P1 = ScalarMul(bits); 
    P1.Px <== Gx; 
    P1.Py <== Gy; 
    P1.k <== k1;

    // u2 * Q (using fixed scalar mul)
    component P2 = ScalarMul(bits); 
    P2.Px <== Qx; 
    P2.Py <== Qy; 
    P2.k <== k2;

    // Simplified: just do standard point addition (assume no point at infinity for now)
    component sum = PointAdd();
    sum.x1 <== P1.Rx; 
    sum.y1 <== P1.Ry;
    sum.x2 <== P2.Rx; 
    sum.y2 <== P2.Ry;
    
    signal resultX, resultY;
    resultX <== sum.x3;
    resultY <== sum.y3;

    // Check if r = R.x mod n
    signal q3n;
    q3n  <== q3 * n;
    signal rx_mod;
    rx_mod <== resultX - q3n;
    rx_mod === r;
}

template FixedVerifyEcdsaSignature(bits) {
    signal input z;
    signal input Qx;
    signal input Qy;
    signal input r;
    signal input s;
    signal input w;
    signal input q1;
    signal input q2;
    signal input q3;
        
    component verify = FixedECDSAVerify(bits);
    verify.z <== z;
    verify.Qx <== Qx;
    verify.Qy <== Qy;
    verify.r <== r;
    verify.s <== s;
    verify.w <== w;
    verify.q1 <== q1;
    verify.q2 <== q2;
    verify.q3 <== q3;
}

component main = FixedVerifyEcdsaSignature(254);