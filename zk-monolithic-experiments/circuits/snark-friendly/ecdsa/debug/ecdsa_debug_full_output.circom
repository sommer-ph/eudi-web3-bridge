pragma circom 2.1.0;

include "ecdsa.circom";

template CompleteECDSADebug() {
    signal input z, Qx, Qy, r, s, w, q1, q2, q3;
    
    // Output ALL intermediate computations
    signal output u1_computed;     // k1 = z*w - q1*n  
    signal output u2_computed;     // k2 = r*w - q2*n
    signal output P1_x, P1_y;      // u1 * G
    signal output P2_x, P2_y;      // u2 * Q  
    signal output R_x, R_y;        // P1 + P2
    signal output rx_final;        // R.x - q3*n
    signal output r_expected;      // input r
    signal output verification;    // rx_final == r
    
    var n = TestCurve_getN();
    var Gx = TestCurve_getGx();
    var Gy = TestCurve_getGy();
    
    // STEP 1: Calculate u1 = z * w mod n
    signal zw;
    zw <== z * w;
    signal q1n;
    q1n <== q1 * n;
    signal k1;
    k1 <== zw - q1n;
    u1_computed <== k1;
    
    // STEP 2: Calculate u2 = r * w mod n  
    signal rw;
    rw <== r * w;
    signal q2n;
    q2n <== q2 * n;
    signal k2;
    k2 <== rw - q2n;
    u2_computed <== k2;
    
    // STEP 3: P1 = u1 * G
    component P1 = ScalarMul(254);
    P1.Px <== Gx;
    P1.Py <== Gy;
    P1.k <== k1;
    P1_x <== P1.Rx;
    P1_y <== P1.Ry;
    
    // STEP 4: P2 = u2 * Q
    component P2 = ScalarMul(254);
    P2.Px <== Qx;
    P2.Py <== Qy;
    P2.k <== k2;
    P2_x <== P2.Rx;
    P2_y <== P2.Ry;
    
    // STEP 5: R = P1 + P2
    component sum = PointAdd();
    sum.x1 <== P1.Rx;
    sum.y1 <== P1.Ry;
    sum.x2 <== P2.Rx;
    sum.y2 <== P2.Ry;
    R_x <== sum.x3;
    R_y <== sum.y3;
    
    // STEP 6: Final verification
    signal q3n;
    q3n <== q3 * n;
    signal rx_mod;
    rx_mod <== sum.x3 - q3n;
    rx_final <== rx_mod;
    r_expected <== r;
    
    // STEP 7: Check equality
    component eq = IsEqual();
    eq.in[0] <== rx_mod;
    eq.in[1] <== r;
    verification <== eq.out;
}

component main = CompleteECDSADebug();