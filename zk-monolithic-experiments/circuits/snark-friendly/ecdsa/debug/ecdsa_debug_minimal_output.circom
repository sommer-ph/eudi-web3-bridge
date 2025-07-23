pragma circom 2.1.0;

include "ecdsa.circom";

template DebugFinalECDSA() {
    signal input z, Qx, Qy, r, s, w, q1, q2, q3;
    signal output rx_computed, r_expected, q3_used, are_equal;
    
    // Copy most of ECDSAVerify but with less outputs
    var n = TestCurve_getN();
    var Gx = TestCurve_getGx();
    var Gy = TestCurve_getGy();
    
    // u1 = z * w mod n  
    signal zw;
    zw <== z * w;
    signal q1n;
    q1n <== q1 * n;
    signal k1;
    k1 <== zw - q1n;
    
    // u2 = r * w mod n
    signal rw;
    rw <== r * w; 
    signal q2n;
    q2n <== q2 * n;
    signal k2;
    k2 <== rw - q2n;
    
    // P1 = u1 * G
    component P1 = ScalarMul(254);
    P1.Px <== Gx;
    P1.Py <== Gy;
    P1.k <== k1;
    
    // P2 = u2 * Q  
    component P2 = ScalarMul(254);
    P2.Px <== Qx;
    P2.Py <== Qy;
    P2.k <== k2;
    
    // R = P1 + P2
    component sum = PointAdd();
    sum.x1 <== P1.Rx;
    sum.y1 <== P1.Ry;
    sum.x2 <== P2.Rx; 
    sum.y2 <== P2.Ry;
    
    // Final check: r = R.x mod n
    signal q3n;
    q3n <== q3 * n;
    signal rx_mod;
    rx_mod <== sum.x3 - q3n;
    
    // Output debug values
    rx_computed <== rx_mod;
    r_expected <== r;
    q3_used <== q3;
    
    component eq = IsEqual();
    eq.in[0] <== rx_mod;
    eq.in[1] <== r;
    are_equal <== eq.out;
}

component main = DebugFinalECDSA();