pragma circom 2.1.0;

include "ecdsa.circom";

template GeneratePublicKey(bits) {
    signal input private_key;
    signal output public_x;
    signal output public_y;
    
    var Gx = TestCurve_getGx();
    var Gy = TestCurve_getGy();
    
    component keygen = ScalarMul(bits);
    keygen.Px <== Gx;
    keygen.Py <== Gy;
    keygen.k <== private_key;
    
    public_x <== keygen.Rx;
    public_y <== keygen.Ry;
}

template VerifyEcdsaSignature(bits) {
    signal input z;
    signal input Qx;
    signal input Qy;
    signal input r;
    signal input s;
    signal input w;
    signal input q1;
    signal input q2;
    signal input q3;
    
    signal output signature_valid;
        
    component verify = ECDSAVerify(bits);
    verify.z <== z;
    verify.Qx <== Qx;
    verify.Qy <== Qy;
    verify.r <== r;
    verify.s <== s;
    verify.w <== w;
    verify.q1 <== q1;
    verify.q2 <== q2;
    verify.q3 <== q3;

    signature_valid <== 1;
}

component main = VerifyEcdsaSignature(254);