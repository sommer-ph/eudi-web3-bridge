pragma circom 2.2.0;

include "circomlib/circuits/babyjub.circom";

template PrivToPubCheck() {
    signal input privKey;
    signal input pubKey[2];
    
    signal output valid;

    signal derivedPub[2];

    // pubKey = privKey * G
    component mul = BabyPbk();
    mul.in <== privKey;
    derivedPub[0] <== mul.Ax;
    derivedPub[1] <== mul.Ay;

    pubKey[0] === derivedPub[0];
    pubKey[1] === derivedPub[1];

    valid <== 1;
}

component main { public [ pubKey ] } = PrivToPubCheck();
