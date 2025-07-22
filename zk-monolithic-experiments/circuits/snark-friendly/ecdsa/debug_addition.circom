pragma circom 2.1.0;

include "ecdsa.circom";

// Debug point addition directly
template DebugPointAddition() {
    signal input x1, y1, x2, y2;
    signal output x3, y3;
    
    component add = PointAdd();
    add.x1 <== x1;
    add.y1 <== y1; 
    add.x2 <== x2;
    add.y2 <== y2;
    
    x3 <== add.x3;
    y3 <== add.y3;
}

component main = DebugPointAddition();