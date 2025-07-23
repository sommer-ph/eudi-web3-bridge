pragma circom 2.1.0;

template DebugFieldArithmetic() {
    signal input a;
    signal input b; 
    signal output a_plus_b;
    signal output a_times_b;
    signal output a_squared;

    a_plus_b <== a + b;
    a_times_b <== a * b;
    a_squared <== a * a;
}

component main = DebugFieldArithmetic();