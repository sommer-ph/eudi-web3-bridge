pragma circom 2.1.0;

include "circomlib/circuits/comparators.circom";

// Simple debug template to test point on curve calculation
template DebugPointOnCurve() {
    signal input x; 
    signal input y; 
    signal output lhs_out;
    signal output rhs_out;
    signal output equal;

    // Debug: Log the exact calculations
    signal x_sq; 
    x_sq <== x * x;
    signal x_cu; 
    x_cu <== x_sq * x;
    signal rhs;  
    rhs  <== x_cu + 3;
    signal lhs;  
    lhs  <== y * y;

    // Output intermediate values for debugging
    lhs_out <== lhs;
    rhs_out <== rhs;
    
    // Check equality
    component eq = IsEqual(); 
    eq.in[0] <== lhs; 
    eq.in[1] <== rhs;
    equal <== eq.out;
}

component main = DebugPointOnCurve();