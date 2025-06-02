// Class refer to constraint 1) from construction --> pk_c = KeyDer(sk_c)

pragma circom 2.0.0;

include "circomlib/eddsaposeidon.circom";
include "circomlib/babyjub.circom";

template DeriveEudiKey() {
    signal input sk;        // Secret key (scalar)
    signal output pk[2];    // Public key (x, y)

    component mul = babyjub.MulScalar();

    // Set base point (G)
    mul.base[0] <== babyjub.Base8[0]; // G_x
    mul.base[1] <== babyjub.Base8[1]; // G_y

    // Set scalar
    mul.e <== sk;

    // Output public key
    pk[0] <== mul.out[0]; // x
    pk[1] <== mul.out[1]; // y
}
