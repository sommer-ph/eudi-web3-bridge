use num_bigint::BigUint;
use num_traits::Num;
use once_cell::sync::Lazy;

/// The field modulus of secp256k1:  
/// p = 2^256 - 2^32 - 977
pub static SECP256K1_FIELD: Lazy<BigUint> = Lazy::new(|| {
    BigUint::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16).unwrap()
});

/// Generator point (G) x-coordinate of secp256k1
pub static SECP256K1_GENERATOR_X: Lazy<BigUint> = Lazy::new(|| {
    BigUint::from_str_radix("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16).unwrap()
});

/// Generator point (G) y-coordinate of secp256k1
pub static SECP256K1_GENERATOR_Y: Lazy<BigUint> = Lazy::new(|| {
    BigUint::from_str_radix("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16).unwrap()
});
