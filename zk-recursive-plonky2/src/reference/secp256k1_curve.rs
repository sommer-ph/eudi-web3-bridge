use crate::reference::secp256k1_params::{SECP256K1_GENERATOR_X, SECP256K1_GENERATOR_Y};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use std::ops::{Add, Mul};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Secp256k1Point {
    pub x: BigUint,
    pub y: BigUint,
    pub infinity: bool,
}

impl Secp256k1Point {
    pub fn generator() -> Self {
        Secp256k1Point {
            x: SECP256K1_GENERATOR_X.clone(),
            y: SECP256K1_GENERATOR_Y.clone(),
            infinity: false,
        }
    }

    pub fn double(&self) -> Self {
        if self.infinity || self.y.is_zero() {
            return Secp256k1Point::infinity();
        }

        let p = crate::reference::secp256k1_params::SECP256K1_FIELD.clone();
        let two = BigUint::from(2u8);
        let three = BigUint::from(3u8);

        let slope = ((&three * &self.x * &self.x)
            * modinv(&(&two * &self.y), &p))
            % &p;

        let x3 = (&slope * &slope - &two * &self.x) % &p;
        let y3 = (&slope * (&self.x - &x3) - &self.y) % &p;

        Secp256k1Point {
            x: x3,
            y: y3,
            infinity: false,
        }
    }

    pub fn add(&self, other: &Self) -> Self {
        if self.infinity {
            return other.clone();
        }
        if other.infinity {
            return self.clone();
        }
        let p = crate::reference::secp256k1_params::SECP256K1_FIELD.clone();

        if self.x == other.x {
            if self.y == other.y {
                return self.double();
            } else {
                return Secp256k1Point::infinity();
            }
        }

        let slope = ((&other.y + &p - &self.y)
            * modinv(&(&other.x + &p - &self.x), &p))
            % &p;

        let x3 = (&slope * &slope - &self.x - &other.x) % &p;
        let y3 = (&slope * (&self.x - &x3) - &self.y) % &p;

        Secp256k1Point {
            x: x3,
            y: y3,
            infinity: false,
        }
    }

    pub fn scalar_mul(&self, scalar: u64) -> Self {
        let mut res = Secp256k1Point::infinity();
        let mut base = self.clone();

        for i in 0..64 {
            if ((scalar >> i) & 1) == 1 {
                res = res.add(&base);
            }
            base = base.double();
        }

        res
    }

    pub fn infinity() -> Self {
        Secp256k1Point {
            x: BigUint::zero(),
            y: BigUint::zero(),
            infinity: true,
        }
    }
}

/// Modular inverse using extended Euclidean algorithm.
fn modinv(a: &BigUint, m: &BigUint) -> BigUint {
    let mut mn = (m.clone(), a.clone());
    let mut xy = (BigUint::zero(), BigUint::one());

    while mn.1 != BigUint::zero() {
        let q = &mn.0 / &mn.1;
        mn = (mn.1.clone(), &mn.0 - &q * &mn.1);
        xy = (xy.1.clone(), &xy.0 - &q * &xy.1);
    }

    (xy.0 + m) % m
}
