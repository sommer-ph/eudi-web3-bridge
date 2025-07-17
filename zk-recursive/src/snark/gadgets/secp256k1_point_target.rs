use plonky2::iop::target::Target;
use plonky2::gadgets::non_native_field::NonNativeFieldTarget;
use plonky2::field::types::Field;

use crate::snark::gadgets::secp256k1_point_target::Secp256k1PointTarget;
use crate::snark::fields::secp256k1_base::Secp256K1Base;

/// Representation of curve point on secp256k1 within a circuit.
#[derive(Clone, Debug)]
pub struct Secp256k1PointTarget<F: Field> {
    pub x: NonNativeFieldTarget<F, Secp256K1Base>,
    pub y: NonNativeFieldTarget<F, Secp256K1Base>,
    pub is_infinity: Target,
}
