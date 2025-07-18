use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::witness::PartialWitness,
    plonk::{circuit_builder::CircuitBuilder, config::CircuitConfig},
};

use crate::{
    reference::secp256k1_curve::Secp256k1Point,
    snark::gadgets::secp256k1_gadgets::Secp256k1Gadgets,
    snark::gadgets::secp256k1_point_target::Secp256k1PointTarget,
};

#[test]
fn test_scalar_mul_snark() {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);
    let mut pw = PartialWitness::new();

    // === Input: scalar (as Target) ===
    let sk_value = 7u64;
    let sk_target = builder.add_virtual_target();
    pw.set_target(sk_target, GoldilocksField::from_canonical_u64(sk_value));

    // === Reference calculation in Rust ===
    let g = Secp256k1Point::generator();
    let q_expected = g.scalar_mul(sk_value);

    // === Embed reference result as constant target ===
    let q_expected_target = Secp256k1PointTarget {
        x: builder.constant_non_native(q_expected.x),
        y: builder.constant_non_native(q_expected.y),
        is_infinity: builder._false(),
    };

    // === Embed generator as constant input to circuit ===
    let g_target = Secp256k1PointTarget {
        x: builder.constant_non_native(g.x),
        y: builder.constant_non_native(g.y),
        is_infinity: builder._false(),
    };

    // === Gadget logic: Q = sk * G ===
    let q_gadget = builder.secp256k1_scalar_mul(g_target, sk_target);

    // === Assert equality with reference ===
    builder.connect_non_native(&q_gadget.x, &q_expected_target.x);
    builder.connect_non_native(&q_gadget.y, &q_expected_target.y);

    // === Run proof ===
    let circuit = builder.build();
    let proof = circuit.prove(pw).unwrap();
    circuit.verify(proof).unwrap();
}
