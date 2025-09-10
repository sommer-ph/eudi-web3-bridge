use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_ecdsa::curve::curve_types::Curve;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;
use plonky2_ecdsa::gadgets::curve_fixed_base::fixed_base_curve_mul_circuit;
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Targets for the C4 circuit (Secp256k1 Key Derivation).
pub struct C4CircuitTargets {
    pub pk_0: plonky2_ecdsa::gadgets::curve::AffinePointTarget<Secp256K1>,
    pub sk_0: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<Secp256K1Scalar>,
}

/// C4 circuit that implements C4 (Secp256k1 Key Derivation).
pub struct C4Circuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: C4CircuitTargets,
}

/// Build the C4 circuit implementing:
/// - C4: pk_0 = KeyDer(sk_0) - Blockchain wallet key derivation over secp256k1
pub fn build_c4_circuit() -> C4Circuit {
    let mut config = CircuitConfig::standard_ecc_config();
    config.zero_knowledge = true; 
    println!("Zero-knowledge active? {}", config.zero_knowledge);
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // === Public Input: Secp256k1 Public Key ===
    let pk_0 = builder.add_virtual_affine_point_target::<Secp256K1>();
    for limb in pk_0.x.value.limbs.iter().chain(pk_0.y.value.limbs.iter()) {
        builder.register_public_input(limb.0);
    }

    // === Private Input: Secp256k1 Secret Key ===
    let sk_0 = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();

    // === C4: Blockchain Wallet Key Derivation (pk_0 = KeyDer(sk_0)) ===
    // Derive public key from secret key using secp256k1 base point multiplication
    let pk_0_calc = fixed_base_curve_mul_circuit::<Secp256K1, F, D>(
        &mut builder,
        Secp256K1::GENERATOR_AFFINE,
        &sk_0,
    );
    
    // Ensure the derived public key matches the public input
    builder.connect_affine_point(&pk_0_calc, &pk_0);

    let data = builder.build::<Cfg>();
    let targets = C4CircuitTargets {
        pk_0,
        sk_0,
    };

    C4Circuit { data, targets }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_build_c4_circuit() {
        let c4_circuit = build_c4_circuit();
        println!("C4 circuit built successfully");
        println!("Circuit size: {} gates", c4_circuit.data.common.degree());
    }
}