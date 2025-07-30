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

/// Targets returned when building the outer-only circuit.
#[allow(dead_code)]
pub struct OuterOnlyCircuitTargets {
    pub pk0: plonky2_ecdsa::gadgets::curve::AffinePointTarget<Secp256K1>,
    pub sk0: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<Secp256K1Scalar>,
}

/// Circuit and targets for the outer-only circuit.
#[allow(dead_code)]
pub struct OuterOnlyCircuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: OuterOnlyCircuitTargets,
}

/// Build the outer-only circuit proving secp256k1 key derivation without inner circuit verification.
/// This corresponds to a simplified blockchain wallet key derivation circuit that:
/// 1. Proves pk0 = KeyDer(sk0) over secp256k1 
pub fn build_outer_only_circuit() -> OuterOnlyCircuit {
    let config = CircuitConfig::standard_ecc_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Public input: secp256k1 blockchain wallet public key (pk0)
    let pk0 = builder.add_virtual_affine_point_target::<Secp256K1>();
    for limb in pk0.x.value.limbs.iter().chain(pk0.y.value.limbs.iter()) {
        builder.register_public_input(limb.0);
    }

    // Private input: secp256k1 blockchain wallet secret key (sk0)
    let sk0 = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();

    // === Blockchain Wallet Key Derivation (pk0 = KeyDer(sk0)) ===
    // Derive public key from secret key using secp256k1 base point multiplication
    let pk0_calc = fixed_base_curve_mul_circuit::<Secp256K1, F, D>(
        &mut builder,
        Secp256K1::GENERATOR_AFFINE,
        &sk0,
    );
    builder.connect_affine_point(&pk0_calc, &pk0);

    let data = builder.build::<Cfg>();
    let targets = OuterOnlyCircuitTargets {
        pk0,
        sk0,
    };
    OuterOnlyCircuit { data, targets }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use plonky2::field::types::Sample;
    use plonky2::field::types::{PrimeField, PrimeField64};
    use plonky2::iop::witness::{PartialWitness};
    use plonky2_ecdsa::curve::ecdsa::ECDSASecretKey;
    use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;

    /// Helper to set a nonnative target.
    fn set_nonnative_target<FF: PrimeField>(
        pw: &mut PartialWitness<F>,
        target: &plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<FF>,
        value: FF,
    ) -> Result<()>
    where
        F: PrimeField64,
    {
        pw.set_biguint_target(&target.value, &value.to_canonical_biguint())
    }

    #[test]
    #[ignore]
    fn test_outer_only_proof() -> Result<()> {
        use std::time::Instant;
        
        println!("=== OUTER-ONLY SECP256K1 KEY DERIVATION PROOF ===");
        let total_start = Instant::now();

        println!("\n=== OUTER-ONLY CIRCUIT: SECP256K1 KEY DERIVATION ===");

        // Build outer-only circuit and prove.
        let outer_start = Instant::now();
        let outer = build_outer_only_circuit();
        println!("Outer-only circuit building time: {:?}", outer_start.elapsed());
        println!("Outer-only circuit size: {} gates", outer.data.common.degree());

        println!("\nGenerating outer-only circuit test data...");
        let data_start = Instant::now();
        let sk0_val = Secp256K1Scalar::rand();
        let sk0 = ECDSASecretKey::<Secp256K1>(sk0_val);
        let pk0 = sk0.to_public().0;
        println!("Outer-only test data generation time: {:?}", data_start.elapsed());

        println!("\nSetting up outer-only circuit witness...");
        let witness_start = Instant::now();
        let mut pw = PartialWitness::<F>::new();
        pw.set_biguint_target(&outer.targets.pk0.x.value, &pk0.x.to_canonical_biguint())?;
        pw.set_biguint_target(&outer.targets.pk0.y.value, &pk0.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw, &outer.targets.sk0, sk0_val)?;
        println!("Outer-only witness setup time: {:?}", witness_start.elapsed());

        println!("\nGenerating outer-only circuit proof...");
        let prove_start = Instant::now();
        let proof = outer.data.prove(pw)?;
        let prove_time = prove_start.elapsed();
        println!("Outer-only proof generation time: {:?}", prove_time);
        println!("Outer-only proof size: {} bytes", proof.to_bytes().len());

        println!("\nVerifying outer-only circuit proof...");
        let verify_start = Instant::now();
        let result = outer.data.verify(proof);
        println!("Outer-only proof verification time: {:?}", verify_start.elapsed());
        
        let outer_total = outer_start.elapsed();
        println!("Outer-only circuit total time: {:?}", outer_total);
        
        println!("\n=== PERFORMANCE SUMMARY ===");
        println!("Outer-only Circuit total time: {:?}", outer_total);
        println!("Total outer-only proof system time: {:?}", total_start.elapsed());
        println!("=== OUTER-ONLY PROOF COMPLETE ===\n");
        
        result
    }
}