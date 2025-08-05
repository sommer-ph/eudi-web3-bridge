use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use plonky2_ecdsa::curve::curve_types::Curve;
use plonky2_ecdsa::curve::p256::P256;
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;
use plonky2_ecdsa::gadgets::curve_fixed_base::fixed_base_curve_mul_circuit;
use plonky2_ecdsa::gadgets::ecdsa::{
    verify_p256_message_circuit, ECDSAPublicKeyTarget, ECDSASignatureTarget,
};
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Targets returned when building the inner extended circuit.
#[allow(dead_code)]
pub struct InnerExtendedCircuitTargets {
    // P256 targets from original inner circuit
    pub pk_issuer: plonky2_ecdsa::gadgets::curve::AffinePointTarget<P256>,
    pub msg: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<P256Scalar>,
    pub sig: ECDSASignatureTarget<P256>,
    pub pk_c: plonky2_ecdsa::gadgets::curve::AffinePointTarget<P256>,
    pub sk_c: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<P256Scalar>,
    // Secp256k1 targets from outer circuit key derivation
    pub pk_0: plonky2_ecdsa::gadgets::curve::AffinePointTarget<Secp256K1>,
    pub sk_0: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<Secp256K1Scalar>,
}

/// Circuit and targets for the inner extended EUDI credential binding circuit.
#[allow(dead_code)]
pub struct InnerExtendedCircuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: InnerExtendedCircuitTargets,
}

/// Build the inner extended circuit proving correctness of both P256 and secp256k1 operations.
/// This corresponds to the EUDI credential binding circuit with four components:
/// C1: pk_c = KeyDer(sk_c) - EUDI wallet key derivation over P256
/// C2: pk_c === pk_c_calc - Public key equality check  
/// C3: SigVerify(pk_I, msg, sig) - Credential signature verification over P256
/// C4: pk_0 = KeyDer(sk_0) - Blockchain wallet key derivation over secp256k1
pub fn build_inner_extended_circuit() -> InnerExtendedCircuit {
    let config = CircuitConfig::standard_ecc_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Public input: issuer public key (pk_issuer) - P256
    let pk_issuer = builder.add_virtual_affine_point_target::<P256>();
    for limb in pk_issuer.x.value.limbs.iter().chain(pk_issuer.y.value.limbs.iter()) {
        builder.register_public_input(limb.0);
    }

    // Public input: secp256k1 blockchain wallet public key (pk_0)
    let pk_0 = builder.add_virtual_affine_point_target::<Secp256K1>();
    for limb in pk_0.x.value.limbs.iter().chain(pk_0.y.value.limbs.iter()) {
        builder.register_public_input(limb.0);
    }

    // Private inputs for P256 operations
    let msg = builder.add_virtual_nonnative_target::<P256Scalar>();
    let r = builder.add_virtual_nonnative_target::<P256Scalar>();
    let s = builder.add_virtual_nonnative_target::<P256Scalar>();
    let signature = ECDSASignatureTarget { r, s };

    // Private inputs: credential public key (extracted from c.cnf.jwk)
    let pk_c = builder.add_virtual_affine_point_target::<P256>();
    
    // Private input: EUDI wallet secret key (P256)
    let sk_c = builder.add_virtual_nonnative_target::<P256Scalar>();

    // Private input: secp256k1 blockchain wallet secret key
    let sk_0 = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();

    // === C1: EUDI Wallet Key Derivation (pk_c = KeyDer(sk_c)) ===
    // Derive public key from secret key using P256 base point multiplication
    let pk_c_calc =
        fixed_base_curve_mul_circuit::<P256, F, D>(&mut builder, P256::GENERATOR_AFFINE, &sk_c);

    // === C2: Credential Public Key Check (pk_c === pk_c_calc) ===
    // Ensure the derived public key matches the key stored in the credential
    builder.connect_affine_point(&pk_c_calc, &pk_c);

    // === C3: Credential Signature Verification (SigVerify(pk_issuer, msg, sig)) ===
    // Verify that the credential was validly signed by a trusted issuer
    let pk_target = ECDSAPublicKeyTarget(pk_issuer.clone());
    verify_p256_message_circuit(&mut builder, msg.clone(), signature.clone(), pk_target);

    // === C4: Blockchain Wallet Key Derivation (pk_0 = KeyDer(sk_0)) ===
    // Derive public key from secret key using secp256k1 base point multiplication
    let pk_0_calc = fixed_base_curve_mul_circuit::<Secp256K1, F, D>(
        &mut builder,
        Secp256K1::GENERATOR_AFFINE,
        &sk_0,
    );
    builder.connect_affine_point(&pk_0_calc, &pk_0);

    let data = builder.build::<Cfg>();
    let targets = InnerExtendedCircuitTargets {
        pk_issuer,
        msg,
        sig: signature,
        pk_c,
        sk_c,
        pk_0,
        sk_0,
    };
    InnerExtendedCircuit { data, targets }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use plonky2::field::types::{Sample, PrimeField};
    use plonky2::iop::witness::PartialWitness;
    use plonky2_ecdsa::curve::ecdsa::{sign_message, ECDSASecretKey};
    use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;
    use crate::utils::parsing::set_nonnative_target;

    #[test]
    #[ignore]
    fn test_inner_extended_circuit_only() -> Result<()> {
        use std::time::Instant;
        
        println!("=== INNER EXTENDED CIRCUIT: EUDI + SECP256K1 KEY DERIVATIONS ===");
        
        let start = Instant::now();
        let inner_extended = build_inner_extended_circuit();
        println!("Circuit building time: {:?}", start.elapsed());
        println!("Circuit size: {} gates", inner_extended.data.common.degree());

        println!("\nGenerating test data...");
        let data_start = Instant::now();
        
        // P256 test data (from original inner circuit)
        let msg = P256Scalar::rand();
        let sk_issuer_val = P256Scalar::rand();
        let sk_issuer = ECDSASecretKey::<P256>(sk_issuer_val);
        let pk_issuer = sk_issuer.to_public().0;
        let sig = sign_message(msg, sk_issuer);

        let sk_c_val = P256Scalar::rand();
        let sk_c = ECDSASecretKey::<P256>(sk_c_val);
        let pk_c = sk_c.to_public().0;

        // Secp256k1 test data (from outer circuit)
        let sk_0_val = Secp256K1Scalar::rand();
        let sk_0 = ECDSASecretKey::<Secp256K1>(sk_0_val);
        let pk_0 = sk_0.to_public().0;

        println!("Test data generation time: {:?}", data_start.elapsed());

        println!("\nSetting up witness...");
        let witness_start = Instant::now();
        let mut pw = PartialWitness::<F>::new();
        
        // P256 witness data
        pw.set_biguint_target(&inner_extended.targets.pk_issuer.x.value, &pk_issuer.x.to_canonical_biguint())?;
        pw.set_biguint_target(&inner_extended.targets.pk_issuer.y.value, &pk_issuer.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw, &inner_extended.targets.msg, msg)?;
        set_nonnative_target(&mut pw, &inner_extended.targets.sig.r, sig.r)?;
        set_nonnative_target(&mut pw, &inner_extended.targets.sig.s, sig.s)?;
        pw.set_biguint_target(&inner_extended.targets.pk_c.x.value, &pk_c.x.to_canonical_biguint())?;
        pw.set_biguint_target(&inner_extended.targets.pk_c.y.value, &pk_c.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw, &inner_extended.targets.sk_c, sk_c_val)?;

        // Secp256k1 witness data
        pw.set_biguint_target(&inner_extended.targets.pk_0.x.value, &pk_0.x.to_canonical_biguint())?;
        pw.set_biguint_target(&inner_extended.targets.pk_0.y.value, &pk_0.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw, &inner_extended.targets.sk_0, sk_0_val)?;

        println!("Witness setup time: {:?}", witness_start.elapsed());

        println!("\nGenerating proof...");
        let prove_start = Instant::now();
        let proof = inner_extended.data.prove(pw)?;
        let prove_time = prove_start.elapsed();
        println!("Proof generation time: {:?}", prove_time);
        println!("Proof size: {} bytes", proof.to_bytes().len());

        println!("\nVerifying proof...");
        let verify_start = Instant::now();
        let result = inner_extended.data.verify(proof);
        let verify_time = verify_start.elapsed();
        println!("Proof verification time: {:?}", verify_time);
        
        println!("\nTotal inner extended circuit time: {:?}", start.elapsed());
        println!("=== INNER EXTENDED CIRCUIT COMPLETE ===\n");
        
        result
    }
}