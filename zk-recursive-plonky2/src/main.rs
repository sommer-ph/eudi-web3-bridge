use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData};
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

/// Targets returned when building the first circuit.
pub struct Step1Targets {
    pub pk_i: plonky2_ecdsa::gadgets::curve::AffinePointTarget<P256>,
    pub msg: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<P256Scalar>,
    pub sig: ECDSASignatureTarget<P256>,
    pub pk_cred: plonky2_ecdsa::gadgets::curve::AffinePointTarget<P256>,
    pub sk_c: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<P256Scalar>,
}

/// Circuit and targets for step one.
pub struct Step1Circuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: Step1Targets,
}

/// Targets returned when building the second circuit.
pub struct Step2Targets {
    pub pk0: plonky2_ecdsa::gadgets::curve::AffinePointTarget<Secp256K1>,
    pub sk0: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<Secp256K1Scalar>,
    pub proof: plonky2::plonk::proof::ProofWithPublicInputsTarget<D>,
    pub vd: plonky2::plonk::circuit_data::VerifierCircuitTarget,
}

/// Circuit and targets for step two.
pub struct Step2Circuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: Step2Targets,
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use plonky2::field::types::Sample;
    use plonky2::field::types::{PrimeField, PrimeField64};
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2_ecdsa::curve::ecdsa::{sign_message, ECDSASecretKey};
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
    fn test_step1_only() -> Result<()> {
        use std::time::Instant;
        
        println!("=== STEP 1: EUDI CREDENTIAL BINDING CIRCUIT ===");
        
        let start = Instant::now();
        let step1 = build_step1_circuit();
        println!("Circuit building time: {:?}", start.elapsed());
        println!("Circuit size: {} gates", step1.data.common.degree());

        println!("\nGenerating test data...");
        let data_start = Instant::now();
        let msg = P256Scalar::rand();
        let sk_i_val = P256Scalar::rand();
        let sk_i = ECDSASecretKey::<P256>(sk_i_val);
        let pk_i = sk_i.to_public().0;
        let sig = sign_message(msg, sk_i);

        let sk_c_val = P256Scalar::rand();
        let sk_c = ECDSASecretKey::<P256>(sk_c_val);
        let pk = sk_c.to_public().0;
        println!("Test data generation time: {:?}", data_start.elapsed());

        println!("\nSetting up witness...");
        let witness_start = Instant::now();
        let mut pw1 = PartialWitness::<F>::new();
        pw1.set_biguint_target(&step1.targets.pk_i.x.value, &pk_i.x.to_canonical_biguint())?;
        pw1.set_biguint_target(&step1.targets.pk_i.y.value, &pk_i.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw1, &step1.targets.msg, msg)?;
        set_nonnative_target(&mut pw1, &step1.targets.sig.r, sig.r)?;
        set_nonnative_target(&mut pw1, &step1.targets.sig.s, sig.s)?;
        pw1.set_biguint_target(&step1.targets.pk_cred.x.value, &pk.x.to_canonical_biguint())?;
        pw1.set_biguint_target(&step1.targets.pk_cred.y.value, &pk.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw1, &step1.targets.sk_c, sk_c_val)?;
        println!("Witness setup time: {:?}", witness_start.elapsed());

        println!("\nGenerating proof...");
        let prove_start = Instant::now();
        let proof1 = step1.data.prove(pw1)?;
        let prove_time = prove_start.elapsed();
        println!("Proof generation time: {:?}", prove_time);
        println!("Proof size: {} bytes", proof1.to_bytes().len());

        println!("\nVerifying proof...");
        let verify_start = Instant::now();
        let result = step1.data.verify(proof1);
        let verify_time = verify_start.elapsed();
        println!("Proof verification time: {:?}", verify_time);
        
        println!("\nTotal step1 time: {:?}", start.elapsed());
        println!("=== STEP 1 COMPLETE ===\n");
        
        result
    }

    #[test]
    #[ignore]
    fn test_recursive_proof() -> Result<()> {
        use std::time::Instant;
        
        println!("=== RECURSIVE ZK-SNARK PROOF SYSTEM ===");
        let total_start = Instant::now();

        println!("\n=== STEP 1: EUDI CREDENTIAL BINDING CIRCUIT ===");
        
        // Build step1 circuit and generate witness.
        let step1_start = Instant::now();
        let step1 = build_step1_circuit();
        println!("Step1 circuit building time: {:?}", step1_start.elapsed());
        println!("Step1 circuit size: {} gates", step1.data.common.degree());

        println!("\nGenerating step1 test data...");
        let data_start = Instant::now();
        let msg = P256Scalar::rand();
        let sk_i_val = P256Scalar::rand();
        let sk_i = ECDSASecretKey::<P256>(sk_i_val);
        let pk_i = sk_i.to_public().0;
        let sig = sign_message(msg, sk_i);

        let sk_c_val = P256Scalar::rand();
        let sk_c = ECDSASecretKey::<P256>(sk_c_val);
        let pk = sk_c.to_public().0;
        println!("Step1 test data generation time: {:?}", data_start.elapsed());

        println!("\nSetting up step1 witness...");
        let witness_start = Instant::now();
        let mut pw1 = PartialWitness::<F>::new();
        pw1.set_biguint_target(&step1.targets.pk_i.x.value, &pk_i.x.to_canonical_biguint())?;
        pw1.set_biguint_target(&step1.targets.pk_i.y.value, &pk_i.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw1, &step1.targets.msg, msg)?;
        set_nonnative_target(&mut pw1, &step1.targets.sig.r, sig.r)?;
        set_nonnative_target(&mut pw1, &step1.targets.sig.s, sig.s)?;
        pw1.set_biguint_target(&step1.targets.pk_cred.x.value, &pk.x.to_canonical_biguint())?;
        pw1.set_biguint_target(&step1.targets.pk_cred.y.value, &pk.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw1, &step1.targets.sk_c, sk_c_val)?;
        println!("Step1 witness setup time: {:?}", witness_start.elapsed());

        println!("\nGenerating step1 proof...");
        let prove1_start = Instant::now();
        let proof1 = step1.data.prove(pw1)?;
        let prove1_time = prove1_start.elapsed();
        println!("Step1 proof generation time: {:?}", prove1_time);
        println!("Step1 proof size: {} bytes", proof1.to_bytes().len());

        println!("\nVerifying step1 proof...");
        let verify1_start = Instant::now();
        step1.data.verify(proof1.clone())?;
        println!("Step1 proof verification time: {:?}", verify1_start.elapsed());
        
        let step1_total = step1_start.elapsed();
        println!("Step1 total time: {:?}", step1_total);

        println!("\n=== STEP 2: RECURSIVE CIRCUIT WITH SECP256K1 ===");

        // Build step2 circuit and prove recursively.
        let step2_start = Instant::now();
        let step2 = build_step2_circuit(&step1.data.common);
        println!("Step2 circuit building time: {:?}", step2_start.elapsed());
        println!("Step2 circuit size: {} gates", step2.data.common.degree());

        println!("\nGenerating step2 test data...");
        let data2_start = Instant::now();
        let sk0_val = Secp256K1Scalar::rand();
        let sk0 = ECDSASecretKey::<Secp256K1>(sk0_val);
        let pk0 = sk0.to_public().0;
        println!("Step2 test data generation time: {:?}", data2_start.elapsed());

        println!("\nSetting up step2 witness...");
        let witness2_start = Instant::now();
        let mut pw2 = PartialWitness::<F>::new();
        pw2.set_biguint_target(&step2.targets.pk0.x.value, &pk0.x.to_canonical_biguint())?;
        pw2.set_biguint_target(&step2.targets.pk0.y.value, &pk0.y.to_canonical_biguint())?;
        set_nonnative_target(&mut pw2, &step2.targets.sk0, sk0_val)?;
        pw2.set_proof_with_pis_target(&step2.targets.proof, &proof1)?;
        pw2.set_verifier_data_target(&step2.targets.vd, &step1.data.verifier_only)?;
        println!("Step2 witness setup time: {:?}", witness2_start.elapsed());

        println!("\nGenerating step2 recursive proof...");
        let prove2_start = Instant::now();
        let proof2 = step2.data.prove(pw2)?;
        let prove2_time = prove2_start.elapsed();
        println!("Step2 proof generation time: {:?}", prove2_time);
        println!("Step2 proof size: {} bytes", proof2.to_bytes().len());

        println!("\nVerifying step2 recursive proof...");
        let verify2_start = Instant::now();
        let result = step2.data.verify(proof2);
        println!("Step2 proof verification time: {:?}", verify2_start.elapsed());
        
        let step2_total = step2_start.elapsed();
        println!("Step2 total time: {:?}", step2_total);
        
        println!("\n=== PERFORMANCE SUMMARY ===");
        println!("Step1 (EUDI Circuit) total time: {:?}", step1_total);
        println!("Step2 (Recursive Circuit) total time: {:?}", step2_total);
        println!("Total recursive proof system time: {:?}", total_start.elapsed());
        println!("=== RECURSIVE PROOF COMPLETE ===\n");
        
        result
    }
}

/// Build the first circuit proving correctness of a P256 signature and key derivation.
/// This corresponds to the EUDI credential binding circuit with three components:
/// C1: pk_c = KeyDer(sk_c) - EUDI wallet key derivation over P256
/// C2: pk_c === pk_cred - Public key equality check  
/// C3: SigVerify(pk_I, msg, sig) - Credential signature verification over P256
fn build_step1_circuit() -> Step1Circuit {
    let config = CircuitConfig::standard_ecc_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Public input: issuer public key (pk_I)
    let pk_i = builder.add_virtual_affine_point_target::<P256>();
    for limb in pk_i.x.value.limbs.iter().chain(pk_i.y.value.limbs.iter()) {
        builder.register_public_input(limb.0);
    }

    // Private inputs
    let msg = builder.add_virtual_nonnative_target::<P256Scalar>();
    let r = builder.add_virtual_nonnative_target::<P256Scalar>();
    let s = builder.add_virtual_nonnative_target::<P256Scalar>();
    let signature = ECDSASignatureTarget { r, s };

    // Private inputs: credential public key (extracted from c.cnf.jwk)
    let pk_cred = builder.add_virtual_affine_point_target::<P256>();
    
    // Private input: EUDI wallet secret key
    let sk_c = builder.add_virtual_nonnative_target::<P256Scalar>();

    // === C1: EUDI Wallet Key Derivation (pk_c = KeyDer(sk_c)) ===
    // Derive public key from secret key using P256 base point multiplication
    let pk_c =
        fixed_base_curve_mul_circuit::<P256, F, D>(&mut builder, P256::GENERATOR_AFFINE, &sk_c);

    // === C2: Credential Public Key Check (pk_c === pk_cred) ===
    // Ensure the derived public key matches the key stored in the credential
    builder.connect_affine_point(&pk_c, &pk_cred);

    // === C3: Credential Signature Verification (SigVerify(pk_I, msg, sig)) ===
    // Verify that the credential was validly signed by a trusted issuer
    let pk_target = ECDSAPublicKeyTarget(pk_i.clone());
    verify_p256_message_circuit(&mut builder, msg.clone(), signature.clone(), pk_target);

    let data = builder.build::<Cfg>();
    let targets = Step1Targets {
        pk_i,
        msg,
        sig: signature,
        pk_cred,
        sk_c,
    };
    Step1Circuit { data, targets }
}

/// Build the second circuit proving secp256k1 key derivation and recursively verifying the first proof.
/// This corresponds to the blockchain wallet key derivation circuit that:
/// 1. Proves pk0 = KeyDer(sk0) over secp256k1 
/// 2. Recursively verifies the inner EUDI credential binding proof
fn build_step2_circuit(inner_common: &CommonCircuitData<F, D>) -> Step2Circuit {
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

    // === Recursive Proof Verification ===
    // Add targets for the proof of the inner EUDI circuit and verify it recursively
    let proof = builder.add_virtual_proof_with_pis(inner_common);
    let vd = builder.add_virtual_verifier_data(inner_common.config.fri_config.cap_height);
    builder.verify_proof::<Cfg>(&proof, &vd, inner_common);

    let data = builder.build::<Cfg>();
    let targets = Step2Targets {
        pk0,
        sk0,
        proof,
        vd,
    };
    Step2Circuit { data, targets }
}

fn main() {
    use std::time::Instant;
    
    println!("=== ZK-RECURSIVE PLONKY2 CIRCUIT BUILDER ===");
    let total_start = Instant::now();
    
    println!("\nBuilding Step1 (EUDI Credential Binding) circuit...");
    let step1_start = Instant::now();
    let step1 = build_step1_circuit();
    println!("Step1 circuit building time: {:?}", step1_start.elapsed());
    println!("Step1 circuit size: {} gates", step1.data.common.degree());
    
    println!("\nBuilding Step2 (Recursive + Secp256k1) circuit...");
    let step2_start = Instant::now();
    let step2 = build_step2_circuit(&step1.data.common);
    println!("Step2 circuit building time: {:?}", step2_start.elapsed());
    println!("Step2 circuit size: {} gates", step2.data.common.degree());
    
    println!("\nTotal circuit building time: {:?}", total_start.elapsed());
    println!("=== CIRCUITS BUILT SUCCESSFULLY ===");
    
    // Prevent unused warnings when running `cargo check`.
    let _ = (step1.data.prover_only, step1.data.verifier_only, step2.data.prover_only);
}
