use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use plonky2_ecdsa::curve::p256::P256;
use plonky2_ecdsa::field::p256_scalar::P256Scalar;
use plonky2_ecdsa::gadgets::ecdsa::ECDSASignatureTarget;
use plonky2_ecdsa::add_static_pk_ecdsa_verify_constraints;
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Targets for the signature verification only inner circuit with static public key.
#[allow(dead_code)]
pub struct InnerSigVerifyStaticTargets {
    pub msg: plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<P256Scalar>,
    pub sig: ECDSASignatureTarget<P256>,
}

/// Circuit that only implements the signature verification constraint: VerifySig(pk_I, msg, sig)
/// with a static/fixed issuer public key for improved efficiency.
#[allow(dead_code)]
pub struct InnerSigVerifyStaticCircuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: InnerSigVerifyStaticTargets,
}

/// Build inner circuit that only proves signature verification with static issuer public key
/// This uses the efficient lookup-based verification for the fixed issuer key.
pub fn build_inner_sig_verify_static_circuit() -> InnerSigVerifyStaticCircuit {
    let config = CircuitConfig::standard_ecc_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Private inputs: message and signature (public key is now static/fixed)
    let msg = builder.add_virtual_nonnative_target::<P256Scalar>();
    let r = builder.add_virtual_nonnative_target::<P256Scalar>();
    let s = builder.add_virtual_nonnative_target::<P256Scalar>();
    let signature = ECDSASignatureTarget { r, s };

    // === C3: Credential Signature Verification with Static Issuer Key ===
    // Verify that the credential was validly signed by the fixed trusted issuer
    // This uses the efficient lookup table for the static public key Q
    add_static_pk_ecdsa_verify_constraints(&mut builder, msg.clone(), signature.clone());

    let data = builder.build::<Cfg>();
    let targets = InnerSigVerifyStaticTargets {
        msg,
        sig: signature,
    };

    InnerSigVerifyStaticCircuit { data, targets }
}