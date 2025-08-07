//! Parsing and conversion utilities for cryptographic data.

use anyhow::Result;
use plonky2::field::types::{PrimeField, PrimeField64};
use plonky2::iop::witness::{PartialWitness};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Convert hex string (with or without 0x prefix) to BigUint
pub fn hex_to_bigint(hex_str: &str) -> num_bigint::BigUint {
    let hex_clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    num_bigint::BigUint::parse_bytes(hex_clean.as_bytes(), 16)
        .expect("Invalid hex string")
}

/// Helper to set a nonnative field element as a circuit target value
pub fn set_nonnative_target<FF: PrimeField>(
    pw: &mut PartialWitness<F>,
    target: &plonky2_ecdsa::gadgets::nonnative::NonNativeTarget<FF>,
    value: FF,
) -> Result<()>
where
    F: PrimeField64,
{
    pw.set_biguint_target(&target.value, &value.to_canonical_biguint())?;
    Ok(())
}
