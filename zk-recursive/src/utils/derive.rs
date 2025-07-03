use k256::{
    elliptic_curve::{
        sec1::ToEncodedPoint,
        bigint::U256,
        Group,
        ops::Reduce,
    }, 
    ProjectivePoint, 
    PublicKey, 
    Scalar,
};
use hmac::{Hmac, Mac};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// BIP32 non-hardened public key derivation for secp256k1
/// 
/// Derives a child public key from a parent public key using the BIP32 specification.
/// Only works for non-hardened derivation (index < 2^31).
/// 
/// # Arguments
/// * `parent_pubkey` - The parent public key
/// * `chain_code` - The 32-byte chain code
/// * `index` - The derivation index (must be < 2^31 for non-hardened)
/// 
/// # Returns
/// A tuple containing (child_public_key, child_chain_code)
/// 
/// # Panics
/// Panics if index >= 2^31 (hardened derivation not supported)
pub fn derive_child_pubkey(
    parent_pubkey: &PublicKey,
    chain_code: &[u8; 32],
    index: u32,
) -> Result<(PublicKey, [u8; 32]), &'static str> {
    // Ensure non-hardened derivation
    if index >= 0x80000000 {
        return Err("Hardened derivation not supported in public key derivation");
    }

    // 1. Serialize parent public key in compressed format (33 bytes)
    let parent_compressed = parent_pubkey.to_encoded_point(true);
    let parent_bytes = parent_compressed.as_bytes();
    
    // 2. Prepare HMAC input: compressed_pubkey || index_be
    let mut hmac_input = Vec::with_capacity(37); // 33 + 4 bytes
    hmac_input.extend_from_slice(parent_bytes);
    hmac_input.extend_from_slice(&index.to_be_bytes());

    // 3. Compute I = HMAC-SHA512(chain_code, hmac_input)
    let mut mac = HmacSha512::new_from_slice(chain_code)
        .map_err(|_| "Invalid chain code length")?;
    mac.update(&hmac_input);
    let i = mac.finalize().into_bytes();

    // 4. Split I into I_L (left 32 bytes) and I_R (right 32 bytes)
    let il_bytes: [u8; 32] = i[..32].try_into().unwrap();
    let ir_bytes: [u8; 32] = i[32..].try_into().unwrap();

    // 5. Convert I_L to scalar, ensuring it's valid (< curve order)
    let il_u256 = U256::from_be_slice(&il_bytes);
    let il_scalar = <Scalar as Reduce<U256>>::reduce(il_u256);
    
    // Check if I_L is zero (invalid case, though extremely unlikely)
    if il_scalar.is_zero().into() {
        return Err("Invalid derivation: I_L is zero");
    }

    // 6. Compute child public key: PK_child = G * I_L + PK_parent
    let g_times_il = ProjectivePoint::GENERATOR * il_scalar;
    let parent_point = ProjectivePoint::from(*parent_pubkey.as_affine());
    let child_point = parent_point + g_times_il;
    
    // Check if result is point at infinity (invalid case)
    if child_point.is_identity().into() {
        return Err("Invalid derivation: result is point at infinity");
    }

    // 7. Convert back to PublicKey
    let child_pubkey = PublicKey::from_affine(child_point.to_affine())
        .map_err(|_| "Failed to create child public key")?;

    Ok((child_pubkey, ir_bytes))
}