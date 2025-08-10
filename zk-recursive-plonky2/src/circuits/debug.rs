use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use crate::utils::key_derivation::{
    add_bip32_key_derivation_constraints_fixed, Bip32KeyDerivationTargets
};
use crate::utils::bit_packing::{pack_256_bits_to_field_elements, pack_32_bits_to_field_element};
use crate::types::input::DeriveMode;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

pub struct DebugCircuit {
    pub data: CircuitData<F, Cfg, D>,
    pub targets: Bip32KeyDerivationTargets,
}

impl DebugCircuit {
    pub fn build(derive_mode: DeriveMode) -> anyhow::Result<Self> {
        // **Unified** ECC-Config (needed for BIP32 key derivation gates)
        let cfg = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(cfg);

        let bip32_targets = add_bip32_key_derivation_constraints_fixed(&mut builder, derive_mode);

        // Pack cc_0 (256 bits) into 4 field elements
        let cc_0_packed = pack_256_bits_to_field_elements(&bip32_targets.cc_0, &mut builder);
        for &target in &cc_0_packed {
            builder.register_public_input(target);
        }
        
        // Pack derivation_index (32 bits) into 1 field element  
        let index_packed = pack_32_bits_to_field_element(&bip32_targets.derivation_index, &mut builder);
        builder.register_public_input(index_packed);
        
        // Register pk_i as public input
        for limb in bip32_targets.pk_i.x.value.limbs.iter().chain(
            bip32_targets.pk_i.y.value.limbs.iter()
        ) {
            builder.register_public_input(limb.0);
        }
        
        // Pack cc_i (256 bits) into 4 field elements
        let cc_i_packed = pack_256_bits_to_field_elements(&bip32_targets.cc_i, &mut builder);
        for &target in &cc_i_packed {
            builder.register_public_input(target);
        }
            
        // Build **with** Cfg binding:
        let data = builder.build::<Cfg>();
        
        Ok(Self { 
            data, 
            targets: bip32_targets,
        })
    }
}
