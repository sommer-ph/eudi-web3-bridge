//! Circuit statistics and performance monitoring utilities.

use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

/// Print detailed circuit statistics including gates, constraints, and complexity metrics
pub fn print_circuit_stats(name: &str, circuit_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>) {
    // Calculate total constraints by summing constraints for each gate instance
    let total_constraints: usize = circuit_data.gates.iter()
        .map(|gate| gate.0.num_constraints())
        .sum::<usize>() * circuit_data.degree();
    
    println!("{} circuit statistics:", name);
    println!("  Gates: {}", circuit_data.degree());
    println!("  Total constraints: {}", total_constraints);
    println!("  Public inputs: {}", circuit_data.num_public_inputs);
    println!("  Constants: {}", circuit_data.num_constants);
    println!("  Gate types: {}", circuit_data.gates.len());
}