//! Circuit statistics and performance monitoring utilities

use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::circuit_data::CommonCircuitData;
use std::collections::HashMap;

const D: usize = 2;
type Cfg = PoseidonGoldilocksConfig;
type F = <Cfg as GenericConfig<D>>::F;

fn extract_gate_base_type(gate_id: &str) -> String {
    if let Some(pos) = gate_id.find(" {") {
        gate_id[..pos].to_string()
    } else if let Some(pos) = gate_id.find('(') {
        gate_id[..pos].to_string()
    } else if let Some(pos) = gate_id.find('<') {
        gate_id[..pos].to_string()
    } else {
        gate_id.to_string()
    }
}

pub fn print_circuit_stats(name: &str, cd: &CommonCircuitData<F, D>) {
    println!("\n{name} Circuit Summary");
    println!("{}", "=".repeat(40));

    let idx = &cd.selectors_info.selector_indices;
    let mut gate_stats = HashMap::<String, (usize, usize)>::new(); // (instances, constraints)

    let mut total_gate_instances = 0;
    let mut total_constraints = 0;

    for (gate_idx, gate_ref) in cd.gates.iter().enumerate() {
        let base_type = extract_gate_base_type(&gate_ref.0.id());
        let constraints_per_instance = gate_ref.0.num_constraints();
        let instances = if gate_idx + 1 < idx.len() {
            idx[gate_idx + 1] - idx[gate_idx]
        } else {
            0
        };
        let total_constraints_for_gate = instances * constraints_per_instance;
        if instances > 0 {
            gate_stats
                .entry(base_type)
                .and_modify(|e| {
                    e.0 += instances;
                    e.1 += total_constraints_for_gate;
                })
                .or_insert((instances, total_constraints_for_gate));
        }

        total_gate_instances += instances;
        total_constraints += total_constraints_for_gate;
    }

    let circuit_rows = cd.degree();
    let utilization = if circuit_rows > 0 {
        (total_gate_instances as f64 / circuit_rows as f64) * 100.0
    } else {
        0.0
    };

    // Summary block
    println!("Circuit Rows (degree):     {}", cd.degree());
    println!("Public Inputs:             {}", cd.num_public_inputs);
    println!("Constants:                 {}", cd.num_constants);
    println!("Active Gate Types:         {}", gate_stats.len());
    println!("Total Gate Instances:      {}", total_gate_instances);
    println!("Total Constraints:         {} ({:.2}k)", total_constraints, total_constraints as f64 / 1000.0);
    println!("Utilization:               {:.2}%", utilization);
    println!();

    // Gate breakdown
    println!("Top Gates (sorted by constraints):");
    let mut sorted_gates: Vec<_> = gate_stats.into_iter().collect();
    sorted_gates.sort_by(|a, b| b.1.1.cmp(&a.1.1));

    println!("{:<25} {:>7} {:>12} {:>7}", "Gate", "Count", "Constraints", "Share");
    for (gate, (instances, constraints)) in &sorted_gates {
        let pct = (*constraints as f64 / total_constraints as f64) * 100.0;
        println!("{:<25} {:>7} {:>12} {:>6.1}%", gate, instances, constraints, pct);
    }

    println!();
}
