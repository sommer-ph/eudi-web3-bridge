use std::path::PathBuf;

use anyhow::Result;
use nova_scotia::{
    circom::{circuit::CircomCircuit, reader::{load_r1cs, load_witness_from_file}},
    create_public_params, FileLocation, F, C1, C2,
};
use nova_snark::{
    provider,
    PublicParams, RecursiveSNARK,
};

fn main() -> Result<()> {
    // Define the cycle of curves compatible with Circom's bn254 prime
    type G1 = provider::bn256_grumpkin::bn256::Point;
    type G2 = provider::bn256_grumpkin::grumpkin::Point;

    let total_start = std::time::Instant::now();
    println!("=== Nova-Scotia Main Implementation - Complete Flow ===\n");

    // Determine paths to the R1CS and witness files
    let mut args = std::env::args().skip(1);
    let r1cs_path: PathBuf = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("build_monolithic/nova-cred-bind-wrapper.r1cs"));
    let witness_path: PathBuf = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("build_monolithic/nova-cred-bind-wrapper.wtns"));

    // 1. Load R1CS
    println!("[STEP 1] Loading R1CS from: {:?}", r1cs_path);
    if !r1cs_path.exists() {
        return Err(anyhow::anyhow!("R1CS file not found: {:?}", r1cs_path));
    }
    
    let r1cs_start = std::time::Instant::now();
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(r1cs_path.clone()));
    let r1cs_time = r1cs_start.elapsed();
    println!("   R1CS loaded in {:?} ({} constraints, {} variables, {} inputs)", 
             r1cs_time, r1cs.constraints.len(), r1cs.num_variables, r1cs.num_inputs);
    
    // 2. Load Witness
    println!("\n[STEP 2] Loading witness from: {:?}", witness_path);
    if !witness_path.exists() {
        return Err(anyhow::anyhow!("Witness file not found: {:?}", witness_path));
    }
    
    let witness_start = std::time::Instant::now();
    let witness = load_witness_from_file::<F<G1>>(&witness_path);
    let witness_time = witness_start.elapsed();
    println!("   Witness loaded in {:?} ({} elements)", witness_time, witness.len());

    // 3. Create Nova public parameters
    println!("\n[STEP 3] Creating Nova public parameters...");
    let pp_start = std::time::Instant::now();
    let pp: PublicParams<G1, G2, C1<G1>, C2<G2>> = create_public_params(r1cs.clone());
    let pp_time = pp_start.elapsed();
    println!("   Public parameters created in {:?} ({:.1} minutes)", pp_time, pp_time.as_secs_f64() / 60.0);

    // 4. Calculate Nova configuration
    println!("\n[STEP 4] Calculating Nova configuration...");
    let config_start = std::time::Instant::now();
    let _total_public_inputs = r1cs.num_inputs - 1; // Subtract 1 for the constant
    
    // For nova-cred-bind-wrapper: public input is z_i[1] (line 85 in .circom)
    // Circuit computes z_out[0] = z_i[0] + 1
    // From public.json: ["1","0"] means z_out=1 when z_i=0
    // So we start with z_i = 0 and expect z_out = 1
    let arity = 1; // Nova state has 1 element
    let start_public_input = vec![F::<G1>::from(0)]; // Start with z_i = 0
    
    let config_time = config_start.elapsed();
    println!("   Configuration calculated in {:?}", config_time);
    println!("   Using arity {} with z_i = 0 (expecting z_out = 1)", arity);

    // 5. Prepare circuits
    println!("\n[STEP 5] Setting up Nova circuits...");
    let circuit_start = std::time::Instant::now();
    let circuit_primary = CircomCircuit {
        r1cs: r1cs.clone(),
        witness: Some(witness),
    };
    let circuit_secondary = nova_scotia::C2::<G2>::default();
    let z0_secondary = vec![<G2 as nova_snark::traits::Group>::Scalar::zero()];
    let circuit_time = circuit_start.elapsed();
    println!("   Circuits prepared in {:?}", circuit_time);

    // 6. Initialize RecursiveSNARK
    println!("\n[STEP 6] Initializing RecursiveSNARK...");
    let init_start = std::time::Instant::now();
    let mut recursive_snark = RecursiveSNARK::new(
        &pp,
        &circuit_primary,
        &circuit_secondary,
        start_public_input.clone(),
        z0_secondary.clone(),
    );
    let init_time = init_start.elapsed();
    println!("   RecursiveSNARK initialized in {:?}", init_time);

    // 7. Prove Step 0
    println!("\n[STEP 7] Proving folding step 0...");
    let prove_start = std::time::Instant::now();
    recursive_snark.prove_step(
        &pp,
        &circuit_primary,
        &circuit_secondary,
        start_public_input.clone(),
        z0_secondary.clone(),
    )?;
    let prove_time = prove_start.elapsed();
    println!("   Step 0 proved in {:?} ({:.2} μs)", prove_time, prove_time.as_nanos() as f64 / 1000.0);

    // 8. Verify the proof
    println!("\n[STEP 8] Verifying recursive proof...");
    let verify_start = std::time::Instant::now();
    let res = recursive_snark.verify(&pp, 1, &start_public_input, &z0_secondary)?;
    let verify_time = verify_start.elapsed();
    println!("   Verification completed in {:?} ({:.2} ms)", verify_time, verify_time.as_millis());
    println!("   Verification result: {:?}", res);

    let total_time = total_start.elapsed();
    
    println!("\n{}", "=".repeat(70));
    println!("COMPLETE PERFORMANCE SUMMARY");
    println!("{}", "=".repeat(70));
    println!("├─ R1CS Loading:           {:>10.3}s", r1cs_time.as_secs_f64());
    println!("├─ Witness Loading:        {:>10.3}s", witness_time.as_secs_f64());
    println!("├─ Public Parameters:      {:>10.1}s ({:.1} min)", pp_time.as_secs_f64(), pp_time.as_secs_f64() / 60.0);
    println!("├─ Configuration:          {:>10.3}s", config_time.as_secs_f64());
    println!("├─ Circuit Setup:          {:>10.3}s", circuit_time.as_secs_f64());
    println!("├─ SNARK Initialization:   {:>10.3}s", init_time.as_secs_f64());
    println!("├─ Step 0 Proving:         {:>10.6}s ({:.2} μs)", prove_time.as_secs_f64(), prove_time.as_nanos() as f64 / 1000.0);
    println!("├─ Verification:           {:>10.6}s ({:.2} ms)", verify_time.as_secs_f64(), verify_time.as_millis());
    println!("└─ TOTAL TIME:             {:>10.1}s ({:.1} min)", total_time.as_secs_f64(), total_time.as_secs_f64() / 60.0);
    println!("{}", "=".repeat(70));
    
    println!("\nSUCCESS!");
    println!("   Nova-compatible circuit verified successfully!");
    println!("   Recursive proof generated and verified: {:?}", res);

    Ok(())
}
