use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    // Parse arguments
    let mut value: Option<u64> = None;
    let mut bits: Option<usize> = None;
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--value" => {
                if i + 1 < args.len() {
                    value = args[i + 1].parse().ok();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--bits" => {
                if i + 1 < args.len() {
                    bits = args[i + 1].parse().ok();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    
    // Check if we have both arguments
    if value.is_none() || bits.is_none() {
        eprintln!("Usage: cargo run --bin range_proof -- --value <value> --bits <bits>");
        eprintln!("Example: cargo run --bin range_proof -- --value 42 --bits 64");
        std::process::exit(1);
    }
    
    let value = value.unwrap();
    let bits = bits.unwrap();
    
    // Validate bits
    if bits > 64 || bits == 0 {
        eprintln!("Error: bits must be between 1 and 64");
        std::process::exit(1);
    }
    
    // Validate value fits in the bit range
    let max_value = if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 };
    if value > max_value {
        eprintln!("Error: value {} exceeds maximum for {} bits ({})", value, bits, max_value);
        std::process::exit(1);
    }
    
    // Setup generators
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1);
    let blinding = Scalar::random(&mut thread_rng());
    
    // Create proof
    let mut prover_transcript = Transcript::new(b"range_proof_example");
    let (proof, committed_value) = match RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        value,
        &blinding,
        bits,
    ) {
        Ok((p, c)) => (p, c),
        Err(e) => {
            eprintln!("Error creating proof: {:?}", e);
            std::process::exit(1);
        }
    };
    
    // Verify proof
    let mut verifier_transcript = Transcript::new(b"range_proof_example");
    let verification_result = proof.verify_single(
        &bp_gens,
        &pc_gens,
        &mut verifier_transcript,
        &committed_value,
        bits,
    );
    
    let is_valid = verification_result.is_ok();
    
    let proof_size = proof.to_bytes().len();
    
    // Output in consistent format
    println!("VALUE: {}", value);
    println!("BITS: {}", bits);
    println!("PROOF_SIZE: {}", proof_size);
    println!("VERIFICATION: {}", if is_valid { "OK" } else { "FAILED" });
}