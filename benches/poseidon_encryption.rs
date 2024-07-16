use std::str::FromStr;

// bench-mark tool
use criterion::{criterion_group, criterion_main, Criterion};
use num_bigint::BigUint;
use poseidon::hash;
use pvde::encryption::poseidon_encryption::encrypt;
use pvde::encryption::poseidon_encryption_zkp::{
    load, prove, verify, PoseidonEncryptionPublicInput, PoseidonEncryptionSecretInput,
};

fn poseidon_encryption_bench(name: &str, c: &mut Criterion) {
    // Define prover and verifier names
    let prover_name = "Measure prover time in ".to_owned() + name;
    let verifier_name = "Measure verifier time in ".to_owned() + name;

    let (params, proving_key, verifying_key) = load();

    let data = "stompesi";

    let k = BigUint::from_str("1").unwrap();
    let k_hash_value = hash::hash(k.clone());
    
    let encrypted_data = encrypt(data, &k_hash_value);
    let poseidon_encryption_public_input = PoseidonEncryptionPublicInput {
        encrypted_data,
        k_hash_value: k_hash_value.clone(),
    };
    let poseidon_encryption_secret_input = PoseidonEncryptionSecretInput {
        data: data.to_string(),
        k,
    };

    // Benchmark the prove
    c.bench_function(&prover_name, |b| {
        b.iter(|| {
            prove(
                &params,
                &proving_key,
                &poseidon_encryption_public_input,
                &poseidon_encryption_secret_input,
            );
        });
    });

    // Make a proof
    let proof = prove(
        &params,
        &proving_key,
        &poseidon_encryption_public_input,
        &poseidon_encryption_secret_input,
    );

    // Benchmark the verification
    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            let is_valid = verify(
                &params,
                &verifying_key,
                &poseidon_encryption_public_input,
                &proof,
            );
            assert!(is_valid);
        });
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    poseidon_encryption_bench("poseidon encryption verify", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
