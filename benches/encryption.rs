use std::str::FromStr;

// bench-mark tool
use criterion::{criterion_group, criterion_main, Criterion};
use encryptor::hash;
use num_bigint::BigUint;
use pvde::encryption::encryption::encrypt;
use pvde::encryption::encryption_zkp::{
    load, prove, verify, EncryptionPublicInput, EncryptionSecretInput,
};
use pvde::encryption::poseidon_encryption::encrypt;

fn encryption_bench(name: &str, c: &mut Criterion) {
    // Define prover and verifier names
    let prover_name = "Measure prover time in ".to_owned() + name;
    let verifier_name = "Measure verifier time in ".to_owned() + name;

    let (params, proving_key, verifying_key) = load();

    let data = "stompesi";

    let k = BigUint::from_str("1").unwrap();
    let k_hash_value = hash::hash(k.clone());

    let encrypted_data = encrypt(data, &k_hash_value);
    let encryption_public_input = EncryptionPublicInput {
        encrypted_data,
        k_hash_value: k_hash_value.clone(),
    };
    let encryption_secret_input = EncryptionSecretInput {
        data: data.to_string(),
        k,
    };

    // Benchmark the prove
    c.bench_function(&prover_name, |b| {
        b.iter(|| {
            prove(
                &params,
                &proving_key,
                &encryption_public_input,
                &encryption_secret_input,
            );
        });
    });

    // Make a proof
    let proof = prove(
        &params,
        &proving_key,
        &encryption_public_input,
        &encryption_secret_input,
    );

    // Benchmark the verification
    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            let is_valid = verify(&params, &verifying_key, &encryption_public_input, &proof);
            assert!(is_valid);
        });
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    encryption_bench("encryption verify", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
