use std::str::FromStr;

// bench-mark tool
use criterion::{criterion_group, criterion_main, Criterion};
use num_bigint::{BigUint, RandomBits};
use poseidon::hash;
use pvde::time_lock_puzzle::key_validation_zkp::{
    load, prove, verify, KeyValidationParam, KeyValidationPublicInput, KeyValidationSecretInput,
};
use pvde::time_lock_puzzle::sigma_protocol::{
    get_c, verify as verify_sigma_protocol, SigmaProtocolParam, SigmaProtocolPublicInput,
};
use pvde::time_lock_puzzle::{G, N};
use rand::{thread_rng, Rng};

fn bench_delay<const T: usize, const RATE: usize, const K: u32>(
    name: &str,
    criterion: &mut Criterion,
) {
    // Define prover and verifier names
    let prover_name = "Measure prover time in ".to_owned() + name;
    let verifier_name = "Measure verifier time in ".to_owned() + name;
    let sigma_protocol_verifier_name = "Measure sigma protocol verifier time in ".to_owned() + name;

    // set params for protocol
    let (params, proving_key, verifying_key) = load();

    let g = BigUint::from_str(G).unwrap();
    let n = BigUint::from_str(N).unwrap();
    let t = 2048;

    // y = g^{2^t}
    let mut y = g.clone();
    for _ in 0..t {
        y = (&y * &y) % &n;
    }

    let y_two: BigUint = (&y * &y) % &n;

    let r = thread_rng().sample::<BigUint, _>(RandomBits::new(128));
    let s = thread_rng().sample::<BigUint, _>(RandomBits::new(128));

    let r1 = g.modpow(&r, &n);
    let r2 = y_two.modpow(&r, &n);
    let c = get_c(r1.clone(), r2.clone());

    let z = &r + &s * &c;
    let o = g.modpow(&s, &n);
    let k = y.modpow(&s, &n);
    let k_two = y_two.modpow(&s, &n);

    let k_hash_value = hash::hash(k.clone());

    let sigma_protocol_public_input = SigmaProtocolPublicInput {
        r1,
        r2,
        z,
        o,
        k_two: k_two.clone(),
    };
    let sigma_protocol_params = SigmaProtocolParam {
        n: n.clone(),
        g: g.clone(),
        y_two: y_two.clone(),
    };

    // Benchmark the sigma protocol verification
    criterion.bench_function(&sigma_protocol_verifier_name, |b| {
        b.iter(|| {
            let is_valid =
                verify_sigma_protocol(&sigma_protocol_public_input, &sigma_protocol_params);
            assert!(is_valid);
        });
    });

    let key_validation_params = KeyValidationParam { n };
    let key_validation_public_input = KeyValidationPublicInput {
        k_two: k_two.clone(),
        k_hash_value,
    };
    let key_validation_secret_input = KeyValidationSecretInput { k };

    // Benchmark the proving
    criterion.bench_function(&prover_name, |b| {
        b.iter(|| {
            prove(
                &params,
                &proving_key,
                &key_validation_params,
                &key_validation_public_input,
                &key_validation_secret_input,
            );
        });
    });

    let proof = prove(
        &params,
        &proving_key,
        &key_validation_params,
        &key_validation_public_input,
        &key_validation_secret_input,
    );

    // Benchmark the verification
    criterion.bench_function(&verifier_name, |b| {
        b.iter(|| {
            let is_valid = verify(
                &params,
                &verifying_key,
                &key_validation_public_input,
                &proof,
            );
            assert!(is_valid);
        });
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    bench_delay::<5, 4, 14>("delay hash", c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
