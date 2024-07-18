pub mod key_validation_circuit;
pub mod sigma_protocol;

pub mod key_validation_zkp;
use std::fs::File;
use std::io::Write;
use std::str::FromStr;

use encryptor::hash::hash;
use encryptor::hash::types::HashValue;
use halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
use halo2_proofs::plonk::{ProvingKey, VerifyingKey};
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use num_bigint::{BigUint, RandomBits};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use sigma_protocol::generate_sigma_protocol_public_input;

use crate::time_lock_puzzle::key_validation_zkp::{
    prove as prove_key_validity, verify as verify_key_validity_zkp, KeyValidationParam,
    KeyValidationPublicInput, KeyValidationSecretInput,
};
use crate::time_lock_puzzle::sigma_protocol::{
    get_c, verify as verify_sigma_protocol, SigmaProtocolParam, SigmaProtocolPublicInput,
};

const BITS_LEN: usize = 2048;
const LIMB_WIDTH: usize = 64;
const LIMB_COUNT: usize = BITS_LEN / LIMB_WIDTH;
const EXP_LIMB_BITS: usize = 15;

const T: usize = 5;
const RATE: usize = 4;

pub const G: &str = "5";
pub const N: &str = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TimeLockPuzzleParam {
    pub g: BigUint,
    pub n: BigUint,
    pub y_two: BigUint,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TimeLockPuzzlePublicInput {
    pub r1: BigUint,
    pub r2: BigUint,
    pub z: BigUint,
    pub o: BigUint,
    pub k_two: BigUint,
    pub k_hash_value: HashValue,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TimeLockPuzzleSecretInput {
    pub k: BigUint,
}

pub fn generate_time_lock_puzzle_param(t: u32) -> TimeLockPuzzleParam {
    let g = BigUint::from_str(G).unwrap();
    let n = BigUint::from_str(N).unwrap();

    // y = g^{2^t}
    let mut y = g.clone();
    for _ in 0..t {
        y = (&y * &y) % &n;
    }

    let y_two: BigUint = (&y * &y) % &n;

    TimeLockPuzzleParam {
        g: g.clone(),
        n: n.clone(),
        y_two: y_two.clone(),
    }
}

pub fn export_time_lock_puzzle_param(file_path: &str, time_lock_puzzle_param: TimeLockPuzzleParam) {
    let json_string = serde_json::to_string(&time_lock_puzzle_param).unwrap();

    let mut file = File::create(file_path).expect("Unable to create file");
    file.write_all(json_string.as_bytes())
        .expect("Unable to write to file");
}

pub fn import_time_lock_puzzle_param(file_path: &str) -> TimeLockPuzzleParam {
    let file = File::open(file_path).expect("Unable to open file");
    let time_lock_puzzle_param: TimeLockPuzzleParam =
        serde_json::from_reader(file).expect("Unable to read file");

    time_lock_puzzle_param
}

pub fn generate_time_lock_puzzle_public_input(
    k: BigUint,
    g: BigUint,
    n: BigUint,
    y_two: BigUint,
) -> TimeLockPuzzlePublicInput {
    let r = thread_rng().sample::<BigUint, _>(RandomBits::new(128));
    let s = thread_rng().sample::<BigUint, _>(RandomBits::new(128));

    let r1 = g.modpow(&r, &n);
    let r2 = y_two.modpow(&r, &n);
    let c = get_c(r1.clone(), r2.clone());

    let z = &r + &s * &c;
    let o = g.modpow(&s, &n);
    let k_two = y_two.modpow(&s, &n);

    let k_hash_value: HashValue = hash(k.clone());

    let time_lock_puzzle_public_input = TimeLockPuzzlePublicInput {
        r1,
        r2,
        z,
        o,
        k_two,
        k_hash_value,
    };
    time_lock_puzzle_public_input
}

pub fn solve_time_lock_puzzle(o: BigUint, t: u32, n: BigUint) -> BigUint {
    let two: BigUint = BigUint::from(2usize);
    let two_t: BigUint = two.pow(t);

    // k = o ^ (2^t)
    o.modpow(&two_t, &n)
}

pub fn get_decryption_key(o: BigUint, t: u32, n: BigUint) -> Result<HashValue, String> {
    let k = solve_time_lock_puzzle(o, t, n);

    // Symmetric key from o
    // Current version (Halo2) uses hash of k
    let encryption_key: HashValue = hash(k);

    Ok(encryption_key)
}

pub fn prove_time_lock_puzzle_validity(
    param: &ParamsKZG<Bn256>,
    proving_key: &ProvingKey<G1Affine>,
    time_lock_puzzle_public_input: TimeLockPuzzlePublicInput,
    time_lock_puzzle_secret_input: TimeLockPuzzleSecretInput,
    time_lock_puzzle_param: TimeLockPuzzleParam,
) -> Vec<u8> {
    let key_validation_param = KeyValidationParam {
        n: time_lock_puzzle_param.n.clone(),
    };
    let key_validation_public_input = KeyValidationPublicInput {
        k_two: time_lock_puzzle_public_input.k_two.clone(),
        k_hash_value: time_lock_puzzle_public_input.k_hash_value.clone(),
    };
    let key_validation_secret_input = KeyValidationSecretInput {
        k: time_lock_puzzle_secret_input.k.clone(),
    };

    let proof = prove_key_validity(
        &param,
        &proving_key,
        &key_validation_param,
        &key_validation_public_input,
        &key_validation_secret_input,
    );

    proof
}

pub fn verify_time_lock_puzzle_zkp(
    param: &ParamsKZG<Bn256>,
    verifying_key: &VerifyingKey<G1Affine>,
    time_lock_puzzle_public_input: &TimeLockPuzzlePublicInput,
    time_lock_puzzle_param: &TimeLockPuzzleParam,
    proof: &[u8],
) -> bool {
    let sigma_protocol_public_input = SigmaProtocolPublicInput {
        r1: time_lock_puzzle_public_input.r1.clone(),
        r2: time_lock_puzzle_public_input.r2.clone(),
        z: time_lock_puzzle_public_input.z.clone(),
        o: time_lock_puzzle_public_input.o.clone(),
        k_two: time_lock_puzzle_public_input.k_two.clone(),
    };
    let sigma_protocol_param = SigmaProtocolParam {
        n: time_lock_puzzle_param.n.clone(),
        g: time_lock_puzzle_param.g.clone(),
        y_two: time_lock_puzzle_param.y_two.clone(),
    };

    let is_valid = verify_sigma_protocol(&sigma_protocol_public_input, &sigma_protocol_param);

    if !is_valid {
        return false;
    }

    let key_validation_public_input = KeyValidationPublicInput {
        k_two: time_lock_puzzle_public_input.k_two.clone(),
        k_hash_value: time_lock_puzzle_public_input.k_hash_value.clone(),
    };

    verify_key_validity_zkp(&param, &verifying_key, &key_validation_public_input, &proof)
}

pub fn generate_time_lock_puzzle(
    time_lock_puzzle_param: TimeLockPuzzleParam,
) -> (
    SigmaProtocolPublicInput,
    KeyValidationParam,
    KeyValidationPublicInput,
    KeyValidationSecretInput,
) {
    let g = time_lock_puzzle_param.g.clone();
    let n = time_lock_puzzle_param.n.clone();
    let y = time_lock_puzzle_param.y.clone();
    let y_two = time_lock_puzzle_param.y_two.clone();

    let r = thread_rng().sample::<BigUint, _>(RandomBits::new(128));
    let s = thread_rng().sample::<BigUint, _>(RandomBits::new(128));

    // Generate sigma protocol public input
    let sigma_protocol_param = SigmaProtocolParam {
        n: n.clone(),
        g: g.clone(),
        y_two: y_two.clone(),
    };
    let sigma_protocol_public_input =
        generate_sigma_protocol_public_input(&sigma_protocol_param, &r, &s);

    // k = y^s mod n
    let k = y.modpow(&s, &n);
    let k_two = y_two.modpow(&s, &n);
    let k_hash_value: HashValue = hash(k.clone());

    // Generate key validation param & public & secret input
    let key_validation_param = KeyValidationParam { n: n.clone() };
    let key_validation_public_input = KeyValidationPublicInput {
        k_two: k_two.clone(),
        k_hash_value: k_hash_value.clone(),
    };
    let key_validation_secret_input = KeyValidationSecretInput { k: k.clone() };

    (
        sigma_protocol_public_input,
        key_validation_param,
        key_validation_public_input,
        key_validation_secret_input,
    )
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn setup_and_export_test() {
        let data_dir = "./public/data/";
        let param_file_path = data_dir.to_owned() + "time_lock_puzzle_param.json";

        let time_lock_puzzle_param = generate_time_lock_puzzle_param(2048);

        export_time_lock_puzzle_param(&param_file_path, time_lock_puzzle_param);
    }

    #[test]
    pub fn load_test() {
        let data_dir = "./public/data/";
        let param_file_path = data_dir.to_owned() + "time_lock_puzzle_param.json";

        let time_lock_puzzle_param = import_time_lock_puzzle_param(&param_file_path);

        println!("{:?}", time_lock_puzzle_param);
    }
}
