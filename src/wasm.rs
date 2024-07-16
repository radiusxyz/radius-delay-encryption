use std::io::BufReader;
use std::str::FromStr;

use encryptor::hash::hash;
use encryptor::hash::types::HashValue;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::plonk::{ProvingKey, VerifyingKey};
use halo2_proofs::poly::commitment::Params; /* Zeroknight : without it, ParamsKZG::Read error!! */
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::SerdeFormat;
use js_sys::Uint8Array;
use num_bigint::BigUint;
use serde_wasm_bindgen::{self, from_value};
//= WASM =//
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

use crate::encryption::poseidon_encryption::{decrypt as decryptor, encrypt as encryptor};
use crate::encryption::poseidon_encryption_circuit::PoseidonEncryptionCircuit as EncryptionCircuit;
use crate::encryption::poseidon_encryption_zkp::{
    prove as prove_encryption_zkp, verify as verify_encryption_zkp,
    PoseidonEncryptionPublicInput as EncryptionPublicInput,
    PoseidonEncryptionSecretInput as EncryptionSecretInput,
};
use crate::time_lock_puzzle::key_validation_circuit::KeyValidationCircuit;
use crate::time_lock_puzzle::key_validation_zkp::{
    prove as prove_valid_time_lock_puzzle_zkp, verify as verify_valid_time_lock_puzzle_zkp,
    KeyValidationParam, KeyValidationPublicInput, KeyValidationSecretInput,
};
use crate::time_lock_puzzle::sigma_protocol::{
    get_c, verify as verify_sigma_protocol, SigmaProtocolParam, SigmaProtocolPublicInput,
};
use crate::time_lock_puzzle::{
    setup as setup_time_lock_puzzle, TimeLockPuzzleParam, TimeLockPuzzlePublicInput,
    TimeLockPuzzleSecretInput,
};

const BITS_LEN: usize = 2048;

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    // The `console.log` is quite polymorphic, so we can bind it with multiple
    // signatures. Note that we need to use `js_name` to ensure we always call
    // `log` in JS.
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_u32(a: u32);

    // Multiple arguments too!
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn log_many(a: &str, b: &str);
}

#[wasm_bindgen]
pub fn str_to_big_uint(value: &str) -> JsValue {
    let value = BigUint::from_str(value).unwrap();

    serde_wasm_bindgen::to_value(&value).unwrap()
}

#[wasm_bindgen]
pub fn random_big_uint(bits: u64) -> JsValue {
    let random_value = thread_rng().sample::<BigUint, _>(RandomBits::new(bits));

    serde_wasm_bindgen::to_value(&random_value).unwrap()
}

#[wasm_bindgen]
pub fn generate_k(n: JsValue) -> JsValue {
    // param
    let n = from_value::<BigUint>(n).unwrap();
    log(n.to_string().as_str());

    let mut rng = thread_rng();
    let k = rng.sample::<BigUint, _>(RandomBits::new(BITS_LEN as u64)) % &n;
    log(k.to_string().as_str());

    serde_wasm_bindgen::to_value(&k).unwrap()
}

#[wasm_bindgen]
pub fn calculate_k_two(k: JsValue, n: JsValue) -> JsValue {
    // param
    let n = from_value::<BigUint>(n).unwrap();
    let k = from_value::<BigUint>(k).unwrap();

    let k_two = big_pow_mod(&k, &BigUint::from_str("2").unwrap(), &n);

    serde_wasm_bindgen::to_value(&k_two).unwrap()
}

#[wasm_bindgen]
pub fn calculate_hash(k: JsValue) -> JsValue {
    let k = from_value::<BigUint>(k).unwrap();

    let hash_value = hash(k);

    serde_wasm_bindgen::to_value(&hash_value).unwrap()
}

#[wasm_bindgen]
pub fn generate_params_for_making_time_lock_puzzle(t: JsValue) -> JsValue {
    let t = from_value::<u32>(t).unwrap();

    let time_lock_puzzle_params = setup_time_lock_puzzle(t);

    serde_wasm_bindgen::to_value(&time_lock_puzzle_params).unwrap()
}

#[wasm_bindgen]
pub fn get_time_lock_puzzle_public_input(
    k: JsValue,
    g: JsValue,
    n: JsValue,
    y_two: JsValue,
) -> JsValue {
    let k = from_value::<BigUint>(k).unwrap();
    let g = from_value::<BigUint>(g).unwrap();
    let n = from_value::<BigUint>(n).unwrap();
    let y_two = from_value::<BigUint>(y_two).unwrap();

    let r = thread_rng().sample::<BigUint, _>(RandomBits::new(128));
    let s = thread_rng().sample::<BigUint, _>(RandomBits::new(128));

    let r1 = g.modpow(&r, &n);
    let r2 = y_two.modpow(&r, &n);
    let c = get_c(r1.clone(), r2.clone());

    let z = &r + &s * &c;
    let o = g.modpow(&s, &n);
    let k_two = y_two.modpow(&s, &n);

    let k_hash_value = hash(k.clone());

    let time_lock_puzzle_public_input = TimeLockPuzzlePublicInput {
        r1,
        r2,
        z,
        o,
        k_two,
        k_hash_value,
    };

    serde_wasm_bindgen::to_value(&time_lock_puzzle_public_input).unwrap()
}

#[wasm_bindgen]
pub fn prove_time_lock_puzzle(
    param: JsValue,
    proving_key: JsValue,
    time_lock_puzzle_public_input: JsValue,
    time_lock_puzzle_secret_input: JsValue,
    time_lock_puzzle_param: JsValue,
) -> JsValue {
    log("stompesi - 1");
    // Convert JsValue to Rust struct
    let time_lock_puzzle_public_input: TimeLockPuzzlePublicInput =
        serde_wasm_bindgen::from_value(time_lock_puzzle_public_input).unwrap();
    let time_lock_puzzle_secret_input: TimeLockPuzzleSecretInput =
        serde_wasm_bindgen::from_value(time_lock_puzzle_secret_input).unwrap();
    let time_lock_puzzle_param: TimeLockPuzzleParam =
        serde_wasm_bindgen::from_value(time_lock_puzzle_param).unwrap();

    log("stompesi - 2");
    let param_vec = Uint8Array::new(&param).to_vec();
    let param = ParamsKZG::<Bn256>::read(&mut BufReader::new(&param_vec[..])).unwrap();

    log("stompesi - 3");
    let proving_key_vec = Uint8Array::new(&proving_key).to_vec();

    log("stompesi - 4");
    let proving_key = ProvingKey::<G1Affine>::read::<BufReader<_>, KeyValidationCircuit<Fr, 5, 4>>(
        &mut BufReader::new(&proving_key_vec[..]),
        SerdeFormat::RawBytes,
    )
    .expect("Failed to read proving_key");

    log("stompesi - 5");
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

    let proof = prove_valid_time_lock_puzzle_zkp(
        &param,
        &proving_key,
        &key_validation_param,
        &key_validation_public_input,
        &key_validation_secret_input,
    );

    serde_wasm_bindgen::to_value(&proof).unwrap()
}

#[wasm_bindgen]
pub fn verify_time_lock_puzzle(
    param: JsValue,
    verifying_key: JsValue,
    time_lock_puzzle_public_input: JsValue,
    time_lock_puzzle_param: JsValue,
    proof: JsValue,
) -> bool {
    // Convert JsValue to Rust struct
    let time_lock_puzzle_public_input: TimeLockPuzzlePublicInput =
        serde_wasm_bindgen::from_value(time_lock_puzzle_public_input).unwrap();
    let time_lock_puzzle_param: TimeLockPuzzleParam =
        serde_wasm_bindgen::from_value(time_lock_puzzle_param).unwrap();

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

    let proof = Uint8Array::new(&proof).to_vec();

    let param_vec = Uint8Array::new(&param).to_vec();
    let param = ParamsKZG::<Bn256>::read(&mut BufReader::new(&param_vec[..])).unwrap();

    let verifying_key_vec = Uint8Array::new(&verifying_key).to_vec();
    let verifying_key =
        VerifyingKey::<G1Affine>::read::<BufReader<_>, KeyValidationCircuit<Fr, 5, 4>>(
            &mut BufReader::new(&verifying_key_vec[..]),
            SerdeFormat::RawBytes,
        )
        .expect("Failed to read verifying_key");

    let key_validation_public_input = KeyValidationPublicInput {
        k_two: time_lock_puzzle_public_input.k_two.clone(),
        k_hash_value: time_lock_puzzle_public_input.k_hash_value.clone(),
    };

    verify_valid_time_lock_puzzle_zkp(&param, &verifying_key, &key_validation_public_input, &proof)
}

#[wasm_bindgen]
pub fn solve_time_lock_puzzle(o: JsValue, t: JsValue, n: JsValue) -> JsValue {
    let two: BigUint = BigUint::from(2usize);
    let two_t: BigUint = two.pow(from_value::<u32>(t).unwrap());
    let o = from_value::<BigUint>(o).unwrap();
    let n = from_value::<BigUint>(n).unwrap();
    // k = o ^ (2^t)
    let k = o.modpow(&two_t, &n);
    serde_wasm_bindgen::to_value(&k).unwrap()
}

pub fn get_decryption_key(o: JsValue, t: JsValue, n: JsValue) -> JsValue {
    let k = solve_time_lock_puzzle(o, t, n);

    // Symmetric key from o
    let encryption_key = calculate_hash(k);

    encryption_key
}
// ====================================================== //

//================= Encryption =================//
#[wasm_bindgen]
pub fn prove_encryption(
    param: JsValue,
    proving_key: JsValue,
    encryption_public_input: JsValue,
    encryption_secret_input: JsValue,
) -> JsValue {
    // Convert JsValue to Rust struct
    let encryption_public_input: EncryptionPublicInput =
        serde_wasm_bindgen::from_value(encryption_public_input).unwrap();
    let encryption_secret_input: EncryptionSecretInput =
        serde_wasm_bindgen::from_value(encryption_secret_input).unwrap();

    let param_vec = Uint8Array::new(&param).to_vec();
    let param = ParamsKZG::<Bn256>::read(&mut BufReader::new(&param_vec[..])).unwrap();

    let proving_key_vec = Uint8Array::new(&proving_key).to_vec();
    let proving_key = ProvingKey::<G1Affine>::read::<BufReader<_>, EncryptionCircuit<Fr, 5, 4>>(
        &mut BufReader::new(&proving_key_vec[..]),
        SerdeFormat::RawBytes,
    )
    .expect("Failed to read proving_key");

    let proof = prove_encryption_zkp(
        &param,
        &proving_key,
        &encryption_public_input,
        &encryption_secret_input,
    );

    serde_wasm_bindgen::to_value(&proof).unwrap()
}

#[wasm_bindgen]
pub fn verify_encryption(
    param: JsValue,
    verifying_key: JsValue,
    encryption_public_input: JsValue,
    proof: JsValue,
) -> bool {
    // Convert JsValue to Rust struct
    let encryption_public_input: EncryptionPublicInput =
        serde_wasm_bindgen::from_value(encryption_public_input).unwrap();

    let proof = Uint8Array::new(&proof).to_vec();

    let param_vec = Uint8Array::new(&param).to_vec();
    let param = ParamsKZG::<Bn256>::read(&mut BufReader::new(&param_vec[..])).unwrap();

    let verifying_key_vec = Uint8Array::new(&verifying_key).to_vec();
    let verifying_key =
        VerifyingKey::<G1Affine>::read::<BufReader<_>, EncryptionCircuit<Fr, 5, 4>>(
            &mut BufReader::new(&verifying_key_vec[..]),
            SerdeFormat::RawBytes,
        )
        .expect("Failed to read verifying_key");

    verify_encryption_zkp(&param, &verifying_key, &encryption_public_input, &proof)
}
//=============================================//

//================ Encrypt & Decrypt ==========//
#[wasm_bindgen]
pub fn encrypt(data: &str, hash_value: JsValue) -> JsValue {
    let hash_value: HashValue = serde_wasm_bindgen::from_value(hash_value).unwrap();

    let encrypted_data = encryptor(data, &hash_value);

    serde_wasm_bindgen::to_value(&encrypted_data).unwrap()
}

#[wasm_bindgen]
pub fn decrypt(encrypted_data: &str, hash_value: JsValue) -> JsValue {
    let hash_value: HashValue = serde_wasm_bindgen::from_value(hash_value).unwrap();

    let raw_data = decryptor(encrypted_data, &hash_value);

    serde_wasm_bindgen::to_value(&raw_data).unwrap()
}
//=============================================//

// ================== Utils ================ //
#[wasm_bindgen]
pub fn check_hash(k: JsValue, check_hash_value: JsValue) -> bool {
    let check_hash_value: HashValue = serde_wasm_bindgen::from_value(check_hash_value).unwrap();

    let k = from_value::<BigUint>(k).unwrap();
    let hash_value = hash(k);

    return check_hash_value.get(0) == hash_value.get(0)
        && check_hash_value.get(1) == hash_value.get(1);
}
// ========================================= //
