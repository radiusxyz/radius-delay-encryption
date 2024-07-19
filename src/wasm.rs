use std::io::BufReader;
use std::str::FromStr;

use encryptor::hash::hash;
use encryptor::hash::types::HashValue;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::plonk::{ProvingKey, VerifyingKey};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::SerdeFormat;
use js_sys::Uint8Array;
use num_bigint::BigUint;
use serde_wasm_bindgen::{self, from_value};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

use crate::encryption::encryption::{decrypt as decryptor, encrypt as encryptor};
use crate::encryption::encryption_circuit::EncryptionCircuit;
use crate::encryption::encryption_zkp::{
    prove as prove_encryption_zkp, verify as verify_encryption_zkp, EncryptionPublicInput,
    EncryptionSecretInput,
};
use crate::time_lock_puzzle::key_validation_circuit::KeyValidationCircuit;
use crate::time_lock_puzzle::{
    generate_time_lock_puzzle as generate_tlp,
    generate_time_lock_puzzle_param as generate_tlp_param, get_decryption_key as get_key,
    prove_time_lock_puzzle as prove_tlp, solve_time_lock_puzzle as solve_tlp,
    verify_time_lock_puzzle_proof as verify_tlp_proof, TimeLockPuzzleParam,
    TimeLockPuzzlePublicInput, TimeLockPuzzleSecretInput,
};

// ================== Time-Lock Puzzle ================ //
#[wasm_bindgen]
pub fn generate_time_lock_puzzle_param(t: JsValue) -> JsValue {
    let t: u32 = serde_wasm_bindgen::from_value(t).unwrap();

    let time_lock_puzzle_param = generate_tlp_param(t);

    serde_wasm_bindgen::to_value(&time_lock_puzzle_param).unwrap()
}

#[wasm_bindgen]
pub fn generate_time_lock_puzzle(time_lock_puzzle_param: JsValue) -> JsValue {
    let time_lock_puzzle_param: TimeLockPuzzleParam =
        serde_wasm_bindgen::from_value(time_lock_puzzle_param).unwrap();

    let time_lock_puzzle_inputs = generate_tlp(time_lock_puzzle_param);

    serde_wasm_bindgen::to_value(&time_lock_puzzle_inputs).unwrap()
}

#[wasm_bindgen]
pub fn prove_time_lock_puzzle(
    time_lock_puzzle_zkp_param: JsValue,
    time_lock_puzzle_zkp_proving_key: JsValue,
    time_lock_puzzle_public_input: JsValue,
    time_lock_puzzle_secret_input: JsValue,
    time_lock_puzzle_param: JsValue,
) -> JsValue {
    let time_lock_puzzle_public_input: TimeLockPuzzlePublicInput =
        serde_wasm_bindgen::from_value(time_lock_puzzle_public_input).unwrap();
    let time_lock_puzzle_secret_input: TimeLockPuzzleSecretInput =
        serde_wasm_bindgen::from_value(time_lock_puzzle_secret_input).unwrap();
    let time_lock_puzzle_param: TimeLockPuzzleParam =
        serde_wasm_bindgen::from_value(time_lock_puzzle_param).unwrap();

    let time_lock_puzzle_zkp_param_vec = Uint8Array::new(&time_lock_puzzle_zkp_param).to_vec();
    let time_lock_puzzle_zkp_param =
        ParamsKZG::<Bn256>::read(&mut BufReader::new(&time_lock_puzzle_zkp_param_vec[..])).unwrap();

    let time_lock_puzzle_zkp_proving_key_vec =
        Uint8Array::new(&time_lock_puzzle_zkp_proving_key).to_vec();

    let time_lock_puzzle_zkp_proving_key =
        ProvingKey::<G1Affine>::read::<BufReader<_>, KeyValidationCircuit<Fr, 5, 4>>(
            &mut BufReader::new(&time_lock_puzzle_zkp_proving_key_vec[..]),
            SerdeFormat::RawBytes,
        )
        .expect("Failed to read proving_key");

    let proof = prove_tlp(
        &time_lock_puzzle_zkp_param,
        &time_lock_puzzle_zkp_proving_key,
        time_lock_puzzle_public_input,
        time_lock_puzzle_secret_input,
        time_lock_puzzle_param,
    );

    serde_wasm_bindgen::to_value(&proof).unwrap()
}

#[wasm_bindgen]
pub fn verify_time_lock_puzzle_proof(
    time_lock_puzzle_zkp_param: JsValue,
    time_lock_puzzle_zkp_verifying_key: JsValue,
    time_lock_puzzle_public_input: JsValue,
    time_lock_puzzle_param: JsValue,
    time_lock_puzzle_proof: JsValue,
) -> bool {
    let time_lock_puzzle_public_input: TimeLockPuzzlePublicInput =
        serde_wasm_bindgen::from_value(time_lock_puzzle_public_input).unwrap();
    let time_lock_puzzle_param: TimeLockPuzzleParam =
        serde_wasm_bindgen::from_value(time_lock_puzzle_param).unwrap();

    let time_lock_puzzle_proof = Uint8Array::new(&time_lock_puzzle_proof).to_vec();

    let time_lock_puzzle_zkp_param_vec = Uint8Array::new(&time_lock_puzzle_zkp_param).to_vec();
    let time_lock_puzzle_zkp_param =
        ParamsKZG::<Bn256>::read(&mut BufReader::new(&time_lock_puzzle_zkp_param_vec[..])).unwrap();

    let time_lock_puzzle_zkp_verifying_key_vec =
        Uint8Array::new(&time_lock_puzzle_zkp_verifying_key).to_vec();
    let time_lock_puzzle_zkp_verifying_key =
        VerifyingKey::<G1Affine>::read::<BufReader<_>, KeyValidationCircuit<Fr, 5, 4>>(
            &mut BufReader::new(&time_lock_puzzle_zkp_verifying_key_vec[..]),
            SerdeFormat::RawBytes,
        )
        .expect("Failed to read time_lock_puzzle_zkp_verifying_key");

    verify_tlp_proof(
        &time_lock_puzzle_zkp_param,
        &time_lock_puzzle_zkp_verifying_key,
        &time_lock_puzzle_public_input,
        &time_lock_puzzle_param,
        &time_lock_puzzle_proof,
    )
}

#[wasm_bindgen]
pub fn solve_time_lock_puzzle(o: JsValue, t: JsValue, n: JsValue) -> JsValue {
    let o = from_value::<BigUint>(o).unwrap();
    let t = from_value::<u32>(t).unwrap();
    let n = from_value::<BigUint>(n).unwrap();

    let k = solve_tlp(o, t, n);

    serde_wasm_bindgen::to_value(&k).unwrap()
}

#[wasm_bindgen]
pub fn generate_symmetric_key(k: JsValue) -> JsValue {
    let k = from_value::<BigUint>(k).unwrap();

    let hash_value = hash(k);

    serde_wasm_bindgen::to_value(&hash_value).unwrap()
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
pub fn verify_encryption_proof(
    param: JsValue,
    verifying_key: JsValue,
    encryption_public_input: JsValue,
    proof: JsValue,
) -> bool {
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
pub fn encrypt(data: &str, encrypt: JsValue) -> JsValue {
    let encrypt: HashValue = serde_wasm_bindgen::from_value(encrypt).unwrap();

    let encrypted_data = encryptor(data, &encrypt);

    serde_wasm_bindgen::to_value(&encrypted_data).unwrap()
}

#[wasm_bindgen]
pub fn decrypt(encrypted_data: &str, hash_value: JsValue) -> JsValue {
    let hash_value: HashValue = serde_wasm_bindgen::from_value(hash_value).unwrap();

    let raw_data = decryptor(encrypted_data, &hash_value);

    serde_wasm_bindgen::to_value(&raw_data).unwrap()
}
//=============================================//
