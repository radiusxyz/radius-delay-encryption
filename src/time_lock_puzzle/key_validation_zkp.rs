use std::fs::File;
use std::io::BufReader;

use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, VerifyingKey,
};
use halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
use halo2_proofs::poly::kzg::strategy::AccumulatorStrategy;
use halo2_proofs::poly::VerificationStrategy;
use halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};
use halo2_proofs::SerdeFormat;
use maingate::decompose_big;
use num_bigint::BigUint;
use poseidon::chip::{FULL_ROUND, PARTIAL_ROUND};
use poseidon::hash::types::PoseidonHashValue;
use poseidon::spec::Spec;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use super::key_validation_circuit::KeyValidationCircuit;
use super::{LIMB_COUNT, LIMB_WIDTH, RATE, T};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyValidationPublicInput {
    pub k_two: BigUint,
    pub k_hash_value: PoseidonHashValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyValidationSecretInput {
    pub k: BigUint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyValidationParam {
    pub n: BigUint,
}

pub fn export_proving_key(file_path: &str, proving_key: ProvingKey<G1Affine>) {
    let mut proving_key_buf = Vec::new();
    let _ = proving_key.write(&mut proving_key_buf, SerdeFormat::RawBytes);

    std::fs::write(file_path, proving_key_buf).expect("Failed to write proving key");
}

pub fn export_verifying_key(file_path: &str, verifying_key: VerifyingKey<G1Affine>) {
    let mut verifying_key_buf = Vec::new();
    let _ = verifying_key.write(&mut verifying_key_buf, SerdeFormat::RawBytes);

    std::fs::write(file_path, verifying_key_buf).expect("Failed to write verifying key");
}

pub fn export_zkp_param(file_path: &str, param: ParamsKZG<Bn256>) {
    let mut param_buf = Vec::<u8>::new();
    param.write(&mut param_buf).expect("Failed to write param");

    std::fs::write(file_path, param_buf).expect("Failed to write param");
}

pub fn import_proving_key(file_path: &str) -> ProvingKey<G1Affine> {
    let proving_key_file = File::open(file_path).expect("Failed to load proving_key_file");

    ProvingKey::<G1Affine>::read::<BufReader<File>, KeyValidationCircuit<Fr, T, RATE>>(
        &mut BufReader::new(proving_key_file),
        SerdeFormat::RawBytes,
    )
    .expect("Failed to read pk")
}

pub fn import_verifying_key(file_path: &str) -> VerifyingKey<G1Affine> {
    let verifying_key_file = File::open(file_path).expect("Failed to load verifying_file_path");

    VerifyingKey::<G1Affine>::read::<BufReader<File>, KeyValidationCircuit<Fr, T, RATE>>(
        &mut BufReader::new(verifying_key_file),
        SerdeFormat::RawBytes,
    )
    .expect("Failed to read vk")
}

pub fn import_zkp_param(file_path: &str) -> ParamsKZG<Bn256> {
    let param_file = File::open(file_path).expect("Failed to load param");

    ParamsKZG::read::<_>(&mut BufReader::new(param_file)).expect("Failed to read param")
}

pub fn load() -> (
    ParamsKZG<Bn256>,
    ProvingKey<G1Affine>,
    VerifyingKey<G1Affine>,
) {
    let data_dir = "./public/data/";
    let param_file_path = data_dir.to_owned() + "key_validation_zkp_param.data";
    let proving_key_file_path = data_dir.to_owned() + "key_validation_proving_key.data";
    let verifying_key_file_path = data_dir.to_owned() + "key_validation_verifying_key.data";

    let param = import_zkp_param(&param_file_path);
    let proving_key = import_proving_key(&proving_key_file_path);
    let verifying_key = import_verifying_key(&verifying_key_file_path);

    (param, proving_key, verifying_key)
}

pub fn setup(
    k: u32,
) -> (
    ParamsKZG<Bn256>,
    VerifyingKey<G1Affine>,
    ProvingKey<G1Affine>,
) {
    let param = ParamsKZG::<Bn256>::setup(k, OsRng);

    let circuit = KeyValidationCircuit::<Fr, T, RATE>::create_empty_circuit();

    let verifying_key = keygen_vk(&param, &circuit.clone()).expect("keygen_vk failed");

    let proving_key =
        keygen_pk(&param, verifying_key.clone(), &circuit.clone()).expect("keygen_pk failed");

    (param, verifying_key, proving_key)
}

pub fn prove(
    param: &ParamsKZG<Bn256>,
    proving_key: &ProvingKey<G1Affine>,
    key_validation_param: &KeyValidationParam,
    key_validation_public_input: &KeyValidationPublicInput,
    key_validation_secret_input: &KeyValidationSecretInput,
) -> Vec<u8> {
    let mut public_inputs = decompose_big::<Fr>(
        key_validation_public_input.k_two.clone(),
        LIMB_COUNT,
        LIMB_WIDTH,
    );
    public_inputs.push(Fr::from_bytes(key_validation_public_input.k_hash_value.get(0)).unwrap());
    public_inputs.push(Fr::from_bytes(key_validation_public_input.k_hash_value.get(1)).unwrap());

    // circuit
    let spec = Spec::<Fr, T, RATE>::new(FULL_ROUND, PARTIAL_ROUND);
    let circuit = KeyValidationCircuit::<Fr, T, RATE> {
        n: key_validation_param.n.clone(),
        k: key_validation_secret_input.k.clone(),
        spec: spec.clone(),
    };

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, _, _>(
        param,
        proving_key,
        &[circuit.clone()],
        &[&[&public_inputs]],
        &mut OsRng,
        &mut transcript,
    )
    .expect("Proof generation failed");

    transcript.finalize()
}

pub fn verify(
    param: &ParamsKZG<Bn256>,
    verifying_key: &VerifyingKey<G1Affine>,
    key_validation_public_input: &KeyValidationPublicInput,
    proof: &[u8],
) -> bool {
    let mut public_inputs = decompose_big::<Fr>(
        key_validation_public_input.k_two.clone(),
        LIMB_COUNT,
        LIMB_WIDTH,
    );
    public_inputs.push(Fr::from_bytes(key_validation_public_input.k_hash_value.get(0)).unwrap());
    public_inputs.push(Fr::from_bytes(key_validation_public_input.k_hash_value.get(1)).unwrap());

    let mut transcript: Blake2bRead<&[u8], _, Challenge255<_>> =
        TranscriptReadBuffer::<_, G1Affine, _>::init(proof);

    let verifier_param = param.verifier_params();

    VerificationStrategy::<_, VerifierGWC<_>>::finalize(
        verify_proof::<_, VerifierGWC<_>, _, _, _>(
            verifier_param,
            verifying_key,
            AccumulatorStrategy::new(verifier_param),
            &[&[&public_inputs[..]]],
            &mut transcript,
        )
        .unwrap(),
    )
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use num_bigint::RandomBits;
    use poseidon::hash;
    use rand::{thread_rng, Rng};

    use super::*;
    use crate::time_lock_puzzle::N;

    #[test]
    pub fn setup_and_export_test() {
        let data_dir = "./public/data/";
        let param_file_path = data_dir.to_owned() + "key_validation_zkp_param.data";
        let proving_key_file_path = data_dir.to_owned() + "key_validation_proving_key.data";
        let verifying_key_file_path = data_dir.to_owned() + "key_validation_verifying_key.data";

        let (param, verifying_key, proving_key) = setup(13);

        export_zkp_param(&param_file_path, param);
        export_proving_key(&proving_key_file_path, proving_key);
        export_verifying_key(&verifying_key_file_path, verifying_key);
    }

    #[test]
    pub fn verify_valid_test() {
        println!("Loading...");
        let (param, proving_key, verifying_key) = load();
        println!("Loaded!");

        let g = BigUint::from_str("5").unwrap();
        let n = BigUint::from_str(N).unwrap();
        let t = 2048;

        // y = g^{2^t}
        let mut y = g.clone();
        for _ in 0..t {
            y = (&y * &y) % &n;
        }

        let y_two: BigUint = (&y * &y) % &n;

        let s = thread_rng().sample::<BigUint, _>(RandomBits::new(128));

        let k = y.modpow(&s, &n);
        let k_two = y_two.modpow(&s, &n);

        let k_hash_value = hash::hash(k.clone());

        let key_validation_param = KeyValidationParam { n };
        let key_validation_public_input = KeyValidationPublicInput {
            k_two: k_two.clone(),
            k_hash_value,
        };
        let key_validation_secret_input = KeyValidationSecretInput { k };

        println!("Proving...");
        let proof = prove(
            &param,
            &proving_key,
            &key_validation_param,
            &key_validation_public_input,
            &key_validation_secret_input,
        );
        println!("Proved!");

        println!("Verifying...");
        let is_valid = verify(&param, &verifying_key, &key_validation_public_input, &proof);
        println!("Verified!");

        println!("is_valid : {:?}", is_valid);
    }

    #[test]
    pub fn verify_invalid_test() {
        println!("Loading...");
        let (param, proving_key, verifying_key) = load();
        println!("Loaded!");

        let g = BigUint::from_str("5").unwrap();
        let n = BigUint::from_str(N).unwrap();

        let mut y = g.clone();
        for _ in 0..2048 {
            y = &y * &y % &n;
        }

        let y_two: BigUint = &y * &y % &n;

        let s = thread_rng().sample::<BigUint, _>(RandomBits::new(128));

        let k = y.modpow(&s, &n);
        let k_two = y_two.modpow(&s, &n);
        let k_hash_value = hash::hash(k.clone());

        let key_validation_param = KeyValidationParam { n };
        let key_validation_public_input = KeyValidationPublicInput {
            k_two: k_two.clone(),
            k_hash_value,
        };
        let key_validation_secret_input = KeyValidationSecretInput { k };

        println!("Proving...");
        let proof = prove(
            &param,
            &proving_key,
            &key_validation_param,
            &key_validation_public_input,
            &key_validation_secret_input,
        );
        println!("Proved!");

        // It is invalid
        let k_two = thread_rng().sample::<BigUint, _>(RandomBits::new(128));
        let k_hash_value = hash::hash(k_two.clone());
        let key_validation_public_input = KeyValidationPublicInput {
            k_two: k_two.clone(),
            k_hash_value,
        };

        println!("Verifying...");
        let is_valid = verify(&param, &verifying_key, &key_validation_public_input, &proof);
        println!("Verified!");

        println!("is_valid : {:?}", is_valid);
    }
}
