use halo2_proofs::halo2curves::bn256::{self, Fr};
use maingate::{big_to_fe, fe_to_big};
use num_bigint::BigUint;
use poseidon::encryption::cipher::{data_to_slices, encrypted_str_to_fr_slices, PoseidonCipher};
use poseidon::hash::types::PoseidonHashValue;

pub fn encrypt(data: &str, encryption_key: &PoseidonHashValue) -> String {
    let data_slices = data_to_slices(data);
    let fr_slices: Vec<Fr> = data_slices
        .into_iter()
        .map(|s| {
            let s_big = BigUint::from_bytes_be(s.as_bytes());
            big_to_fe(s_big)
        })
        .collect();

    let mut cipher = PoseidonCipher::<bn256::Fr, 8, 57, 5, 4>::new();

    let encryption_key = [
        Fr::from_bytes(encryption_key.get(0)).unwrap(),
        Fr::from_bytes(encryption_key.get(1)).unwrap(),
    ];

    let fr_slices = fr_slices.as_slice();

    let encrypted_data = cipher.encrypt(fr_slices, &encryption_key).unwrap();

    let encrypted_data_str: Vec<String> = encrypted_data
        .into_iter()
        .map(|s| {
            let fr_big = fe_to_big(s);
            fr_big.to_string()
        })
        .collect();

    encrypted_data_str.as_slice().join(",")
}

pub fn decrypt(encrypted_data: &str, decryption_key: &PoseidonHashValue) -> String {
    let encrypted_data = encrypted_str_to_fr_slices(encrypted_data);

    let mut cipher = PoseidonCipher::<bn256::Fr, 8, 57, 5, 4>::new();
    let decryption_key = [
        Fr::from_bytes(decryption_key.get(0)).unwrap(),
        Fr::from_bytes(decryption_key.get(1)).unwrap(),
    ];

    let plain_text_slice = cipher.decrypt(&encrypted_data, &decryption_key).unwrap();

    let plain_text_vec: Vec<String> = plain_text_slice
        .into_iter()
        .map(|s| {
            let s_big = fe_to_big(s);
            let mut s_bytes = s_big.to_bytes_be();
            if s_bytes.last() == Some(&0) {
                s_bytes.pop();
            }
            String::from_utf8(s_bytes).unwrap()
        })
        .collect();

    plain_text_vec.join("")
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use halo2_proofs::halo2curves::bn256::Fr;
    use poseidon::hash::types::PoseidonHashValue;

    #[test]
    fn encrypt_end_decrypt_test() {
        let data = "123";
        let hash_value = PoseidonHashValue::new([Fr::ONE.into(); 2]);

        let encrypted_data = super::encrypt(data, &hash_value);
        let decrypted_data = super::decrypt(&encrypted_data, &hash_value);

        assert!(data == decrypted_data)
    }
}
