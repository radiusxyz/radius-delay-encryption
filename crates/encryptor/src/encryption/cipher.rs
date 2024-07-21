use ff::{FromUniformBytes, PrimeField};
use halo2_proofs::halo2curves::bn256::Fr;
use maingate::big_to_fe;
use num_bigint::BigUint;
use rand_core::Error;

use crate::chip::{FULL_ROUND, PARTIAL_ROUND};
use crate::encryptor::Encryptor;

pub const MESSAGE_CAPACITY: usize = 11; // max 31
pub const CIPHER_SIZE: usize = MESSAGE_CAPACITY + 1;

#[derive(Debug, Clone, Copy)]
pub struct Cipher<
    F: PrimeField + FromUniformBytes<64>,
    const R_F: usize,
    const R_P: usize,
    const T: usize,
    const RATE: usize,
> {
    pub cipher_byte_size: usize,
    pub cipher: [F; CIPHER_SIZE],
}

impl<F, const R_F: usize, const R_P: usize, const T: usize, const RATE: usize> Default
    for Cipher<F, R_F, R_P, T, RATE>
where
    F: PrimeField + FromUniformBytes<64> + Default,
{
    fn default() -> Self {
        Cipher {
            cipher_byte_size: Default::default(),
            cipher: [F::default(); CIPHER_SIZE],
        }
    }
}

impl<F, const R_F: usize, const R_P: usize, const T: usize, const RATE: usize>
    Cipher<F, R_F, R_P, T, RATE>
where
    F: PrimeField + FromUniformBytes<64>,
{
    pub const fn new() -> Self {
        Self {
            cipher_byte_size: CIPHER_SIZE * (F::NUM_BITS as usize) / 8,
            cipher: [F::ZERO; CIPHER_SIZE],
        }
    }

    pub const fn capacity() -> usize {
        MESSAGE_CAPACITY
    }
    pub const fn cipher_size() -> usize {
        CIPHER_SIZE
    }

    pub fn initial_state(&self, nonce: F) -> [F; 3] {
        [F::ZERO, F::ZERO, nonce]
    }

    pub fn encrypt(
        &mut self,
        data: &[F],
        encryption_key: &[F; 2],
    ) -> Result<[F; CIPHER_SIZE], Error> {
        let mut encryptor = Encryptor::<F, T, RATE>::new_enc(
            FULL_ROUND,
            PARTIAL_ROUND,
            encryption_key[0],
            encryption_key[1],
        );

        let mut cipher = [F::ZERO; CIPHER_SIZE];

        // Permutation is update in Encryptor
        encryptor.update(&[]);
        encryptor.squeeze(0);

        let mut i = 0;

        for inputs in data.chunks(RATE) {
            for (word, input) in encryptor
                .state
                .words()
                .iter_mut()
                .skip(1)
                .zip(inputs.iter())
            {
                *word = word.add(input); // c = s + m, m = c - s
                if i < MESSAGE_CAPACITY {
                    // c_n = p(s+m) + m_n
                    cipher[i] = *word;
                    i += 1;
                }
            }

            encryptor.update(inputs);
            if inputs.len() < RATE {
                encryptor.squeeze(0);
            }
        }
        cipher[MESSAGE_CAPACITY] = encryptor.state.words()[1];

        self.cipher = cipher;

        Ok(cipher)
    }

    pub fn decrypt(
        &mut self,
        cipher: &[F; CIPHER_SIZE],
        decryption_key: &[F; 2],
    ) -> Result<[F; MESSAGE_CAPACITY], Error> {
        let mut decryptor = Encryptor::<F, T, RATE>::new_enc(
            FULL_ROUND,
            PARTIAL_ROUND,
            decryption_key[0],
            decryption_key[1],
        );

        decryptor.update(&[]);
        decryptor.squeeze(0);

        let mut data = [F::ZERO; MESSAGE_CAPACITY];
        let mut i = 0;

        let parity = cipher[MESSAGE_CAPACITY];

        for chunk in cipher[..MESSAGE_CAPACITY].chunks(RATE) {
            for (word, encrypted_word) in
                decryptor.state.words().iter_mut().skip(1).zip(chunk.iter())
            {
                if i < MESSAGE_CAPACITY {
                    data[i] = encrypted_word.sub(*word);
                    i += 1;
                }
            }
            let offset = i % RATE;
            if offset == 0 {
                decryptor.update(&data[i - RATE..i]);
            } else {
                decryptor.update(&data[i - offset..i]);
                decryptor.squeeze(0);
            }
        }

        if parity != decryptor.state.words()[1] {
            return Err(Error::new("Invalid cipher text"));
        }

        Ok(data)
    }
}

pub fn data_to_slices(data: &str) -> [&str; MESSAGE_CAPACITY] {
    // For preventing overflow (Filed element size is 32 bytes)
    let slice_size = 31;

    let mut slices = data
        .as_bytes()
        .chunks(slice_size)
        .map(std::str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .unwrap_or_else(|_| vec![]);

    // Resize the vector to contain exactly 11 elements
    slices.resize_with(MESSAGE_CAPACITY, Default::default);

    // Convert the vector to an array
    slices.try_into().unwrap_or_else(|v: Vec<&str>| {
        panic!(
            "Expected a Vec of length {} but it was {}",
            MESSAGE_CAPACITY,
            v.len()
        )
    })
}

pub fn str_slices_to_fr_slices(data_slices: [&str; MESSAGE_CAPACITY]) -> [Fr; MESSAGE_CAPACITY] {
    data_slices.map(|s| {
        let s_big = BigUint::from_bytes_be(s.as_bytes());
        big_to_fe(s_big)
    })
}

pub fn encrypted_str_to_fr_slices(encrypted_data: &str) -> [Fr; CIPHER_SIZE] {
    let encrypted_data_vec: Vec<Fr> = encrypted_data
        .split(',')
        .map(|s| {
            let s_big = BigUint::parse_bytes(s.as_bytes(), 10).unwrap();
            big_to_fe(s_big)
        })
        .collect();

    encrypted_data_vec
        .as_slice()
        .try_into()
        .expect("incorrect length of cipher_text")
}

#[cfg(test)]
mod tests {

    use ff::Field;
    use halo2_proofs::halo2curves::bn256::Fr;

    use crate::encryption::cipher::{Cipher, MESSAGE_CAPACITY};
    use crate::hash::types::HashValue;

    #[test]
    fn test_encryption() {
        let hash_value = HashValue::new([Fr::ONE.into(); 2]);

        let mut cipher = Cipher::<Fr, 8, 57, 5, 4>::new();
        let data = [Fr::default(); MESSAGE_CAPACITY];

        let symmetric_key = [
            Fr::from_bytes(hash_value.get(0)).unwrap(),
            Fr::from_bytes(hash_value.get(1)).unwrap(),
        ];

        println!("data: {:?}", data);

        let cipher_text = cipher.encrypt(&data, &symmetric_key).unwrap();
        println!("encrypted: {:?}", cipher_text);
        println!(
            "decrypted: {:?}",
            cipher.decrypt(&cipher_text, &symmetric_key).unwrap()
        );
    }
}
