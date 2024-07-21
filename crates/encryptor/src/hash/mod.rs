use halo2_proofs::halo2curves::bn256::Fr;
use maingate::{big_to_fe, decompose_big};
use num_bigint::BigUint;

pub mod chip;
pub mod types;

pub use types::*;

use crate::chip::{FULL_ROUND, PARTIAL_ROUND};
use crate::encryptor::Encryptor;

pub const BITS_LEN: usize = 2048;
pub const LIMB_WIDTH: usize = 64;
pub const LIMB_COUNT: usize = BITS_LEN / LIMB_WIDTH;

pub const T: usize = 5; // The number of fields.
pub const RATE: usize = 4; // Rate

pub fn hash(value: BigUint) -> HashValue {
    let mut hasher = Encryptor::<Fr, T, RATE>::new_hash(FULL_ROUND, PARTIAL_ROUND);

    let base1: Fr = big_to_fe(BigUint::from(
        2_u128.pow((LIMB_WIDTH as u128).try_into().unwrap()),
    ));
    let base2: Fr = base1 * base1;

    let k_limbs = decompose_big::<Fr>(value, LIMB_COUNT, LIMB_WIDTH);

    // Remove limb counts with grouping (3) (LIMB_COUNT: 32 -> 11)
    for i in 0..(LIMB_COUNT / 3) {
        let mut a_poly = k_limbs[3 * i];

        a_poly += base1 * k_limbs[3 * i + 1];
        a_poly += base2 * k_limbs[3 * i + 2];

        hasher.update(&[a_poly]);
    }

    // apply with remaining limbs
    let mut a_poly = k_limbs[30];
    a_poly += base1 * k_limbs[31];

    let e = a_poly;
    hasher.update(&[e]);

    let hashed = hasher.squeeze(1);

    HashValue::new([hashed[1].to_bytes(), hashed[2].to_bytes()])
}
