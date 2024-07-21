use std::str::FromStr;

use encryptor::chip::{FULL_ROUND, PARTIAL_ROUND};
use encryptor::encryptor::Encryptor;
use halo2_proofs::halo2curves::bn256::Fr;
use maingate::{decompose_big, fe_to_big};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use super::{G, LIMB_COUNT, LIMB_WIDTH, N, RATE, T};

pub struct SigmaProtocolPublicInput {
    pub r1: BigUint,
    pub r2: BigUint,
    pub z: BigUint,
    pub o: BigUint,
    pub k_two: BigUint,
}

pub struct SigmaProtocolParam {
    pub n: BigUint,
    pub g: BigUint,
    pub y_two: BigUint,
}

pub fn setup(t: u32) -> SigmaProtocolParam {
    let g = BigUint::from_str(G).unwrap();
    let n = BigUint::from_str(N).unwrap();

    // y = g^{2^t}
    let mut y = g.clone();
    for _ in 0..t {
        y = (&y * &y) % &n;
    }

    let y_two: BigUint = (&y * &y) % &n;

    SigmaProtocolParam { n, g, y_two }
}

pub fn generate_sigma_protocol_public_input(
    sigma_protocol_param: &SigmaProtocolParam,
    r: &BigUint,
    s: &BigUint,
) -> SigmaProtocolPublicInput {
    // r1 = g^r mod n
    let r1 = sigma_protocol_param.g.modpow(r, &sigma_protocol_param.n);

    // r2 = y_two^r mod n
    let r2 = sigma_protocol_param
        .y_two
        .modpow(&r, &sigma_protocol_param.n);

    // c = H(r1, r2)
    let c = get_c(r1.clone(), r2.clone());

    // z = (r + s * c) mod n
    let z = (r + s * &c) % &sigma_protocol_param.n;

    // o = g^s mod n
    let o = sigma_protocol_param.g.modpow(s, &sigma_protocol_param.n);

    // k_two = y_two^s mod n
    let k_two = sigma_protocol_param
        .y_two
        .modpow(&s, &sigma_protocol_param.n);

    SigmaProtocolPublicInput {
        r1,
        r2,
        z,
        o,
        k_two,
    }
}

pub fn verify(
    sigma_protocol_public_input: &SigmaProtocolPublicInput,
    time_lock_puzzle_param: &SigmaProtocolParam,
) -> bool {
    let r1 = sigma_protocol_public_input.r1.clone();
    let r2 = sigma_protocol_public_input.r2.clone();
    let z = sigma_protocol_public_input.z.clone();
    let o = sigma_protocol_public_input.o.clone();
    let k_two = sigma_protocol_public_input.k_two.clone();

    let n = time_lock_puzzle_param.n.clone();
    let g = time_lock_puzzle_param.g.clone();
    let y_two = time_lock_puzzle_param.y_two.clone();

    // 1-1. c <- Hash (r_1, r_2);
    let c = get_c(
        sigma_protocol_public_input.r1.clone(),
        sigma_protocol_public_input.r2.clone(),
    );

    // 1-2. g^z = r_1 * o^c
    let left_side = g.modpow(&z, &n);
    let right_side = (r1 * (o.modpow(&c, &n))) % &n;

    if left_side != right_side {
        println!("Verification process of sigma 1-2 failed");
        return false;
    }

    // 1-3. (y^2)^2 = r_2 * (k^2)^c
    let left_side = y_two.modpow(&z, &n);
    let right_side = (r2.clone() * (k_two.modpow(&c, &n))) % &n;

    if left_side != right_side {
        println!("Verification process of sigma 1-3 failed");
        return false;
    }

    true
}

// c <- Hash (r_1, r_2);
pub fn get_c(r1: BigUint, r2: BigUint) -> BigUint {
    let mut hasher = Encryptor::<Fr, T, RATE>::new_hash(FULL_ROUND, PARTIAL_ROUND);

    let r1_limbs = decompose_big::<Fr>(r1, LIMB_COUNT, LIMB_WIDTH);
    hasher.update(&r1_limbs);

    let r2_limbs = decompose_big::<Fr>(r2, LIMB_COUNT, LIMB_WIDTH);
    hasher.update(&r2_limbs);

    let c_seq = hasher.squeeze(1);

    fe_to_big(c_seq[1])
}

#[cfg(test)]
mod tests {
    use num_bigint::RandomBits;
    use rand::{thread_rng, Rng};

    use super::*;

    #[test]
    pub fn verify_valid_test() {
        let sigma_protocol_param = setup(2048);

        let r = thread_rng().sample::<BigUint, _>(RandomBits::new(128));
        let s = thread_rng().sample::<BigUint, _>(RandomBits::new(128));

        let sigma_protocol_public_input =
            generate_sigma_protocol_public_input(&sigma_protocol_param, &r, &s);

        let is_valid = verify(&sigma_protocol_public_input, &sigma_protocol_param);

        println!("is_valid : {:?}", is_valid);
    }

    #[test]
    pub fn verify_invalid_test() {
        let sigma_protocol_param = setup(2048);

        let r = thread_rng().sample::<BigUint, _>(RandomBits::new(128));
        let s = thread_rng().sample::<BigUint, _>(RandomBits::new(128));

        let mut sigma_protocol_public_input =
            generate_sigma_protocol_public_input(&sigma_protocol_param, &r, &s);

        // It is invalid
        let r1 = thread_rng().sample::<BigUint, _>(RandomBits::new(128));

        sigma_protocol_public_input.r1 = r1;

        let is_valid = verify(&sigma_protocol_public_input, &sigma_protocol_param);

        println!("is_valid : {:?}", is_valid);
    }
}
