pub mod chip;
pub use chip::*;
pub mod instructions;
use big_integer::*;
use halo2wrong::halo2::arithmetic::Field;
use halo2wrong::halo2::circuit::Value;
use halo2wrong::halo2::plonk::Error;
pub use instructions::*;
use maingate::{big_to_fe, AssignedValue, MainGateInstructions, RegionCtx};
use num_bigint::BigUint;

/// A parameter `e` in the RSA public key that is about to be assigned.
#[derive(Clone, Debug)]
pub enum RSAPubE<F: Field> {
    /// A variable parameter `e`.
    Var(UnassignedInteger<F>),
    /// A fixed parameter `e`.
    Fix(BigUint),
}

/// A parameter `e` in the assigned RSA public key.
#[derive(Clone, Debug)]
pub enum AssignedRSAPubE<F: Field> {
    /// A variable parameter `e`.
    Var(AssignedInteger<F, Fresh>),
    /// A fixed parameter `e`.
    Fix(BigUint),
}

/// RSA public key that is about to be assigned.
#[derive(Clone, Debug)]
pub struct RSAPublicKey<F: Field> {
    /// a modulus parameter
    pub n: UnassignedInteger<F>,
    /// an exponent parameter
    pub e: RSAPubE<F>,
}

impl<F: Field> RSAPublicKey<F> {
    /// Creates new [`RSAPublicKey`] from `n` and `e`.
    ///
    /// # Arguments
    /// * n - an integer of `n`.
    /// * e - a parameter `e`.
    ///
    /// # Return values
    /// Returns new [`RSAPublicKey`].
    pub fn new(n: UnassignedInteger<F>, e: RSAPubE<F>) -> Self {
        Self { n, e }
    }

    pub fn without_witness(num_limbs: usize, fix_e: BigUint) -> Self {
        let n = UnassignedInteger {
            value: Value::unknown(),
            num_limbs,
        };
        let e = RSAPubE::<F>::Fix(fix_e);
        Self { n, e }
    }
}

/// An assigned RSA public key.
#[derive(Clone, Debug)]
pub struct AssignedRSAPublicKey<F: Field> {
    /// a modulus parameter
    pub n: AssignedInteger<F, Fresh>,
    /// an exponent parameter
    pub e: AssignedRSAPubE<F>,
}

impl<F: Field> AssignedRSAPublicKey<F> {
    /// Creates new [`AssignedRSAPublicKey`] from assigned `n` and `e`.
    ///
    /// # Arguments
    /// * n - an assigned integer of `n`.
    /// * e - an assigned parameter `e`.
    ///
    /// # Return values
    /// Returns new [`AssignedRSAPublicKey`].
    pub fn new(n: AssignedInteger<F, Fresh>, e: AssignedRSAPubE<F>) -> Self {
        Self { n, e }
    }
}

/// RSA signature that is about to be assigned.
#[derive(Clone, Debug)]
pub struct RSASignature<F: Field> {
    c: UnassignedInteger<F>,
}

impl<F: Field> RSASignature<F> {
    /// Creates new [`RSASignature`] from its integer.
    ///
    /// # Arguments
    /// * c - an integer of the signature.
    ///
    /// # Return values
    /// Returns new [`RSASignature`].
    pub fn new(c: UnassignedInteger<F>) -> Self {
        Self { c }
    }

    pub fn without_witness(num_limbs: usize) -> Self {
        let c = UnassignedInteger {
            value: Value::unknown(),
            num_limbs,
        };
        Self { c }
    }
}

/// An assigned RSA signature.
#[derive(Clone, Debug)]
pub struct AssignedRSASignature<F: Field> {
    c: AssignedInteger<F, Fresh>,
}

impl<F: Field> AssignedRSASignature<F> {
    /// Creates new [`AssignedRSASignature`] from its assigned integer.
    ///
    /// # Arguments
    /// * c - an assigned integer of the signature.
    ///
    /// # Return values
    /// Returns new [`AssignedRSASignature`].
    pub fn new(c: AssignedInteger<F, Fresh>) -> Self {
        Self { c }
    }
}

use ff::PrimeField;
use halo2wrong::halo2::circuit::Layouter;

/// A circuit implementation to verify pkcs1v15 signatures.
#[derive(Clone, Debug)]
pub struct RSASignatureVerifier<F: PrimeField> {
    rsa_chip: RSAChip<F>,
}

impl<F: PrimeField> RSASignatureVerifier<F> {
    /// Creates new [`RSASignatureVerifier`] from [`RSAChip`] and [`Sha256BitChip`].
    ///
    /// # Arguments
    /// * rsa_chip - a [`RSAChip`].
    ///
    /// # Return values
    /// Returns new [`RSASignatureVerifier`].
    pub fn new(rsa_chip: RSAChip<F>) -> Self {
        Self { rsa_chip }
    }

    /// Given a RSA public key, signed message bytes, and a pkcs1v15 signature, verifies the signature with SHA256 hash function.
    ///
    /// # Arguments
    /// * layouter - a layouter of the constraints system.
    /// * public_key - an assigned public key used for the verification.
    /// * msg - signed message bytes.
    /// * signature - a pkcs1v15 signature to be verified.
    ///
    /// # Return values
    /// Returns the assigned bit as `AssignedValue<F>`.
    /// If `signature` is valid for `public_key` and `msg`, the bit is equivalent to one.
    /// Otherwise, the bit is equivalent to zero.
    pub fn verify_pkcs1v15_signature(
        &self,
        mut layouter: impl Layouter<F>,
        public_key: &AssignedRSAPublicKey<F>,
        msg: &[u8],
        signature: &AssignedRSASignature<F>,
    ) -> Result<(AssignedValue<F>, Vec<AssignedValue<F>>), Error> {
        let rsa_chip = self.rsa_chip.clone();
        let main_gate = rsa_chip.main_gate();

        let inputs = msg
            .iter()
            .map(|byte| Value::known(*byte))
            .collect::<Vec<Value<u8>>>();
        let input_byte_size = inputs.len();

        const DIGEST_SIZE: usize = 8;

        let digest_values = layouter.assign_region(
            || "inputs",
            |region| {
                let ctx = &mut RegionCtx::new(region, 0);

                let _zero = main_gate.assign_constant(ctx, F::ZERO)?;

                let values: [AssignedValue<F>; DIGEST_SIZE] = (0..input_byte_size)
                    .map(|index| {
                        main_gate
                            .assign_value(ctx, Value::known(F::from_u128(msg[index] as u128)))
                            .unwrap()
                    })
                    .collect::<Vec<AssignedValue<F>>>()
                    .try_into()
                    .unwrap();

                Ok(values)
            },
        )?;

        let mut hashed_bytes = digest_values.to_vec();
        hashed_bytes.reverse();

        let bytes_len = hashed_bytes.len();
        let limb_bytes = RSAChip::<F>::LIMB_WIDTH / 8;

        // 2. Verify `signature` with `public_key` and `hashed_bytes`.
        let is_valid = layouter.assign_region(
            || "verify pkcs1v15 signature",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                let mut assigned_limbs = Vec::with_capacity(bytes_len / limb_bytes);
                for i in 0..(bytes_len / limb_bytes) {
                    let mut limb_val = main_gate.assign_constant(ctx, F::ZERO)?;
                    for j in 0..limb_bytes {
                        let coeff = main_gate
                            .assign_constant(ctx, big_to_fe(BigUint::from(1usize) << (8 * j)))?;
                        limb_val = main_gate.mul_add(
                            ctx,
                            &coeff,
                            &hashed_bytes[limb_bytes * i + j],
                            &limb_val,
                        )?;
                    }
                    assigned_limbs.push(AssignedLimb::from(limb_val));
                }
                let hashed_msg = AssignedInteger::new(&assigned_limbs);
                let is_sign_valid =
                    rsa_chip.verify_pkcs1v15_signature(ctx, public_key, &hashed_msg, signature)?;
                Ok(is_sign_valid)
            },
        )?;
        hashed_bytes.reverse();
        Ok((is_valid, hashed_bytes))
    }
}
