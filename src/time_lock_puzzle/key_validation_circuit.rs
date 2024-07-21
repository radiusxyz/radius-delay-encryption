use std::marker::PhantomData;

use big_integer::{BigIntConfig, BigIntInstructions, UnassignedInteger};
use encryptor::chip::{Chip, FULL_ROUND, PARTIAL_ROUND};
use encryptor::hash::chip::HashChip;
use encryptor::spec::Spec;
use ff::{FromUniformBytes, PrimeField};
use halo2_proofs::circuit::floor_planner::V1;
use halo2_proofs::circuit::{AssignedCell, Chip as HaloChip};
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
use halo2wrong::RegionCtx;
use maingate::{
    big_to_fe, decompose_big, MainGate, MainGateConfig, MainGateInstructions, RangeChip,
    RangeInstructions,
};
use num_bigint::BigUint;
use rsa::{RSAChip, RSAConfig};

use super::{BITS_LEN, EXP_LIMB_BITS, LIMB_COUNT, LIMB_WIDTH};

#[derive(Clone, Debug)]
pub struct KeyValidationCircuitConfig {
    // Delay
    rsa_config: RSAConfig,

    // Hash
    hash_config: MainGateConfig,
}

#[derive(Clone, Default)]
pub struct KeyValidationCircuit<F, const T: usize, const RATE: usize>
where
    F: PrimeField + FromUniformBytes<64>,
{
    // Mod power
    pub n: BigUint, // parameter
    pub k: BigUint, // secret_input

    // Hash (for library)
    pub spec: Spec<F, T, RATE>,
}

impl<F, const T: usize, const RATE: usize> KeyValidationCircuit<F, T, RATE>
where
    F: PrimeField + FromUniformBytes<64>,
{
    pub fn create_empty_circuit() -> Self {
        Self {
            // TODO: stompesi - checking
            n: BigUint::default(),
            k: BigUint::default(),
            spec: Spec::<F, T, RATE>::new(FULL_ROUND, PARTIAL_ROUND),
        }
    }
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> Circuit<F>
    for KeyValidationCircuit<F, T, RATE>
{
    type Config = KeyValidationCircuitConfig;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self {
            n: self.n.clone(),
            k: self.k.clone(),
            spec: self.spec.clone(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let main_gate_config = MainGate::<F>::configure(meta);
        meta.enable_equality(main_gate_config.instance);

        let rsa_gate_config = main_gate_config.clone();
        let (composition_bit_lens, overflow_bit_lens) =
            RSAChip::<F>::compute_range_lens(LIMB_COUNT);

        let range_config = RangeChip::<F>::configure(
            meta,
            &rsa_gate_config,
            composition_bit_lens,
            overflow_bit_lens,
        );

        let bigint_config = BigIntConfig::new(range_config, rsa_gate_config.clone());
        let rsa_config = RSAConfig::new(bigint_config);
        let hash_config = main_gate_config.clone();

        KeyValidationCircuitConfig {
            rsa_config,
            hash_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    ) -> Result<(), halo2wrong::halo2::plonk::Error> {
        // === RSA based Time-lock === //
        let rsa_chip: RSAChip<F> =
            KeyValidationChip::<F, T, RATE>::new_rsa(config.rsa_config, BITS_LEN, EXP_LIMB_BITS);
        let bigint_chip = rsa_chip.bigint_chip();
        let main_gate_chip = rsa_chip.main_gate();

        let (rsa_output, rsa_input) = layouter.assign_region(
            || "PVDE : k^2 = a",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                let n_limbs = decompose_big::<F>(self.n.clone(), LIMB_COUNT, LIMB_WIDTH);
                let n_unassigned = UnassignedInteger::from(n_limbs);
                let n_assigned = bigint_chip.assign_integer(ctx, n_unassigned)?;

                let k_limbs = decompose_big::<F>// (e, number_of_limbs, bit_len)
                    (self.k.clone(), LIMB_COUNT, LIMB_WIDTH); // EXP_LIMB_BITS 5
                let k_unsigned = UnassignedInteger::from(k_limbs);
                let k_assigned = bigint_chip.assign_integer(ctx, k_unsigned)?;

                // changed to use 'square_mod' instead of 'pow_mod'
                let powed_var = bigint_chip.square_mod(ctx, &k_assigned, &n_assigned)?;

                Ok((powed_var, k_assigned))
            },
        )?;

        let range_chip = bigint_chip.range_chip();
        range_chip.load_table(&mut layouter)?;

        let h_out = layouter.assign_region(
            || "hash mapping from 2048bit",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                let mut hasher = KeyValidationChip::<F, T, RATE>::new_hash(
                    ctx,
                    &self.spec,
                    &config.hash_config,
                )?;

                let base1 = main_gate_chip.assign_constant(
                    ctx,
                    big_to_fe(BigUint::from(
                        2_u128.pow((LIMB_WIDTH as u128).try_into().unwrap()),
                    )),
                )?;
                let base2 = main_gate_chip.mul(ctx, &base1, &base1)?;

                for i in 0..LIMB_COUNT / 3 {
                    let mut a_poly = rsa_input.limb(3 * i);
                    a_poly =
                        main_gate_chip.mul_add(ctx, &rsa_input.limb(3 * i + 1), &base1, &a_poly)?;
                    a_poly =
                        main_gate_chip.mul_add(ctx, &rsa_input.limb(3 * i + 2), &base2, &a_poly)?;
                    let e = a_poly;
                    hasher.update(&[e.clone()]);
                }

                let mut a_poly = rsa_input.limb(30);

                a_poly = main_gate_chip.mul_add(ctx, &rsa_input.limb(31), &base1, &a_poly)?;
                let e = a_poly;
                hasher.update(&[e.clone()]);

                let mut h_out: Vec<AssignedCell<F, F>> = vec![];
                let h_assiged = hasher.hash(ctx)?;

                h_out.push(h_assiged[1].clone());
                h_out.push(h_assiged[2].clone());

                Ok(h_out)
            },
        )?;

        for i in 0..LIMB_COUNT {
            let _ = layouter.constrain_instance(
                rsa_output.limb(i).cell(),
                main_gate_chip.config().instance,
                i,
            );
        }

        for (i, h_out) in h_out.iter().enumerate().take(2) {
            let _ = layouter.constrain_instance(
                h_out.cell(),
                main_gate_chip.config().instance,
                LIMB_COUNT + i,
            );
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
struct KeyValidationChip<
    F: PrimeField + ff::FromUniformBytes<64>,
    const T: usize,
    const RATE: usize,
> {
    _rsa_chip: RSAChip<F>,
    _hash_chip: HashChip<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>,
    _delay_hash_config: KeyValidationCircuitConfig,
    _f: PhantomData<F>,
}

impl<F: PrimeField + ff::FromUniformBytes<64>, const T: usize, const RATE: usize>
    KeyValidationChip<F, T, RATE>
{
    pub fn new_rsa(config: RSAConfig, bits_len: usize, exp_limb_bits: usize) -> RSAChip<F> {
        RSAChip {
            config,
            bits_len,
            exp_limb_bits,
            _f: PhantomData,
        }
    }

    pub fn new_hash(
        ctx: &mut RegionCtx<'_, F>,
        spec: &Spec<F, T, RATE>,
        main_gate_config: &MainGateConfig,
    ) -> Result<HashChip<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>, Error> {
        let hash_chip =
            Chip::<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>::new_hash(ctx, spec, main_gate_config)?;

        Ok(HashChip { chip: hash_chip })
    }
}
