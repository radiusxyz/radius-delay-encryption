// added for verify_delay_hash
use std::marker::PhantomData;

use ff::{FromUniformBytes, PrimeField};
use halo2_proofs::circuit::AssignedCell;
use halo2wrong::halo2::circuit::{SimpleFloorPlanner, Value};
use halo2wrong::halo2::plonk::{Circuit, ConstraintSystem, Error};
use halo2wrong::RegionCtx;
use maingate::{big_to_fe, decompose_big, MainGate, MainGateConfig, MainGateInstructions};
use num_bigint::BigUint;
use poseidon::chip::{PoseidonChip, FULL_ROUND, PARTIAL_ROUND};
use poseidon::encryption::chip::PoseidonEncChip;
use poseidon::encryption::cipher::MESSAGE_CAPACITY;
use poseidon::hash::chip::PoseidonHashChip;
use poseidon::spec::Spec;

use super::{LIMB_COUNT, LIMB_WIDTH};

#[derive(Clone)]
pub struct PoseidonEncryptionCircuit<F, const T: usize, const RATE: usize>
where
    F: PrimeField + FromUniformBytes<64>,
{
    // Poseidon Enc
    pub spec: Spec<F, T, RATE>,
    pub data: [F; MESSAGE_CAPACITY],

    // Hash related
    pub k_limbs: Vec<F>,
}

impl<F, const T: usize, const RATE: usize> PoseidonEncryptionCircuit<F, T, RATE>
where
    F: PrimeField + FromUniformBytes<64>,
{
    pub fn create_empty_circuit() -> Self {
        let k = BigUint::default();
        let k_limbs = decompose_big::<F>(k.clone(), LIMB_COUNT, LIMB_WIDTH);

        Self {
            k_limbs,
            data: [F::ZERO; MESSAGE_CAPACITY],
            spec: Spec::<F, T, RATE>::new(FULL_ROUND, PARTIAL_ROUND),
        }
    }
}

impl<F, const T: usize, const RATE: usize> Circuit<F> for PoseidonEncryptionCircuit<F, T, RATE>
where
    F: PrimeField + FromUniformBytes<64>,
{
    type Config = PoseidonEncryptionCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!();
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let main_gate_config = MainGate::<F>::configure(meta);
        meta.enable_equality(main_gate_config.instance);

        let encryption_config = main_gate_config.clone();
        let hash_config = main_gate_config.clone();

        PoseidonEncryptionCircuitConfig {
            encryption_config,
            hash_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl halo2wrong::halo2::circuit::Layouter<F>,
    ) -> Result<(), halo2wrong::halo2::plonk::Error> {
        let h_out = layouter.assign_region(
            || "hash mapping from 2048bit",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                let mut hasher = PoseidonEncryptionChip::<F, T, RATE>::new_hash(
                    ctx,
                    &self.spec,
                    &config.hash_config,
                )?;
                let main_gate_chip = hasher.poseidon_chip.main_gate();

                let base1 = main_gate_chip.assign_constant(
                    ctx,
                    big_to_fe(BigUint::from(
                        2_u128.pow((LIMB_WIDTH as u128).try_into().unwrap()),
                    )),
                )?;
                let base2 = main_gate_chip.mul(ctx, &base1, &base1)?;
                for i in 0..(LIMB_COUNT) / 3 {
                    let in0 =
                        main_gate_chip.assign_value(ctx, Value::known(self.k_limbs[3 * i]))?;
                    let in1 =
                        main_gate_chip.assign_value(ctx, Value::known(self.k_limbs[3 * i + 1]))?;
                    let in2 =
                        main_gate_chip.assign_value(ctx, Value::known(self.k_limbs[3 * i + 2]))?;

                    let mut a_poly = in0;
                    a_poly = main_gate_chip.mul_add(ctx, &in1, &base1, &a_poly)?;
                    a_poly = main_gate_chip.mul_add(ctx, &in2, &base2, &a_poly)?;
                    let e = a_poly;
                    hasher.update(&[e.clone()]);
                }

                let in0 = main_gate_chip.assign_value(ctx, Value::known(self.k_limbs[30]))?;
                let in1 = main_gate_chip.assign_value(ctx, Value::known(self.k_limbs[31]))?;

                let mut a_poly = in0;

                a_poly = main_gate_chip.mul_add(ctx, &in1, &base1, &a_poly)?;
                let e = a_poly;
                hasher.update(&[e.clone()]);

                let mut h_out: Vec<AssignedCell<F, F>> = vec![];
                let h_assiged = hasher.hash(ctx)?;

                h_out.push(h_assiged[1].clone());
                h_out.push(h_assiged[2].clone());

                Ok(h_out)
            },
        )?;

        let _ =
            layouter.constrain_instance(h_out[0].clone().cell(), config.hash_config.instance, 0);
        let _ =
            layouter.constrain_instance(h_out[1].clone().cell(), config.hash_config.instance, 1);

        let cipher_text = layouter.assign_region(
            || "poseidon region",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);
                let mut pose_key = [F::ZERO; 2];

                // set poseidon enc key as the ouput of rsa
                h_out[0].value().map(|e| *e).map(|v| pose_key[0] = v);
                h_out[1].value().map(|e| *e).map(|v| pose_key[1] = v);

                // == Encryption ciruit ==//
                // new assigns initial_state into cells.
                let mut enc = PoseidonEncryptionChip::<F, T, RATE>::new_enc(
                    ctx,
                    &self.spec,
                    &config.encryption_config,
                    pose_key,
                )?;
                let main_gate_chip = enc.poseidon_chip.main_gate();
                main_gate_chip.assert_equal(ctx, &enc.poseidon_chip.state.0[2], &h_out[0])?;
                main_gate_chip.assert_equal(ctx, &enc.poseidon_chip.state.0[3], &h_out[1])?;

                // permute before state data addtion
                enc.poseidon_chip.permutation(ctx, vec![])?;

                // check the permuted state
                let data = Value::known(self.data);

                // set the data to be an input to the encryption
                for e in data.as_ref().transpose_vec(self.data.len()) {
                    let e = main_gate_chip.assign_value(ctx, e.map(|v| *v))?;
                    enc.poseidon_chip.set_inputs(&[e.clone()]);
                }

                // add the input to the currentn state and output encrypted result
                let cipher_text = enc.absorb_and_relese(ctx)?;

                Ok(cipher_text)
            },
        )?;

        for (i, cipher_text) in cipher_text.iter().enumerate() {
            let _ = layouter.constrain_instance(
                cipher_text.cell(),
                config.encryption_config.instance,
                2 + i,
            );
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct PoseidonEncryptionCircuitConfig {
    // Poseidon Encryption
    encryption_config: MainGateConfig,
    // Hash
    hash_config: MainGateConfig,
}

#[derive(Debug, Clone)]
struct PoseidonEncryptionChip<
    F: PrimeField + ff::FromUniformBytes<64>,
    const T: usize,
    const RATE: usize,
> {
    _encryption_chip: PoseidonChip<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>,
    _hash_chip: PoseidonHashChip<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>,
    _encryption_config: PoseidonEncryptionCircuitConfig,
    _f: PhantomData<F>,
}

impl<F: PrimeField + ff::FromUniformBytes<64>, const T: usize, const RATE: usize>
    PoseidonEncryptionChip<F, T, RATE>
{
    pub fn new_hash(
        ctx: &mut RegionCtx<'_, F>,
        spec: &Spec<F, T, RATE>,
        main_gate_config: &MainGateConfig,
    ) -> Result<PoseidonHashChip<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>, Error> {
        let pos_hash_chip = PoseidonChip::<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>::new_hash(
            ctx,
            spec,
            main_gate_config,
        )?;

        Ok(PoseidonHashChip {
            poseidon_chip: pos_hash_chip,
        })
    }

    pub fn new_enc(
        ctx: &mut RegionCtx<'_, F>,
        spec: &Spec<F, T, RATE>,
        main_gate_config: &MainGateConfig,
        sk: [F; 2],
    ) -> Result<PoseidonEncChip<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>, Error> {
        let encryption_chip =
            PoseidonChip::<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>::new_encryption_de(
                ctx,
                spec,
                main_gate_config,
                &sk[0],
                &sk[1],
            )?;

        Ok(PoseidonEncChip {
            poseidon_chip: encryption_chip,
            pose_key0: sk[0],
            pose_key1: sk[1],
        })
    }
}
