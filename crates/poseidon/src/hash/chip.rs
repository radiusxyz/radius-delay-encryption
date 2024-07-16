use ff::{FromUniformBytes, PrimeField};
use halo2wrong::halo2::plonk::Error;
use maingate::{AssignedValue, MainGateConfig, RegionCtx};

use crate::chip::PoseidonChip;
use crate::spec::Spec;

#[derive(Debug, Clone)]
pub struct PoseidonHashChip<
    F: PrimeField + FromUniformBytes<64>,
    // const NUMBER_OF_LIMBS: usize,
    // const BIT_LEN: usize,
    const T: usize,
    const RATE: usize,
    const R_F: usize,
    const R_P: usize,
> {
    pub poseidon_chip: PoseidonChip<F, T, RATE, R_F, R_P>,
}

impl<
        F: PrimeField + FromUniformBytes<64>,
        // const NUMBER_OF_LIMBS: usize,
        // const BIT_LEN: usize,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > PoseidonHashChip<F, T, RATE, R_F, R_P>
{
    // Constructs new hasher chip with assigned initial state
    pub fn new(
        // TODO: we can remove initial state assingment in construction
        ctx: &mut RegionCtx<'_, F>,
        spec: &Spec<F, T, RATE>,
        main_gate_config: &MainGateConfig,
    ) -> Result<Self, Error> {
        let pos_hash_chip =
            PoseidonChip::<F, T, RATE, R_F, R_P>::new_hash(ctx, spec, main_gate_config)?;

        Ok(Self {
            poseidon_chip: pos_hash_chip,
        })
    }

    /// Appends field elements to the absorbation line. It won't perform
    /// permutation here
    pub fn update(&mut self, elements: &[AssignedValue<F>]) {
        self.poseidon_chip.absorbing.extend_from_slice(elements);
    }
}

// wooju - TODO: making as instruction? a form of trait impl
//               and HashChip
impl<
        F: PrimeField + FromUniformBytes<64>,
        const R_F: usize,
        const R_P: usize,
        const T: usize,
        const RATE: usize,
    > PoseidonHashChip<F, T, RATE, R_F, R_P>
{
    pub fn hash(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
    ) -> Result<[halo2_proofs::circuit::AssignedCell<F, F>; T], Error> {
        // Get elements to be hashed
        let input_elements = self.poseidon_chip.absorbing.clone();
        // Flush the input que
        self.poseidon_chip.absorbing.clear();

        let mut padding_offset = 0;
        // Apply permutation to `RATE`Ï sized chunks
        for chunk in input_elements.chunks(RATE) {
            padding_offset = RATE - chunk.len();
            self.poseidon_chip.perm_hash(ctx, chunk.to_vec())?;
        }

        // If last chunking is full apply another permutation for collution resistance
        if padding_offset == 0 {
            self.poseidon_chip.perm_hash(ctx, vec![])?;
        }

        Ok(self.poseidon_chip.state.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use ff::{FromUniformBytes, PrimeField};
    use halo2_proofs::circuit::AssignedCell;
    use halo2wrong::halo2::circuit::{Layouter, SimpleFloorPlanner, Value};
    use halo2wrong::halo2::plonk::{Circuit, ConstraintSystem, Error};
    use maingate::{mock_prover_verify, MainGate, MainGateConfig, MainGateInstructions, RegionCtx};

    use crate::chip::{FULL_ROUND, PARTIAL_ROUND};
    use crate::hash::chip::PoseidonHashChip;
    use crate::poseidon::Poseidon;
    use crate::spec::Spec;

    // const NUMBER_OF_LIMBS: usize = 4;
    // const BIT_LEN_LIMB: usize = 68;

    #[derive(Clone)]
    pub(crate) struct PoseidonHashConfig {
        main_gate_config: MainGateConfig,
    }

    pub(crate) struct PoseidonHashCircuit<
        F: PrimeField + FromUniformBytes<64>,
        const T: usize,
        const RATE: usize,
    > {
        spec: Spec<F, T, RATE>,
        n: usize,
        inputs: Value<Vec<F>>,
        expected: Vec<F>,
    }

    impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> Circuit<F>
        for PoseidonHashCircuit<F, T, RATE>
    {
        type Config = PoseidonHashConfig;
        type FloorPlanner = SimpleFloorPlanner;
        #[cfg(feature = "circuit-params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            unimplemented!();
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let main_gate_config = MainGate::<F>::configure(meta);

            PoseidonHashConfig { main_gate_config }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let main_gate = MainGate::<F>::new(config.main_gate_config.clone());

            // compare results
            layouter.assign_region(
                || "region 0",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let mut expected_result: Vec<AssignedCell<F, F>> = vec![];
                    for i in 0..RATE {
                        expected_result
                            .push(main_gate.assign_value(ctx, Value::known(self.expected[i]))?);
                    }

                    let mut pos_hash_chip =
                        PoseidonHashChip::<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>::new(
                            ctx,
                            &self.spec,
                            &config.main_gate_config,
                        )?;

                    // println!("state0: {:?}\n", pos_hash_chip.poseidon_chip.state.0);

                    for e in self.inputs.as_ref().transpose_vec(self.n) {
                        let e = main_gate.assign_value(ctx, e.map(|e| *e))?;
                        println!("{:?}", e);
                        pos_hash_chip.update(&[e.clone()]);
                    }

                    // println!("state1: {:?}\n", pos_hash_chip.poseidon_chip.state.0);

                    let hash_output = pos_hash_chip.hash(ctx)?;
                    // let expected = main_gate.assign_value(ctx, self.expected)?;

                    // println!("state2: {:?}\n", pos_hash_chip.poseidon_chip.state.0);

                    // println!("hash_output: {:?}", hash_output);
                    // println!("expected hash_output: {:?}\n", self.expected);
                    for i in 0..RATE {
                        main_gate.assert_equal(
                            ctx,
                            &hash_output[T - RATE + i],
                            &expected_result[i],
                        )?;
                    }

                    Ok(())
                },
            )?;

            Ok(())
        }
    }

    #[test]
    fn test_example_hash() {
        use halo2wrong::curves::bn256::Fr;
        let number_of_inputs = 3;
        const T: usize = 5;
        const RATE: usize = 4;

        println!("{:?}", number_of_inputs);
        let mut ref_hasher = Poseidon::<Fr, T, RATE>::new_hash(8, 57);
        let spec = Spec::<Fr, T, RATE>::new(8, 57);

        let inputs: Vec<Fr> = (0..number_of_inputs)
            // .map(|_| Fr::random(OsRng))
            .map(|_| Fr::ZERO)
            .collect::<Vec<Fr>>();

        println!("ref_hahser state0: {:?}", ref_hasher.state.words().clone());

        ref_hasher.update(&inputs[..]);
        let expected = ref_hasher.squeeze(1);
        let expected_out: Vec<_> = (T - RATE..T).map(|i| expected[i].clone()).collect();

        println!("ref_hahser state1: {:?}", ref_hasher.state.words().clone());

        let circuit: PoseidonHashCircuit<Fr, T, RATE> = PoseidonHashCircuit {
            spec: spec.clone(),
            n: number_of_inputs,
            inputs: Value::known(inputs),
            expected: expected_out,
        };
        let instance = vec![vec![]];
        mock_prover_verify(&circuit, instance);
    }
}
