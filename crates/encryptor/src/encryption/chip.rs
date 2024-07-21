use ff::{FromUniformBytes, PrimeField};
use halo2wrong::halo2::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2wrong::halo2::plonk::{Circuit, ConstraintSystem, Error};
use halo2wrong::RegionCtx;
use maingate::{AssignedValue, MainGate, MainGateConfig, MainGateInstructions};

use super::cipher::MESSAGE_CAPACITY;
use crate::chip::{Chip, FULL_ROUND, PARTIAL_ROUND};
use crate::spec::Spec;

#[derive(Clone, Debug)]
pub struct EncChip<
    F: PrimeField + FromUniformBytes<64>,
    const T: usize,
    const RATE: usize,
    const R_F: usize,
    const R_P: usize,
> {
    pub chip: Chip<F, T, RATE, R_F, R_P>,
    pub pose_key0: F,
    pub pose_key1: F,
}

impl<
        F: PrimeField + FromUniformBytes<64>,
        const R_F: usize,
        const R_P: usize,
        const T: usize,
        const RATE: usize,
    > EncChip<F, T, RATE, R_F, R_P>
{
    pub fn new(
        ctx: &mut RegionCtx<'_, F>,
        spec: &Spec<F, T, RATE>,
        main_gate_config: &MainGateConfig,
        sk: [F; 2],
    ) -> Result<Self, Error> {
        let encryption_chip =
            Chip::<F, T, RATE, R_F, R_P>::new_enc(ctx, spec, main_gate_config, &sk[0], &sk[1])?;

        // let encryption_key = EncryptionKey::<F>::init();

        Ok(Self {
            chip: encryption_chip,
            pose_key0: sk[0],
            pose_key1: sk[1],
        })
    }

    /// add the inputs in absorbing and return
    pub fn absorb_and_relese(
        &mut self,
        ctx: &mut RegionCtx<'_, F>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let mut cipher_text = vec![];
        // Get elements to be encrypted
        let input_elements = self.chip.absorbing.clone();
        let main_gate = self.chip.main_gate();

        // Flush the input que
        self.chip.absorbing.clear();

        let mut i = 0;

        // Apply permutation to `RATE` sized chunks
        for inputs in input_elements.chunks(RATE) {
            // Add inputs along with constants
            for (word, input) in self.chip.state.0.iter_mut().skip(1).zip(inputs.iter()) {
                *word = main_gate.add(ctx, word, input)?;
                if i < MESSAGE_CAPACITY {
                    cipher_text.push(word.clone());
                    i += 1;
                }
            }

            self.chip.permutation(ctx, vec![])?;
        }

        cipher_text.push(self.chip.state.0[1].clone());

        Ok(cipher_text)
    }
}

#[derive(Clone)]
pub struct EncryptionCircuit<
    F: PrimeField + FromUniformBytes<64>,
    const T: usize,
    const RATE: usize,
> {
    pub spec: Spec<F, T, RATE>, // Spec for Encryption
    pub data: Value<Vec<F>>,    // data to be encrypted
    pub key: [F; 2],            // the pub setting depend on usage
    pub expected: Vec<F>,       // expected cipher text
}

impl<F: PrimeField + FromUniformBytes<64>, const T: usize, const RATE: usize> Circuit<F>
    for EncryptionCircuit<F, T, RATE>
{
    type Config = MainGateConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        todo!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        MainGate::<F>::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let main_gate = MainGate::<F>::new(config.clone());

        layouter.assign_region(
            || "cipher",
            |region| {
                let offset = 0;
                let ctx = &mut RegionCtx::new(region, offset);

                let mut expected_result = vec![];

                // assign expected result
                for result in &self.expected {
                    let result = main_gate.assign_value(ctx, Value::known(*result))?;
                    expected_result.push(result);
                }

                // == Encryption circuit ==//

                // new assigns initial_state into cells.
                let mut pos_encryption_chip =
                    EncChip::<F, T, RATE, FULL_ROUND, PARTIAL_ROUND>::new(
                        ctx, &self.spec, &config, self.key,
                    )?;

                // check the assigned initial state

                // permute before state data addtion
                pos_encryption_chip.chip.permutation(ctx, vec![])?;

                // set the data to be an input to the encryption
                for e in self.data.as_ref().transpose_vec(MESSAGE_CAPACITY) {
                    let e = main_gate.assign_value(ctx, e.map(|v| *v))?;
                    pos_encryption_chip.chip.set_inputs(&[e.clone()]);
                }

                // add the input to the currentn state and output encrypted result
                let cipher_text = pos_encryption_chip.absorb_and_relese(ctx)?;

                // constrain with encryption result
                for (i, cipher_text) in cipher_text.iter().enumerate() {
                    main_gate.assert_equal(ctx, cipher_text, &expected_result[i])?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ff::FromUniformBytes;
    use halo2wrong::halo2::circuit::Value;
    use maingate::mock_prover_verify;
    use rand_core::OsRng;

    use crate::chip::{FULL_ROUND, PARTIAL_ROUND};
    use crate::encryption::chip::EncryptionCircuit;
    use crate::encryption::cipher::{Cipher, MESSAGE_CAPACITY};
    use crate::encryption::types::EncryptionKey;
    use crate::spec::Spec;

    #[test]
    fn test_pos_enc() {
        fn run<F: FromUniformBytes<64> + Ord, const T: usize, const RATE: usize>() {
            let key = EncryptionKey::<F> {
                key0: F::random(OsRng),
                key1: F::random(OsRng),
            };

            let mut ref_pos_enc = Cipher::<F, FULL_ROUND, PARTIAL_ROUND, T, RATE>::new();

            let spec = Spec::<F, T, RATE>::new(8, 57);
            let inputs = (0..(MESSAGE_CAPACITY)).map(|_| F::ONE).collect::<Vec<F>>();

            //== Encryption ==//
            let ref_cipher = ref_pos_enc.encrypt(&inputs, &[key.key0, key.key1]).unwrap();

            //== Circuit ==//
            let circuit = EncryptionCircuit::<F, T, RATE> {
                spec: spec.clone(),
                data: Value::known(inputs),
                key: [key.key0, key.key1],
                expected: ref_cipher.to_vec(),
            };

            let public_inputs = vec![vec![]];
            mock_prover_verify(&circuit, public_inputs);
        }
        use halo2wrong::curves::bn256::Fr as BnFr;

        run::<BnFr, 5, 4>();
    }
}
