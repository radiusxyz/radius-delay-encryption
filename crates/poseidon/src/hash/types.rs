use serde::{Deserialize, Serialize};

type FieldElement = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PoseidonHashValue([FieldElement; 2]);

impl PoseidonHashValue {
    pub fn new(key: [FieldElement; 2]) -> Self {
        PoseidonHashValue(key)
    }

    pub fn get(&self, index: usize) -> &[u8; 32] {
        if index > 2 {
            panic!("index out of bounds")
        }

        self.0.get(index).unwrap()
    }
}
