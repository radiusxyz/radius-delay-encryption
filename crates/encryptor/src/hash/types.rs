use serde::{Deserialize, Serialize};

type FieldElement = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HashValue([FieldElement; 2]);

impl HashValue {
    pub fn new(key: [FieldElement; 2]) -> Self {
        HashValue(key)
    }

    pub fn get(&self, index: usize) -> &[u8; 32] {
        if index > 2 {
            panic!("index out of bounds")
        }

        self.0.get(index).unwrap()
    }
}
