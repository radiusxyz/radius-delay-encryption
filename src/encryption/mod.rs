pub mod poseidon_encryption;
pub mod poseidon_encryption_circuit;
pub mod poseidon_encryption_zkp;

pub const BITS_LEN: usize = 2048;
pub const LIMB_WIDTH: usize = 64;
pub const LIMB_COUNT: usize = BITS_LEN / LIMB_WIDTH;

const T: usize = 5;
const RATE: usize = 4;
