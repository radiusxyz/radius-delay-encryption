use ff::PrimeField;

#[derive(Copy, Clone, Debug, Default)]
pub struct EncryptionKey<F: PrimeField> {
    pub key0: F,
    pub key1: F,
}

impl<F: PrimeField> EncryptionKey<F> {
    /// The default impl for key
    pub const fn init() -> Self {
        EncryptionKey {
            key0: F::ZERO,
            key1: F::ZERO,
        }
    }

    pub fn set_key(&mut self, k0: F, k1: F) {
        self.key0 = k0;
        self.key1 = k1;
    }
}
