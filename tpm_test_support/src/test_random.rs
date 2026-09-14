use fastrand::Rng;

/// A seeded pseudo-random number generator for test reproducibility backed by `fastrand::Rng`.
///
/// Reads the default seed from the `TPM_TEST_RNG_SEED` environment variable if present,
/// or falls back to a deterministic default seed (`0x5EED_CAFE_BABE_F00D`).
#[derive(Debug, Clone)]
pub struct TestRandom {
    rng: Rng,
}

impl Default for TestRandom {
    fn default() -> Self {
        Self::from_env()
    }
}

impl TestRandom {
    /// Creates a new `TestRandom` initialized from the `TPM_TEST_RNG_SEED` environment variable,
    /// or falls back to a deterministic default seed.
    pub fn from_env() -> Self {
        if let Ok(seed_str) = std::env::var("TPM_TEST_RNG_SEED") {
            let s = seed_str.trim();
            let parsed = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).ok()
            } else {
                s.parse::<u64>().ok()
            };
            if let Some(seed) = parsed {
                return Self::new(seed);
            }
        }
        Self::new(0x5EED_CAFE_BABE_F00D)
    }

    /// Creates a new `TestRandom` with an explicit 64-bit seed.
    pub fn new(seed: u64) -> Self {
        Self {
            rng: Rng::with_seed(seed),
        }
    }

    /// Generates the next pseudo-random 64-bit unsigned integer.
    pub fn next_u64(&mut self) -> u64 {
        self.rng.u64(..)
    }

    /// Generates `n` pseudo-random bytes.
    pub fn random_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; n];
        self.rng.fill(&mut bytes);
        bytes
    }

    /// Generates a random binary blob with length between `min_len` and `max_len`.
    pub fn random_blob(&mut self, min_len: usize, max_len: usize) -> Vec<u8> {
        let len = if max_len <= min_len {
            min_len
        } else {
            self.rng.usize(min_len..=max_len)
        };
        self.random_bytes(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_output() {
        let mut rng1 = TestRandom::new(12345);
        let mut rng2 = TestRandom::new(12345);
        assert_eq!(rng1.next_u64(), rng2.next_u64());
        assert_eq!(rng1.random_bytes(32), rng2.random_bytes(32));
    }

    #[test]
    fn test_random_blob_length_bounds() {
        let mut rng = TestRandom::new(999);
        for _ in 0..100 {
            let blob = rng.random_blob(10, 20);
            assert!(blob.len() >= 10 && blob.len() <= 20);
        }
    }

    #[test]
    fn test_from_env_hex_and_decimal() {
        std::env::set_var("TPM_TEST_RNG_SEED", "0x1234");
        let mut rng_hex = TestRandom::from_env();
        let mut rng_direct = TestRandom::new(0x1234);
        assert_eq!(rng_hex.next_u64(), rng_direct.next_u64());

        std::env::set_var("TPM_TEST_RNG_SEED", "4660");
        let mut rng_dec = TestRandom::from_env();
        let mut rng_direct2 = TestRandom::new(4660);
        assert_eq!(rng_dec.next_u64(), rng_direct2.next_u64());

        std::env::remove_var("TPM_TEST_RNG_SEED");
    }
}
