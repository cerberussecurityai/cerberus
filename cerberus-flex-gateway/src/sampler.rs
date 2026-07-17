// Probabilistic request sampler backing the `sampleRate` config knob.
//
// Non-cryptographic by design: sampling needs a uniform coin flip, not
// unpredictability. We deliberately avoid `rand`/`getrandom` — they
// bottom out in the WASI `random_get` hostcall, whose support in Flex
// Gateway's proxy-wasm host cannot be verified without gateway
// hardware, and a trapping hostcall would crash the policy. A small
// in-crate SplitMix64 keeps the draw dependency-free and infallible.
//
// The PRNG is per-worker, seeded from the host clock at configure time
// (see `sampler_seed_from_clock` in lib.rs), so workers walk different
// decision sequences. RefCell interior mutability is safe for the same
// reason as EventQueue (see the PolicyContext doc comment in lib.rs):
// proxy-wasm workers are single-threaded and no borrow is held across
// an await point.

use std::cell::RefCell;

/// One SplitMix64 step: advance `state` by the gamma constant and
/// return the mixed output.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Map a u64 draw onto [0, 1): keep the top 53 bits (the f64 mantissa
/// width) and scale. Never reaches 1.0 — (2^53 − 1) / 2^53 is the max.
fn unit_interval(x: u64) -> f64 {
    (x >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
}

pub struct Sampler {
    rate: f64,
    state: RefCell<u64>,
}

impl Sampler {
    /// `rate` must already be clamped to [0, 1] — `PolicyContext::new`
    /// owns the clamp; the fast paths in `should_sample` would misread
    /// out-of-range values.
    pub fn new(rate: f64, seed: u64) -> Self {
        Self {
            rate,
            state: RefCell::new(seed),
        }
    }

    /// Per-request coin flip: true iff the request should be captured.
    /// Rates of exactly 1.0 / 0.0 short-circuit without touching the
    /// RefCell, so the default config never pays for the RNG.
    pub fn should_sample(&self) -> bool {
        if self.rate >= 1.0 {
            return true;
        }
        if self.rate <= 0.0 {
            return false;
        }
        let mut state = self.state.borrow_mut();
        unit_interval(splitmix64(&mut state)) < self.rate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_zero_never_samples() {
        let s = Sampler::new(0.0, 42);
        assert!((0..1000).all(|_| !s.should_sample()));
    }

    #[test]
    fn rate_one_always_samples() {
        let s = Sampler::new(1.0, 42);
        assert!((0..1000).all(|_| s.should_sample()));
    }

    #[test]
    fn same_seed_and_rate_give_identical_sequence() {
        let a = Sampler::new(0.5, 0xDEAD_BEEF);
        let b = Sampler::new(0.5, 0xDEAD_BEEF);
        let seq_a: Vec<bool> = (0..64).map(|_| a.should_sample()).collect();
        let seq_b: Vec<bool> = (0..64).map(|_| b.should_sample()).collect();
        assert_eq!(seq_a, seq_b);
    }

    #[test]
    fn distribution_sanity_at_rate_point_three() {
        // Deterministic given the fixed seed — not a statistical flake.
        let s = Sampler::new(0.3, 12345);
        let sampled = (0..100_000).filter(|_| s.should_sample()).count();
        assert!(
            (28_000..=32_000).contains(&sampled),
            "expected ~30% of 100k draws, got {sampled}"
        );
    }

    #[test]
    fn unit_interval_stays_in_range_for_extremes() {
        for x in [0u64, u64::MAX] {
            let u = unit_interval(x);
            assert!((0.0..1.0).contains(&u), "unit_interval({x}) = {u}");
        }
        assert_eq!(unit_interval(0), 0.0);
    }
}
