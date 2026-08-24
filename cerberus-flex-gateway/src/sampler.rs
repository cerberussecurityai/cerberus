// Sampling for the `sampleRate` / `sampleBy` config knobs.
//
// Two mechanisms:
//
//  * `Coin` — independent per-request draw. Backs `sampleBy: request`
//    and the terminal rung of the session-mode key ladder (traffic with
//    no usable key). Non-cryptographic by design: a coin flip needs a
//    uniform draw, not unpredictability. We deliberately avoid
//    `rand`/`getrandom` — they bottom out in the WASI `random_get`
//    hostcall, whose support in Flex Gateway's proxy-wasm host cannot
//    be verified without gateway hardware, and a trapping hostcall
//    would crash the policy. A small in-crate SplitMix64 keeps the
//    draw dependency-free and infallible. The PRNG is per-worker,
//    seeded from the host clock at configure time (see
//    `sampler_seed_from_clock` in lib.rs), so workers walk different
//    decision sequences. RefCell interior mutability is safe for the
//    same reason as EventQueue (see the PolicyContext doc comment in
//    lib.rs): proxy-wasm workers are single-threaded and no borrow is
//    held across an await point.
//
//  * `KeyedSampler` — deterministic keyed-threshold decision backing
//    `sampleBy: session`:
//
//        K    = HMAC-SHA256(key = "cerberus-sampling-v1", msg = key material)
//        h    = u64_be(HMAC-SHA256(K, domain ‖ 0x00 ‖ key
//                                     [‖ 0x00 ‖ decimal(epoch)])[0..8])
//        keep ⇔ rate ≥ 1.0, or rate > 0 and h < floor(rate·2⁶⁴)
//
//    Properties this buys, in decreasing order of importance:
//
//    - **Replica agreement without shared state.** K derives from
//      deployment-level key material (the resolved HMAC secret when
//      one is available, else the policy token), so every worker and
//      replica reaches the same verdict for the same key.
//
//    - **Threshold, not modulo.** `h < floor(rate·2⁶⁴)` makes any rate
//      in [0, 1] exact to 2⁻⁶⁴, and the sampled sets *nest*: every key
//      kept at 0.10 is still kept at 0.25. Operators can tune the rate
//      live without re-shuffling which sessions are observed, two API
//      instances at different rates agree on the shared part, and a
//      later ingest-side sampler composes cleanly. (This is the
//      property OpenTelemetry's consistent-probability sampling spec
//      makes a MUST; `h % n == 0` has none of it.)
//
//    - **Keyed, so membership is not predictable or choosable.** With
//      an unkeyed hash and a known rate, whoever controls a key could
//      pick values that land outside the sampled range. Keying with a
//      value clients cannot know reduces them to blind chance, and
//      gives uniform buckets even for low-entropy keys.
//
//    - **Domain separation.** The `domain` string namespaces the key
//      space: a session id and a user id that happen to share bytes
//      must not share a decision. Request-side and response-side MCP
//      session ids deliberately share the `session` domain — the id a
//      server mints on the handshake response must produce the same
//      verdict as the same id echoed on every later request.
//
//    - **Epoch rotation for coarse identity tiers.** The principal and
//      user-id ladder tiers mix a week number into the hash so the
//      sampled *set of identities* reshuffles weekly — without it, a
//      given user would be permanently in or permanently out of the
//      sample at any fixed rate. Session-id domains never rotate (each
//      session is a fresh key already), and rotation splits the small
//      fraction of sessions that straddle a week boundary — the
//      accepted cost of not having permanent blind spots.
//
//    The exact byte layout is pinned cross-implementation by
//    `parity-fixtures/sample_decision.yaml` (Rust-only today; the
//    contract cerberus-django and the Envoy AI Gateway bridge must
//    match if they adopt sampling).
//
//    Cost: ~2 SHA-256 compressions per decision from a cloned
//    pre-keyed HMAC state, paid on unsampled requests too. "Unsampled
//    requests do zero *capture* work" still holds; "zero cost" does
//    not — the config docs say so.

use std::cell::RefCell;

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Fixed derivation label for the sampling key: K = HMAC(label, key material).
/// Versioned so a future decision-rule change can re-key deliberately.
const SAMPLING_KEY_DERIVATION_LABEL: &[u8] = b"cerberus-sampling-v1";

/// Hash domains for the session-mode key ladder. `sessionKeyHeader`
/// domains are built at decision time as `"header:<lowercased-name>"`.
pub const DOMAIN_SESSION: &str = "session";
pub const DOMAIN_PRINCIPAL: &str = "principal";
pub const DOMAIN_USER: &str = "user";
pub const DOMAIN_AUTHORIZATION: &str = "authorization";

/// Epoch length for the rotated (coarse identity) tiers — one week.
/// `epoch = unix_seconds / EPOCH_SECONDS`.
pub const EPOCH_SECONDS: u64 = 604_800;

/// K = HMAC-SHA256(key = SAMPLING_KEY_DERIVATION_LABEL, msg = key_material).
pub fn derive_sampling_key(key_material: &str) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(SAMPLING_KEY_DERIVATION_LABEL)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(key_material.as_bytes());
    mac.finalize().into_bytes().into()
}

/// floor(rate · 2⁶⁴) computed in f64, truncating cast (saturates at
/// u64::MAX for products that round up to 2⁶⁴). Callers short-circuit
/// rate ≥ 1.0 and rate ≤ 0.0 before comparing against this.
pub fn threshold_for_rate(rate: f64) -> u64 {
    (rate * (2f64).powi(64)) as u64
}

/// The keyed decision hash: u64 (big-endian) from the first 8 bytes of
/// HMAC-SHA256(K, domain ‖ 0x00 ‖ key [‖ 0x00 ‖ decimal(epoch)]).
fn decision_hash(mac_template: &HmacSha256, domain: &str, key: &str, epoch: Option<u64>) -> u64 {
    let mut mac = mac_template.clone();
    mac.update(domain.as_bytes());
    mac.update(&[0x00]);
    mac.update(key.as_bytes());
    if let Some(epoch) = epoch {
        mac.update(&[0x00]);
        mac.update(epoch.to_string().as_bytes());
    }
    let digest = mac.finalize().into_bytes();
    u64::from_be_bytes(digest[0..8].try_into().expect("SHA-256 digest has 32 bytes"))
}

/// Pure form of the whole decision, for tests and the parity runner:
/// returns (decision hash, keep). Not used on the request path — the
/// policy pre-derives K once (see `KeyedSampler::new`).
pub fn keyed_decision(
    key_material: &str,
    domain: &str,
    key: &str,
    epoch: Option<u64>,
    rate: f64,
) -> (u64, bool) {
    let derived = derive_sampling_key(key_material);
    let template =
        HmacSha256::new_from_slice(&derived).expect("HMAC-SHA256 accepts any key length");
    let h = decision_hash(&template, domain, key, epoch);
    let keep = rate >= 1.0 || (rate > 0.0 && h < threshold_for_rate(rate));
    (h, keep)
}

/// Deterministic keyed-threshold sampler (`sampleBy: session`). See the
/// module docs for the decision rule and its properties.
pub struct KeyedSampler {
    rate: f64,
    threshold: u64,
    /// HMAC state pre-keyed on K — cloned per decision (~2 SHA-256
    /// compressions per decision instead of 4).
    mac_template: HmacSha256,
}

impl KeyedSampler {
    /// `rate` must already be clamped to [0, 1] — `PolicyContext::new`
    /// owns the clamp. `key_material` must be a deployment-level value,
    /// identical on every replica.
    pub fn new(rate: f64, key_material: &str) -> Self {
        let derived = derive_sampling_key(key_material);
        let mac_template =
            HmacSha256::new_from_slice(&derived).expect("HMAC-SHA256 accepts any key length");
        Self {
            rate,
            threshold: threshold_for_rate(rate),
            mac_template,
        }
    }

    /// Keep iff the keyed hash of (domain, key, epoch) lands under the
    /// rate threshold. Rates of exactly 1.0 / 0.0 short-circuit without
    /// hashing.
    pub fn keep(&self, domain: &str, key: &str, epoch: Option<u64>) -> bool {
        if self.rate >= 1.0 {
            return true;
        }
        if self.rate <= 0.0 {
            return false;
        }
        decision_hash(&self.mac_template, domain, key, epoch) < self.threshold
    }
}

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

/// Independent per-request draw. See the module docs for why this is a
/// hand-rolled SplitMix64 rather than `rand`.
pub struct Coin {
    rate: f64,
    state: RefCell<u64>,
}

impl Coin {
    /// `rate` must already be clamped to [0, 1] — `PolicyContext::new`
    /// owns the clamp; the fast paths in `flip` would misread
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
    pub fn flip(&self) -> bool {
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

    // ------------------------------------------------------------------
    // Coin
    // ------------------------------------------------------------------

    #[test]
    fn coin_rate_zero_never_samples() {
        let s = Coin::new(0.0, 42);
        assert!((0..1000).all(|_| !s.flip()));
    }

    #[test]
    fn coin_rate_one_always_samples() {
        let s = Coin::new(1.0, 42);
        assert!((0..1000).all(|_| s.flip()));
    }

    #[test]
    fn coin_same_seed_and_rate_give_identical_sequence() {
        let a = Coin::new(0.5, 0xDEAD_BEEF);
        let b = Coin::new(0.5, 0xDEAD_BEEF);
        let seq_a: Vec<bool> = (0..64).map(|_| a.flip()).collect();
        let seq_b: Vec<bool> = (0..64).map(|_| b.flip()).collect();
        assert_eq!(seq_a, seq_b);
    }

    #[test]
    fn coin_distribution_sanity_at_rate_point_three() {
        // Deterministic given the fixed seed — not a statistical flake.
        let s = Coin::new(0.3, 12345);
        let sampled = (0..100_000).filter(|_| s.flip()).count();
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

    // ------------------------------------------------------------------
    // KeyedSampler
    // ------------------------------------------------------------------

    const KEY_MATERIAL: &str = "test-api-key";

    #[test]
    fn threshold_is_exact_for_dyadic_rates() {
        assert_eq!(threshold_for_rate(0.5), 1u64 << 63);
        assert_eq!(threshold_for_rate(0.25), 1u64 << 62);
        assert_eq!(threshold_for_rate(0.0), 0);
    }

    #[test]
    fn keyed_decision_is_deterministic() {
        let a = keyed_decision(KEY_MATERIAL, DOMAIN_SESSION, "sess-1", None, 0.5);
        let b = keyed_decision(KEY_MATERIAL, DOMAIN_SESSION, "sess-1", None, 0.5);
        assert_eq!(a, b);
    }

    #[test]
    fn keyed_sampler_matches_pure_decision() {
        let s = KeyedSampler::new(0.5, KEY_MATERIAL);
        for i in 0..64 {
            let key = format!("sess-{i}");
            let (_, keep) = keyed_decision(KEY_MATERIAL, DOMAIN_SESSION, &key, None, 0.5);
            assert_eq!(s.keep(DOMAIN_SESSION, &key, None), keep, "key {key}");
        }
    }

    #[test]
    fn sampled_sets_nest_across_rates() {
        // Threshold sampling's defining property: every key kept at a
        // lower rate is still kept at any higher rate.
        for i in 0..300 {
            let key = format!("sess-{i}");
            let (_, at_10) = keyed_decision(KEY_MATERIAL, DOMAIN_SESSION, &key, None, 0.10);
            let (_, at_30) = keyed_decision(KEY_MATERIAL, DOMAIN_SESSION, &key, None, 0.30);
            if at_10 {
                assert!(at_30, "key {key} kept at 0.10 but dropped at 0.30");
            }
        }
    }

    #[test]
    fn keyed_rate_bounds_short_circuit() {
        let never = KeyedSampler::new(0.0, KEY_MATERIAL);
        let always = KeyedSampler::new(1.0, KEY_MATERIAL);
        for i in 0..32 {
            let key = format!("k-{i}");
            assert!(!never.keep(DOMAIN_SESSION, &key, None));
            assert!(always.keep(DOMAIN_SESSION, &key, None));
        }
    }

    #[test]
    fn domains_separate_identical_key_bytes() {
        let (h_session, _) = keyed_decision(KEY_MATERIAL, DOMAIN_SESSION, "shared-bytes", None, 0.5);
        let (h_auth, _) = keyed_decision(KEY_MATERIAL, DOMAIN_AUTHORIZATION, "shared-bytes", None, 0.5);
        let (h_user, _) = keyed_decision(KEY_MATERIAL, DOMAIN_USER, "shared-bytes", None, 0.5);
        assert_ne!(h_session, h_auth);
        assert_ne!(h_session, h_user);
        assert_ne!(h_auth, h_user);
    }

    #[test]
    fn epoch_rotates_the_hash() {
        let (h_a, _) = keyed_decision(KEY_MATERIAL, DOMAIN_PRINCIPAL, "alice", Some(2950), 0.5);
        let (h_b, _) = keyed_decision(KEY_MATERIAL, DOMAIN_PRINCIPAL, "alice", Some(2951), 0.5);
        let (h_none, _) = keyed_decision(KEY_MATERIAL, DOMAIN_PRINCIPAL, "alice", None, 0.5);
        assert_ne!(h_a, h_b, "adjacent epochs must reshuffle");
        assert_ne!(h_a, h_none, "epoch-less hash is its own domain");
    }

    #[test]
    fn epoch_reshuffles_but_preserves_rate() {
        // Rotation changes WHICH identities are sampled, not how many:
        // ~half of 2000 identities keep in each epoch at rate 0.5.
        for epoch in [1000u64, 1001] {
            let kept = (0..2000)
                .filter(|i| {
                    keyed_decision(KEY_MATERIAL, DOMAIN_PRINCIPAL, &format!("u{i}"), Some(epoch), 0.5).1
                })
                .count();
            assert!(
                (900..=1100).contains(&kept),
                "epoch {epoch}: expected ~1000 of 2000 kept, got {kept}"
            );
        }
    }

    #[test]
    fn different_key_material_shuffles_the_sample() {
        let (h_a, _) = keyed_decision("token-a", DOMAIN_SESSION, "sess-1", None, 0.5);
        let (h_b, _) = keyed_decision("token-b", DOMAIN_SESSION, "sess-1", None, 0.5);
        assert_ne!(h_a, h_b);
    }

    #[test]
    fn keyed_distribution_sanity_at_rate_point_three() {
        let kept = (0..10_000)
            .filter(|i| keyed_decision(KEY_MATERIAL, DOMAIN_SESSION, &format!("s{i}"), None, 0.3).1)
            .count();
        assert!(
            (2_800..=3_200).contains(&kept),
            "expected ~30% of 10k keys kept, got {kept}"
        );
    }
}
