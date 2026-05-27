// HMAC-SHA256 hashing + IP normalization. Mirrors cerberus-core's
// `hash_pii` and `normalize_ip` Python helpers.
//
// See cerberus-core/src/cerberus_core/sanitization.py:37-80 for the
// canonical Python implementations and parity-fixtures/{normalize_ip,
// hash_pii}.yaml for the cross-impl test cases.

use std::net::{IpAddr, Ipv6Addr};

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 of `value` keyed on `secret`. Returns the lowercase hex
/// digest. Deterministic — same input always produces the same digest,
/// so analytics can dedupe / track "same IP across requests" without
/// storing raw PII.
pub fn hash_pii(value: &str, secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(value.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Normalize an IP string to its canonical form so the same logical
/// address always hashes identically.
///
/// Steps:
///   1. Strip the IPv6 zone ID (`%eth0`, `%25en0`, ...).
///   2. Trim surrounding whitespace.
///   3. Parse as IPv4 or IPv6.
///   4. Re-format canonically:
///      - IPv4 → standard dotted decimal.
///      - IPv6 → compressed hex form, **including** for IPv4-mapped
///        addresses (`::ffff:1.2.3.4` → `::ffff:c0a8:101`). Rust's
///        default `Ipv6Addr::to_string()` formats IPv4-mapped in
///        dotted-quad form; that diverges from Python's `ipaddress`
///        module, so we override.
///   5. On parse failure: return the input unchanged.
pub fn normalize_ip(ip_string: &str) -> String {
    let no_zone = ip_string.split('%').next().unwrap_or("").trim();
    if no_zone.is_empty() {
        return ip_string.to_string();
    }
    match no_zone.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Ok(IpAddr::V6(v6)) => format_ipv6_python_compat(v6),
        Err(_) => ip_string.to_string(),
    }
}

/// Format an IPv6 address matching Python's ipaddress.IPv6Address.compressed.
///
/// Per RFC 5952:
///   * Use `::` to compress the longest run of consecutive zero
///     16-bit groups (only if the run is at least 2 long).
///   * On ties, compress the leftmost run.
///   * Hex digits are lowercase, leading zeros within each group are
///     suppressed.
///
/// Python's compressed form does not switch to dotted-quad notation for
/// IPv4-mapped addresses (::ffff:0:0/96) — Rust's Display impl does.
/// We follow Python.
fn format_ipv6_python_compat(addr: Ipv6Addr) -> String {
    let segments = addr.segments();

    // Find the longest run of zero segments to compress.
    let (best_start, best_len) = find_longest_zero_run(&segments);

    let mut out = String::with_capacity(39);
    let mut i = 0usize;

    while i < 8 {
        if best_len >= 2 && i == best_start {
            // Always write the full "::" — it represents both the
            // separator-after-prev and the separator-before-next, with
            // the elided zero-run in between. The next segment's
            // prefix-colon is suppressed below because `out` ends with
            // ':' after we write here.
            out.push_str("::");
            i += best_len;
            continue;
        }
        // Prefix-colon between segments, but only if there isn't
        // already a trailing colon from a `::` we just wrote.
        if !out.is_empty() && !out.ends_with(':') {
            out.push(':');
        }
        out.push_str(&format!("{:x}", segments[i]));
        i += 1;
    }
    if out.is_empty() {
        // No segments and no compression — Ipv6Addr can never produce
        // an empty `out` reachable here, but keep the guard for safety.
        return "::".to_string();
    }
    out
}

fn find_longest_zero_run(segments: &[u16; 8]) -> (usize, usize) {
    let mut best_start = 0;
    let mut best_len = 0;
    let mut cur_start = 0;
    let mut cur_len = 0;
    for (i, &seg) in segments.iter().enumerate() {
        if seg == 0 {
            if cur_len == 0 {
                cur_start = i;
            }
            cur_len += 1;
            if cur_len > best_len {
                best_start = cur_start;
                best_len = cur_len;
            }
        } else {
            cur_len = 0;
        }
    }
    (best_start, best_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_pii_is_deterministic() {
        let a = hash_pii("192.168.1.1", "secret");
        let b = hash_pii("192.168.1.1", "secret");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // SHA-256 hex
    }

    #[test]
    fn hash_pii_changes_with_secret() {
        let a = hash_pii("192.168.1.1", "secret-1");
        let b = hash_pii("192.168.1.1", "secret-2");
        assert_ne!(a, b);
    }

    #[test]
    fn normalize_strips_ipv6_zone() {
        assert_eq!(normalize_ip("fe80::1%eth0"), "fe80::1");
        assert_eq!(normalize_ip("fe80::1%25en0"), "fe80::1");
    }

    #[test]
    fn normalize_passes_invalid_through() {
        assert_eq!(normalize_ip("not-an-ip"), "not-an-ip");
        assert_eq!(normalize_ip(""), "");
    }

    #[test]
    fn normalize_ipv4_mapped_uses_hex_segments() {
        // Diverges from std::net::Ipv6Addr::to_string() — match Python's
        // ipaddress module, which always emits hex segments.
        assert_eq!(normalize_ip("::ffff:192.168.1.1"), "::ffff:c0a8:101");
    }

    #[test]
    fn normalize_compresses_long_form() {
        assert_eq!(
            normalize_ip("0000:0000:0000:0000:0000:0000:0000:0001"),
            "::1"
        );
    }
}
