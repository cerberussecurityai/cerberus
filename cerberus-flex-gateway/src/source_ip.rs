// Source IP resolution.
//
// Strategy (per flex_gateway_plan.md §0 row 5):
//   1. Read the configured `clientIpHeader` (default X-Forwarded-For).
//      If present and non-empty, take the first hop (everything left of
//      the first comma) and trim. This is the externally-observed client
//      IP behind any number of LBs / proxies.
//   2. Otherwise, fall back to Envoy's source.address stream property.
//      That gives "host:port" form ("1.2.3.4:54321" or "[::1]:54321") —
//      strip the port.
//   3. If neither yields a usable string, return None and the event
//      ships without remote_addr.
//
// Hashing happens in lib.rs via PolicyContext::maybe_hash AFTER
// normalization (normalize_ip strips IPv6 zone IDs etc.).

use pdk::hl::{PropertyAccessor, StreamProperties};

/// Pick a source IP from (a) the configured client IP header (e.g.
/// X-Forwarded-For first hop) or (b) the Envoy connection source.
///
/// Caller is expected to read the header value via
/// `state.handler().header(<configured-name>)` and pass it in. Keeping
/// the PDK header-handler type out of this signature lets the module
/// compile and unit-test independently of the PDK harness.
pub fn resolve(client_ip_header_value: Option<String>, stream: &StreamProperties) -> Option<String> {
    if let Some(value) = client_ip_header_value {
        let first_hop = value.split(',').next().unwrap_or("").trim();
        if !first_hop.is_empty() {
            return Some(first_hop.to_string());
        }
    }
    let bytes = stream.read_property(&["source", "address"])?;
    let s = std::str::from_utf8(&bytes).ok()?;
    Some(strip_port(s))
}

/// "1.2.3.4:5678" → "1.2.3.4"
/// "[::1]:5678"   → "::1"
/// "1.2.3.4"      → "1.2.3.4"  (passthrough — no port)
fn strip_port(s: &str) -> String {
    let s = s.trim();
    if let Some(stripped) = s.strip_prefix('[') {
        // IPv6 form `[addr]:port`
        if let Some(end) = stripped.find(']') {
            return stripped[..end].to_string();
        }
        return stripped.to_string();
    }
    // IPv4 form. Only strip if there's exactly one colon AND the colon
    // isn't part of an IPv6 address with no brackets (some Envoy builds
    // emit `::1:5678` without brackets — hard to disambiguate).
    let colon_count = s.bytes().filter(|b| *b == b':').count();
    if colon_count == 1 {
        if let Some((host, _port)) = s.rsplit_once(':') {
            return host.to_string();
        }
    }
    // Multi-colon and no brackets — assume IPv6 without port.
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::strip_port;

    #[test]
    fn strips_ipv4_port() {
        assert_eq!(strip_port("1.2.3.4:5678"), "1.2.3.4");
    }

    #[test]
    fn strips_ipv6_bracketed_port() {
        assert_eq!(strip_port("[::1]:5678"), "::1");
        assert_eq!(strip_port("[fe80::1]:443"), "fe80::1");
    }

    #[test]
    fn passes_through_no_port() {
        assert_eq!(strip_port("1.2.3.4"), "1.2.3.4");
        assert_eq!(strip_port("fe80::1"), "fe80::1");
    }
}
