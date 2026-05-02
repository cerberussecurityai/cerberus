// Source IP resolution.
//
// Strategy:
//   1. Read the configured `clientIpHeader` (default X-Forwarded-For).
//      If present and non-empty, take the first hop (everything left of
//      the first comma), trim, and strip a trailing port if present.
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
            // XFF values normally don't carry a port, but some
            // upstreams do append one. Strip defensively so the
            // hashed/stored value is consistent with the connection-
            // source path.
            return Some(strip_port(first_hop));
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
    // IPv6 in bracketed form: `[addr]:port` or `[addr]`.
    if let Some(stripped) = s.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            return stripped[..end].to_string();
        }
        // Malformed: leading `[` with no closing `]`. Fall through and
        // treat as opaque rather than mangle by stripping the bracket.
    }
    // IPv4 form. Only strip if there's exactly one colon — multi-colon
    // input is almost certainly IPv6 without brackets, and stripping
    // would corrupt the address.
    let colon_count = s.bytes().filter(|b| *b == b':').count();
    if colon_count == 1 {
        if let Some((host, _port)) = s.rsplit_once(':') {
            return host.to_string();
        }
    }
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
