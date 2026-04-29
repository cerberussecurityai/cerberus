# Parity Fixtures

Shared YAML fixtures consumed by both the Python (Django middleware /
`cerberus-core`) and Rust (`cerberus-flex-gateway`) parity test runners.
These fixtures are the single source of truth for what the sanitization /
hashing / path-filter contracts produce.

If `SENSITIVE_KEYS` or `SENSITIVE_HEADERS` ever changes in
`cerberus-core/src/cerberus_core/sanitization.py`, the Rust port (which
duplicates the constants) will diverge silently — until the parity tests
fail and force the Rust port to update. **Don't skip these tests.**

## Layout

| File | Tested by Python | Tested by Rust | Notes |
|------|:---:|:---:|---|
| `sanitize_dict.yaml`   | ✅ | ✅ | Body / query-param redaction (`SENSITIVE_KEYS`). |
| `normalize_ip.yaml`    | ✅ | ✅ | IPv6 zone stripping, IPv4-mapped IPv6, etc. |
| `hash_pii.yaml`        | ✅ | ✅ | HMAC-SHA256 hex digests with a fixed test secret. |
| `content_type.yaml`    | ✅ | ✅ | `application/json` substring matching for body capture. |
| `path_filter.yaml`     | ✗  | ✅ | Rust-only. Django scopes per-app via middleware inclusion. |

The Python runner lives at `cerberus-django/tests/test_parity.py`. The Rust
runner is in `cerberus-flex-gateway/tests/parity/` (added when the Rust
crate is scaffolded).

## Format

Each YAML file is a single document with a top-level `cases:` list. Each
case has at minimum `name`, `input`, `expected`. Comments are encouraged.

```yaml
cases:
  - name: simple_password_redaction
    input:
      username: alice
      password: hunter2
    expected:
      username: alice
      password: "[REDACTED]"
```

## How runners consume fixtures

Both crates symlink (or copy) `parity-fixtures/` into their `tests/` tree
so the YAML files are available to test binaries via stable relative
paths. Runner pseudocode:

```
for case in load_yaml(file):
    actual = invoke_under_test(case.input)
    assert actual == case.expected, case.name
```

Comparison is **deep-equality on parsed values**, not byte-equality on
JSON output — Python's `json.dumps` and Rust's `serde_json::to_vec` use
different separators / Unicode escaping by default, so byte-equal JSON
isn't achievable without custom encoders. Parsed equality catches every
behavior we actually care about (field presence, redaction, hash values).

## Adding a case

1. Pick the right file. If your case spans multiple primitives (e.g.
   normalize-then-hash-an-IP), pick the file that owns the *outermost*
   transformation under test, and add a comment pointing at the others.
2. Pick a `name` that reads as a sentence describing the behavior under
   test, e.g. `ipv6_zone_stripped_before_hashing`.
3. Add the case to the YAML. Run **both** parity test suites and confirm
   they pass.
4. If you change `SENSITIVE_KEYS` / `SENSITIVE_HEADERS` in
   `cerberus-core`, update the relevant fixture file in the **same PR**
   so the Rust port has a failing test forcing it to update.

## Test secret

`hash_pii.yaml` uses a single hard-coded secret string
(`cerberus-parity-test-key-v1`). It is **not** sensitive — it is
intentionally public, used only to derive deterministic test hashes.
Production deployments use a different secret distributed via
`event_ingest`'s `/api/secret-key`.
