#!/usr/bin/env bash
# Post-process the toolchain-generated init hook (src/generated/config.rs,
# written by `cargo anypoint config-gen`) so a configuration that fails to
# deserialize is reported WITHOUT echoing the configuration. The config
# carries `token` / `secretKey`, and the PDK runtime writes the init error
# to the gateway log at Error level.
#
# Invoked by `make build-asset-files` right after config-gen. Idempotent.
# Fails loudly if the generated code no longer has the expected shape (e.g.
# after a cargo-anypoint upgrade) so the echo cannot slip back in unnoticed;
# `config::tests::generated_init_hook_does_not_echo_config` is the second
# tripwire.
set -euo pipefail

file="${1:-src/generated/config.rs}"

if grep -q 'crate::config::redact_parse_error' "$file" && ! grep -q 'from_utf8_lossy' "$file"; then
  exit 0 # already patched
fi

perl -pi -e '
  s/"Failed to parse configuration \x27\{\}\x27\. Cause: \{\}"/"Failed to parse configuration. Cause: {}"/;
  s/String::from_utf8_lossy\(abi\.get_configuration\(\)\), err/crate::config::redact_parse_error(abi.get_configuration(), &err)/;
' "$file"

if grep -q 'from_utf8_lossy' "$file" || ! grep -q 'crate::config::redact_parse_error' "$file"; then
  echo "error: $file: generated init hook is not in the shape this script expects;" >&2
  echo "       update scripts/redact_generated_config.sh so the parse error never echoes the config" >&2
  exit 1
fi
