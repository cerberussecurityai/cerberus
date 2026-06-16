#!/usr/bin/env bash
#
# bundle.sh — assemble the customer distribution tarball from `make build`
# output. Run by `make bundle` (which builds first) and by the release CI.
#
# Output: dist/cerberus-flex-gateway-policy-<version>.tar.gz + a sibling
# dist/SHA256SUMS-<version>.txt (the bundle's own integrity file, for the
# customer to verify the *download*; an in-bundle SHA256SUMS covers the
# extracted payload for install.sh's preflight).
#
# The bundle ships PREBUILT, org-agnostic artifacts — no Rust sources, nothing
# to compile. Our internal Anypoint group_id is rewritten to the placeholder
# {{CERBERUS_ANYPOINT_GROUP_ID}} so our org never leaks into a customer bundle;
# install.sh stamps the customer's real org id into a temp copy at install time.
#
# BUILD-SIDE ONLY. This script needs the `make build` artifacts present; it does
# not run cargo itself (the Makefile target orders `build` before `bundle`).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"

# --- toolchain for hashing (macOS: shasum -a 256, Linux: sha256sum) ----------
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$@"; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$@"; }
else
  echo "bundle: need sha256sum or shasum on PATH" >&2
  exit 1
fi

# --- single source of truth: version + internal group_id from Cargo.toml -----
# crate `version` and the `[package.metadata.anypoint]` group_id. Parsed with
# awk so there is exactly one place these live.
version="$(awk -F'"' '/^\[package\]/{p=1} p&&/^version *=/{print $2;exit}' Cargo.toml)"
internal_group_id="$(awk -F'"' '/^\[package.metadata.anypoint\]/{p=1} p&&/^group_id *=/{print $2;exit}' Cargo.toml)"

if [[ -z "$version" || -z "$internal_group_id" ]]; then
  echo "bundle: failed to parse version ('$version') or group_id ('$internal_group_id') from Cargo.toml" >&2
  exit 1
fi

crate="cerberus_flex_gateway"            # cargo anypoint get-name (underscores)
placeholder="{{CERBERUS_ANYPOINT_GROUP_ID}}"
rel="target/wasm32-wasip1/release"
wasm="$rel/${crate}.wasm"
impl_gcl="$rel/${crate}_implementation.yaml"

echo "bundle: version=$version  internal_group_id=$internal_group_id"

# --- verify the build output is present (fail loud, not a half bundle) --------
require() { [[ -e "$1" ]] || { echo "bundle: missing build artifact '$1' — run 'make build' first" >&2; exit 1; }; }
require "$wasm"
require "$impl_gcl"
require "definition/target/definition/exchange.json"
require "definition/target/definition/gcl.yaml"
require "target/implementation/exchange.json"
require "target/implementation/metadata.yaml"
require ".project.yaml"

# --- stage --------------------------------------------------------------------
name="cerberus-flex-gateway-policy-${version}"
out="dist"
stage="$out/$name"
rm -rf "$out"
mkdir -p "$stage/policy"

# Mirror the real PDK project paths so `anypoint-cli-v4 pdk policy-project
# release` discovers the asset files exactly as it does in-repo. We ship the
# generated asset *files*, not the `asset/*.zip` archives — the CLI repackages
# those at publish time, and a zip can't carry the org-id placeholder.
mkdir -p "$stage/policy/$rel" \
         "$stage/policy/definition/target/definition" \
         "$stage/policy/target/implementation"

cp "$wasm"                  "$stage/policy/$rel/"
cp "$impl_gcl"              "$stage/policy/$rel/"
cp .project.yaml            "$stage/policy/.project.yaml"
cp target/policy-ref-name.txt "$stage/policy/target/policy-ref-name.txt" 2>/dev/null || true

# Copy every generated definition asset file (exchange.json, gcl.yaml,
# metadata.yaml, schema.json, gcl_src.yaml). Skip any asset/*.zip.
find definition/target/definition -maxdepth 1 -type f \
  -exec cp {} "$stage/policy/definition/target/definition/" \;

cp target/implementation/exchange.json \
   target/implementation/metadata.yaml \
   "$stage/policy/target/implementation/"

# --- de-identify: internal group_id -> placeholder in every exchange.json -----
# (group_id appears ONLY in the exchange.json files — verified: the wasm and
# both GCLs carry no org identity.) Replace it everywhere so a `grep` for our
# org in the bundle comes up empty.
stamped=0
while IFS= read -r -d '' f; do
  if grep -q "$internal_group_id" "$f"; then
    sed -i.bak "s/${internal_group_id}/${placeholder}/g" "$f" && rm -f "$f.bak"
    stamped=$((stamped + 1))
  fi
done < <(find "$stage/policy" -name 'exchange.json' -print0)
echo "bundle: rewrote internal group_id -> placeholder in $stamped exchange.json file(s)"

# Safety net: our org id must not survive anywhere in the staged payload.
if grep -rq "$internal_group_id" "$stage/policy"; then
  echo "bundle: ERROR internal group_id still present in staged bundle:" >&2
  grep -rl "$internal_group_id" "$stage/policy" >&2
  exit 1
fi

# --- ship the installer, docs, license, version ------------------------------
cp install.sh "$stage/install.sh"
chmod +x "$stage/install.sh"
cp INSTALL.md "$stage/INSTALL.md"
cp ../LICENSE "$stage/LICENSE" 2>/dev/null || cp LICENSE "$stage/LICENSE" 2>/dev/null || true
printf '%s\n' "$version" > "$stage/VERSION"

# --- SHA256SUMS over the extracted payload (for install.sh preflight) --------
# Lists every shipped file except SHA256SUMS itself, paths relative to $stage.
( cd "$stage" && find . -type f ! -name 'SHA256SUMS' | LC_ALL=C sort | sed 's#^\./##' | while read -r p; do
    sha256 "$p"
  done > SHA256SUMS )
echo "bundle: wrote $(wc -l < "$stage/SHA256SUMS" | tr -d ' ') entries to SHA256SUMS"

# --- tarball + download-integrity sums ---------------------------------------
tarball="$out/${name}.tar.gz"
# --owner=0 --group=0 --numeric-owner store ownership as root (0/0) regardless
# of who runs the build, so our local username never leaks into the published
# bundle and a root extract yields predictable ownership. All three are
# supported by both GNU tar and bsdtar (macOS). Integrity is verified via the
# two SHA256SUMS files (in-bundle payload + download), not tarball byte-identity.
tar --owner=0 --group=0 --numeric-owner -czf "$tarball" -C "$out" "$name"

( cd "$out" && sha256 "$(basename "$tarball")" > "SHA256SUMS-${version}.txt" )

echo "bundle: created $tarball"
echo "bundle: created $out/SHA256SUMS-${version}.txt"
