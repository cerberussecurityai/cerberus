#!/usr/bin/env bash
#
# install.sh — publish the Cerberus Flex Gateway custom policy into YOUR
# Anypoint org's Exchange, so you can apply it to your APIs from API Manager.
#
#   ./install.sh --org-id <YOUR-ANYPOINT-ORG-UUID>
#
# Custom Flex Gateway policies can't be shared across orgs through Exchange, so
# the policy must live in your own org. This wraps MuleSoft's supported PDK CLI
# to do exactly that, using the prebuilt artifacts in this bundle — it needs
# only Node + the Anypoint CLI (see INSTALL.md).
#
# What it does: verifies the bundle, copies the policy project to a TEMP dir
# (never edits the bundle in place), runs `anypoint-cli-v4 pdk policy-project
# build-asset-files` to generate the Exchange asset files stamped with YOUR org
# id, then `anypoint-cli-v4 pdk policy-project release` to publish an immutable
# Exchange asset at the version in ./VERSION.
#
# Supported: macOS + Linux (Windows: run under WSL — see INSTALL.md).
set -euo pipefail

# --- locate ourselves (bundle root) ------------------------------------------
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

prog="$(basename "$0")"
crate="cerberus_flex_gateway"
placeholder="{{CERBERUS_ANYPOINT_GROUP_ID}}"
policy_src="$here/policy"
rel="target/wasm32-wasip1/release"

# --- args --------------------------------------------------------------------
org_id=""
asset_id_suffix=""
environment=""
dry_run=0

usage() {
  cat <<EOF
Usage: ./$prog --org-id <ANYPOINT-ORG-UUID> [options]

Publishes the Cerberus Flex Gateway policy into your Anypoint org's Exchange.

Required:
  --org-id <UUID>         Your Anypoint organization (business group) ID. Find it
                          in Anypoint console -> Access Management -> Organization.
                          You need the "Exchange Contributor" role in this org.

Options:
  --asset-id-suffix <s>   Append "-<s>" to the published asset IDs. Use only if
                          the default IDs collide with an existing asset in your
                          org you don't control.
  --env <name>            Anypoint environment to target (defaults to your CLI's
                          configured environment).
  --dry-run               Print every command without publishing anything.
  -h, --help              Show this help.

Prerequisites (see INSTALL.md): Node >= 18, anypoint-cli-v4 with the
anypoint-pdk-plugin, and an authenticated Anypoint session.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --org-id)          org_id="${2:-}"; shift 2 ;;
    --org-id=*)        org_id="${1#*=}"; shift ;;
    --asset-id-suffix) asset_id_suffix="${2:-}"; shift 2 ;;
    --asset-id-suffix=*) asset_id_suffix="${1#*=}"; shift ;;
    --env)             environment="${2:-}"; shift 2 ;;
    --env=*)           environment="${1#*=}"; shift ;;
    --dry-run)         dry_run=1; shift ;;
    -h|--help)         usage; exit 0 ;;
    *) echo "$prog: unknown argument '$1' (try --help)" >&2; exit 2 ;;
  esac
done

# --- logging helpers ---------------------------------------------------------
info() { printf '  %s\n' "$*"; }
ok()   { printf '  \033[32mok\033[0m  %s\n' "$*"; }
warn() { printf '  \033[33mwarn\033[0m %s\n' "$*" >&2; }
die()  { printf '\n\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# --- validate args -----------------------------------------------------------
[[ -n "$org_id" ]] || { usage; echo; die "--org-id is required."; }
uuid_re='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
[[ "$org_id" =~ $uuid_re ]] || die "--org-id '$org_id' is not a UUID. Use the org UUID from Access Management -> Organization (not the org name)."
if [[ -n "$asset_id_suffix" && ! "$asset_id_suffix" =~ ^[a-z0-9-]+$ ]]; then
  die "--asset-id-suffix '$asset_id_suffix' must be lowercase letters, digits, or hyphens."
fi

version="$(cat "$here/VERSION" 2>/dev/null || true)"
[[ -n "$version" ]] || die "missing ./VERSION — is this the extracted bundle directory?"

step "Cerberus Flex Gateway policy installer  (version $version)"
info "target org : $org_id"
[[ -n "$environment" ]] && info "environment: $environment"
[[ "$dry_run" == 1 ]] && warn "dry-run: no changes will be published."

# --- choose a sha256 tool ----------------------------------------------------
if command -v sha256sum >/dev/null 2>&1; then
  SHA256_CHECK=(sha256sum -c --quiet)
elif command -v shasum >/dev/null 2>&1; then
  SHA256_CHECK=(shasum -a 256 -c)
else
  die "need sha256sum or shasum on PATH to verify bundle integrity."
fi

# =============================================================================
step "1/4  Preflight"
# =============================================================================

# Bundle layout present? We ship the prebuilt wasm + implementation GCL, the
# definition *source* (gcl.yaml), the project descriptor, and an org-agnostic
# publish-metadata template. The PDK regenerates everything else in step 2.
[[ -d "$policy_src" ]] || die "missing ./policy/ — run this from the extracted bundle directory."
wasm="$policy_src/$rel/${crate}.wasm"
impl_gcl="$policy_src/$rel/${crate}_implementation.yaml"
proj_yaml="$policy_src/.project.yaml"
defn_src_gcl="$policy_src/definition/gcl.yaml"
metadata_tmpl="$here/anypoint-metadata.json"
[[ -f "$wasm" ]]          || die "missing policy wasm at policy/$rel/${crate}.wasm"
[[ -f "$impl_gcl" ]]      || die "missing implementation GCL at policy/$rel/${crate}_implementation.yaml"
[[ -f "$proj_yaml" ]]     || die "missing policy/.project.yaml — bundle may be malformed."
[[ -f "$defn_src_gcl" ]]  || die "missing policy/definition/gcl.yaml — bundle may be malformed."
[[ -f "$metadata_tmpl" ]] || die "missing ./anypoint-metadata.json — bundle may be malformed."
ok "bundle layout present"

# Integrity: SHA256SUMS covers the extracted payload.
if [[ -f "$here/SHA256SUMS" ]]; then
  if [[ "$dry_run" == 1 ]]; then
    info "(dry-run) would verify SHA256SUMS"
  elif ( cd "$here" && "${SHA256_CHECK[@]}" SHA256SUMS ) >/dev/null 2>&1; then
    ok "SHA256SUMS verified ($(wc -l < "$here/SHA256SUMS" | tr -d ' ') files)"
  else
    die "SHA256SUMS verification failed — the bundle is incomplete or modified. Re-download it."
  fi
else
  warn "no SHA256SUMS in bundle; skipping integrity check"
fi

# Node >= 18 (the anypoint-pdk-plugin needs >=16.11 for class static blocks;
# we pin >=18).
command -v node >/dev/null 2>&1 || die "Node.js not found. Install Node >= 18 (see INSTALL.md)."
node_major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
[[ "$node_major" -ge 18 ]] || die "Node >= 18 required (found $(node --version)). The Anypoint PDK plugin breaks on older Node."
ok "node $(node --version)"

# Anypoint CLI + PDK plugin
command -v anypoint-cli-v4 >/dev/null 2>&1 || die "anypoint-cli-v4 not found. Install it: npm install -g anypoint-cli-v4 (see INSTALL.md)."
if anypoint-cli-v4 plugins 2>/dev/null | grep -qi 'pdk'; then
  ok "anypoint-cli-v4 + PDK plugin present"
else
  die "the Anypoint PDK plugin is not installed. Run: anypoint-cli-v4 plugins:install anypoint-pdk-plugin"
fi

# Authenticated session (and, implicitly, that the org/role works). pdk get-token
# mints a bearer token against the configured credentials.
if [[ "$dry_run" == 1 ]]; then
  info "(dry-run) would verify an authenticated Anypoint session"
elif anypoint-cli-v4 pdk get-token >/dev/null 2>&1; then
  ok "authenticated Anypoint session"
else
  die "no authenticated Anypoint session. Configure the CLI (client_id/client_secret/organization) — see INSTALL.md."
fi

# =============================================================================
step "2/4  Stage the project and build asset files for your org"
# =============================================================================
# Never edit the bundle in place: copy policy/ to a temp dir and let the PDK
# regenerate the Exchange asset files there, stamped with YOUR org id.
work="$(mktemp -d "${TMPDIR:-/tmp}/cerberus-flex-install.XXXXXX")"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT
cp -R "$policy_src" "$work/policy"
proj="$work/policy"
ok "staged to $proj"

# Build the publish metadata from the shipped template: substitute YOUR org id
# for the placeholder and (optionally) append the asset-id suffix to the asset
# ids. The PDK reads these via --metadata and bakes them into the generated
# exchange.json / definition.zip, so nothing generated needs hand-editing.
metadata="$(sed "s/${placeholder}/${org_id}/g" "$metadata_tmpl")"
grep -q "$placeholder" <<<"$metadata" && die "placeholder still present in metadata after stamping — aborting."
grep -q "$org_id"      <<<"$metadata" || die "failed to stamp org id into the publish metadata — bundle may be malformed."
if [[ -n "$asset_id_suffix" ]]; then
  metadata="$(sed -E "s/(\"(definition|implementation)-asset-id\"[[:space:]]*:[[:space:]]*\"[a-z0-9-]+)\"/\1-${asset_id_suffix}\"/g" <<<"$metadata")"
  ok "appended asset-id suffix '-$asset_id_suffix'"
fi

# Regenerate the definition + implementation asset files (definition.zip,
# exchange.json, metadata.yaml, schema.json) under the staged project's target/
# dirs, stamped for your org. This step does no network I/O and no publish — so
# it runs in dry-run too (it only writes into the temp dir).
#
# --metadata accepts inline JSON (confirmed against PDK 1.8.0). If a future PDK
# upgrade makes it expect a file path instead, write $metadata to a temp file
# (e.g. "$work/metadata.json") and pass that path here.
info "running: anypoint-cli-v4 pdk policy-project build-asset-files --metadata <stamped-json>"
ba_log="$work/build-asset-files.log"
if ! ( cd "$proj" && anypoint-cli-v4 pdk policy-project build-asset-files --metadata "$metadata" ) >"$ba_log" 2>&1; then
  cat "$ba_log" >&2
  die "failed to build asset files (pdk policy-project build-asset-files). See the CLI output above and INSTALL.md troubleshooting."
fi
defn_zip="$proj/definition/target/asset/definition.zip"
impl_exchange="$proj/target/implementation/exchange.json"
[[ -f "$defn_zip" ]]      || die "build-asset-files did not produce definition.zip — cannot publish."
[[ -f "$impl_exchange" ]] || die "build-asset-files did not produce the implementation exchange.json — cannot publish."
grep -q "$org_id" "$impl_exchange" || die "generated implementation exchange.json is missing your org id — aborting."
ok "built asset files (definition.zip + exchange descriptors) stamped for org $org_id"

# =============================================================================
step "3/4  Check for an existing install (idempotency)"
# =============================================================================
# Exchange versions are immutable: re-publishing the same version is a no-op
# error. Detect a prior install and exit 0 cleanly.
impl_asset="$(awk -F'"' '/"assetId"/{print $4; exit}' "$proj/target/implementation/exchange.json" 2>/dev/null || echo "")"
already=0
if [[ "$dry_run" == 1 ]]; then
  info "(dry-run) would check Exchange for ${impl_asset:-the policy} v$version in org $org_id"
elif [[ -n "$impl_asset" ]] && \
     anypoint-cli-v4 exchange asset describe "$org_id/$impl_asset/$version" >/dev/null 2>&1; then
  already=1
fi
if [[ "$already" == 1 ]]; then
  ok "already installed: $impl_asset v$version is present in org $org_id"
  step "Done — nothing to do."
  echo "Apply it from Anypoint API Manager (Custom policies). See INSTALL.md."
  exit 0
fi
ok "no existing v$version found — proceeding to publish"

# =============================================================================
step "4/4  Publish to Exchange (immutable release)"
# =============================================================================
publish_args=(
  pdk policy-project release
  --organization "$org_id"
  --binary-path "$rel/${crate}.wasm"
  --implementation-gcl-path "$rel/${crate}_implementation.yaml"
)
[[ -n "$environment" ]] && publish_args+=(--environment "$environment")

info "running from: $proj"
set +e
if [[ "$dry_run" == 1 ]]; then
  printf '  + (cd %s && ANYPOINT_ORG=%s anypoint-cli-v4 %s)\n' "$proj" "$org_id" "${publish_args[*]}"
  rc=0
else
  ( cd "$proj" && ANYPOINT_ORG="$org_id" anypoint-cli-v4 "${publish_args[@]}" )
  rc=$?
fi
set -e

if [[ "$rc" -ne 0 ]]; then
  # Treat "version already exists" as success: Exchange versions are immutable,
  # so a concurrent install (two runners racing past step 3) or a publish that
  # actually landed before erroring is a no-op, not a failure. Re-query Exchange
  # and exit 0 if the asset is present; otherwise it's a real error.
  if [[ -n "$impl_asset" ]] && \
     anypoint-cli-v4 exchange asset describe "$org_id/$impl_asset/$version" >/dev/null 2>&1; then
    ok "$impl_asset v$version is already in org $org_id — treating as success (Exchange versions are immutable)."
    step "Done — nothing to do."
    echo "Apply it from Anypoint API Manager (Custom policies). See INSTALL.md."
    exit 0
  fi
  die "publish failed (exit $rc). See the CLI output above and INSTALL.md troubleshooting."
fi

step "Done."
echo "Published $crate v$version into org $org_id."
echo "Next: apply it to your API in Anypoint API Manager (Custom policies tab)."
echo "See INSTALL.md -> \"Apply the policy\" for the walkthrough and config example."
