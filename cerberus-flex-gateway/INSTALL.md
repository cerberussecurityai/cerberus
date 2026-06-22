# Installing the Cerberus Flex Gateway policy (Connected Mode)

This guide installs the Cerberus custom policy into **your own** MuleSoft
Anypoint organization, then applies it to an API in API Manager. It ships with
the distribution bundle (`cerberus-flex-gateway-policy-<version>.tar.gz`) and is
also kept in the repo at `cerberus-flex-gateway/INSTALL.md`.

> The policy ships as a prebuilt WebAssembly artifact — you only need Node and
> the Anypoint CLI to install it.

## Why you publish it into your own org

MuleSoft Exchange can't make a custom Flex Gateway policy applicable across
organizations — a custom policy is only available to APIs in the org whose
Exchange holds it. So each customer publishes the prebuilt policy into their own
org. `install.sh` wraps MuleSoft's supported PDK CLI to do this, stamping in your
Anypoint org ID at install time.

## Prerequisites

| Requirement | Notes |
|---|---|
| **Anypoint account** | With the **Exchange Contributor** role in the target org/business group. |
| **Anypoint org (business group) UUID** | Anypoint console → Access Management → Organization. It's a UUID, **not** the org name. |
| **Node ≥ 18** | The Anypoint PDK plugin uses modern JS that breaks on older Node. |
| **`anypoint-cli-v4` + PDK plugin** | Install below. |
| **Cerberus API key + ingest URL** | From your Cerberus account — used when you *apply* the policy, not when you install it. |
| OS | macOS or Linux. **Windows:** run under WSL. |

Install the CLI and plugin:

```bash
npm install -g anypoint-cli-v4
anypoint-cli-v4 plugins:install anypoint-pdk-plugin   # NB: not "anypoint-cli-pdk-plugin"
```

Authenticate the CLI (client-credentials of a Connected App with **Exchange
Contributor** in the target org):

```bash
anypoint-cli-v4 conf client_id     <connected-app-client-id>
anypoint-cli-v4 conf client_secret <connected-app-client-secret>
anypoint-cli-v4 conf organization  <your-org-uuid>
anypoint-cli-v4 conf environment   <your-environment>      # e.g. Sandbox

anypoint-cli-v4 pdk get-token       # smoke test: should print a bearer token
```

## Install

Download and extract the bundle, then run the installer with your org UUID:

```bash
tar -xzf cerberus-flex-gateway-policy-<version>.tar.gz
cd cerberus-flex-gateway-policy-<version>

# Optional: verify the download against the published checksum first
shasum -a 256 -c ../SHA256SUMS-<version>.txt   # or sha256sum -c

./install.sh --org-id <your-org-uuid>
```

The installer:

1. **Preflights** — verifies Node ≥ 18, the Anypoint CLI + PDK plugin, an
   authenticated session, and the bundle's `SHA256SUMS`.
2. **Stages** a temp copy of the policy project and runs `anypoint-cli-v4 pdk
   policy-project build-asset-files` to generate the Exchange asset files stamped
   with your org id (pure Node/PDK — no Rust toolchain involved).
3. **Checks** whether this version is already in your Exchange — if so it prints
   "already installed" and exits cleanly (Exchange versions are immutable).
4. **Publishes** an immutable release into your org's Exchange via
   `anypoint-cli-v4 pdk policy-project release`.

Useful flags:

| Flag | Purpose |
|---|---|
| `--dry-run` | Print every command without publishing anything. Run this first to see exactly what will happen. |
| `--env <name>` | Target a specific Anypoint environment (defaults to your CLI config). |
| `--asset-id-suffix <s>` | Append `-<s>` to the published asset IDs. Only needed if the default IDs collide with an existing asset in your org. |
| `--help` | Full usage. |

## Apply the policy

Once published, apply it to an API instance in **Anypoint API Manager**:

1. API Manager → your API instance → **Policies** → **Add policy** → **Custom**
   tab → select **cerberus-flex-gateway**.
2. Fill the config form (rendered from the policy's schema). Minimum:
   - `ingestService` — your Cerberus backend URL (the policy POSTs to
     `<ingestService>/v1/ingest/batch`).
   - `token` — your Cerberus API key (sent as `X-API-Key`).
3. Apply, then drive traffic and confirm events land in your Cerberus dashboard.

Or via CLI:

```bash
anypoint-cli-v4 api-mgr policy apply \
  --apiInstanceId <id> \
  --policyId cerberus-flex-gateway \
  --config '{"ingestService":"https://ingest.cerberus.example.com","token":"<your-api-key>"}'
```

See the policy README's **Configuration** table for every option
(`capturePaths`, `secretKey`, `batchSize`, `flushIntervalMs`, …).

## Upgrade

A new bundle version is a new immutable Exchange version. Extract the new
tarball and run `./install.sh --org-id <your-org-uuid>` again — it publishes the
new version alongside the old. Then bump the policy version on your API instance
in API Manager.

## Uninstall

1. Remove the policy from any API instances in API Manager.
2. Optionally deprecate/delete the Exchange asset in your org's Exchange (the
   installer does not delete assets).

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `--org-id … is not a UUID` | Use the org **UUID** from Access Management → Organization, not the org name. |
| `no authenticated Anypoint session` | Re-run the `anypoint-cli-v4 conf …` steps; verify with `anypoint-cli-v4 pdk get-token`. |
| `the Anypoint PDK plugin is not installed` | `anypoint-cli-v4 plugins:install anypoint-pdk-plugin` (note: not `anypoint-cli-pdk-plugin`). |
| `Node >= 18 required` | The PDK plugin crashes on older Node with `Unexpected token '{'`. Install Node ≥ 18. |
| Publish fails with a permissions/403 error | Your account lacks **Exchange Contributor** in the target org, or `--org-id` points at an org where you don't have it. |
| Publish says the version already exists | It's already installed — Exchange versions are immutable. Nothing to do (the installer treats this as success). |
| Every batch 403s **after** applying the policy | The Cerberus `token` you entered in API Manager has surrounding whitespace (e.g. a trailing newline from copy-paste). The policy trims whitespace, but double-check the value. |
| `SHA256SUMS verification failed` | The extracted bundle is incomplete or modified — re-download and re-extract. |

For development/build details (Rust toolchain, local-mode, parity tests) see
the `cerberus-flex-gateway` project repository (`README.md` and
`DEVELOPMENT.md`).
