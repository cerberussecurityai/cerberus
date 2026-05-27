# Local Development Setup (Apple Silicon macOS)

End-to-end setup for iterating on the Cerberus Flex Gateway custom policy:
Anypoint account → CLI install → registration → `make run` → verify a sanitized
batch arrives at the mock backend.

This is **dev-facing** — for operator deployment guidance see `README.md`.

## Prerequisites

```bash
# Node 18+ — the anypoint-pdk-plugin uses modern JS syntax that breaks on Node 16.
nvm install 20 && nvm use 20

# Rust + the wasm target.
brew install rustup
rustup target add wasm32-wasip1

# Cargo helpers used by the PDK build pipeline.
cargo install --locked cargo-generate
cargo install --locked cargo-anypoint@1.8.0

# Docker Desktop with Rosetta enabled for x86_64 emulation.
# Settings → General → "Use Rosetta for x86/amd64 emulation on Apple Silicon".
# The mulesoft/flex-gateway image is amd64-only; running it on M-series
# Macs requires Rosetta. This option may not appear depending on your Docker
# version, in which case you can assume it's enabled.
```

## Anypoint Platform setup

1. **Create a free Anypoint trial:** https://anypoint.mulesoft.com/login/signup
2. Note your **Organization UUID** from Anypoint console → Access Management →
   Organization (it's a UUID, not the org name).
3. Note your **Sandbox Environment UUID** from Access Management → Environments.

### Create a Connected App

Anypoint console → Access Management → Connected Apps → **Create app**:

- Name: `cerberus-pdk-cli` (anything memorable)
- Type: **App acts on its own behalf** (client credentials grant) — *not* "on
  behalf of a user"
- Scopes (add for the **Sandbox** environment, not just root org):
  - **View Organization** *(Access Management group)*
  - **Read Servers** *(Runtime Manager group)*
  - **Manage Servers** *(Runtime Manager group)*
  - **Exchange Contributor** — needed for `make publish` / `make release`
  - **Manage APIs Configuration** — needed if you'll apply the policy via
    API Manager in connected mode

After saving, **copy the client_secret immediately** — it's only shown once.
If you lose it you'll need to rotate.

## Install the Anypoint CLI

```bash
npm install -g anypoint-cli-v4
anypoint-cli-v4 plugins:install anypoint-pdk-plugin   # NB: not "anypoint-cli-pdk-plugin"
```

The plugin was renamed in PDK 1.7.0 — older docs reference the wrong name.

## Configure CLI authentication

```bash
anypoint-cli-v4 conf client_id <connected-app-client-id>
anypoint-cli-v4 conf client_secret <connected-app-client-secret>
anypoint-cli-v4 conf organization <org-uuid>
anypoint-cli-v4 conf environment Sandbox
```

Smoke test (should print your org without prompting):

```bash
anypoint-cli-v4 account business-group list
anypoint-cli-v4 pdk get-token   # prints a bearer token
```

### Common 401 causes

- **`/accounts/login` in the error URL** → the CLI is falling back to
  username/password auth. Run `anypoint-cli-v4 conf username --delete` and
  `password --delete` to clear stale values from earlier setup.
- **Connected App scopes only granted at root org** → the picker requires
  selecting a business-group/environment when adding scopes. Re-grant for the
  specific Sandbox env you'll target.
- **Wrong `organization` UUID** → must be the org/BG where the Connected App
  scopes were granted.

## Generate the registration.yaml

The Flex Gateway docker image needs a `registration.yaml` to start, even in
local mode. Generate it once via `flexctl`:

```bash
cd cerberus-flex-gateway/playground/config

docker run --rm \
  --platform linux/amd64 \
  --entrypoint flexctl \
  -v "$(pwd)":/registration \
  -u $(id -u) \
  mulesoft/flex-gateway:1.10.0 \
  registration create \
  --client-id=<connected-app-client-id> \
  --client-secret=<connected-app-client-secret> \
  --organization=<org-uuid> \
  --environment=<sandbox-env-uuid> \
  --connected=false \
  --output-directory=/registration \
  cerberus-local-dev
```

**Critical flag:** `--connected=false`. With `--connected=true`, the gateway
rejects local `api.yaml` files (`the resource is not allowed in connected
mode`) — connected mode expects API definitions to come from API Manager.

If registration fails with *"an active target with the same name already
exists"*, either pick a different name (e.g. `cerberus-local-dev2`) or delete
the old entry in Anypoint → Runtime Manager → Flex Gateway.

The output (`registration.yaml` + `certificate.yaml`) is gitignored — it's
tied to a specific Connected App and Anypoint env, so don't commit it.

## Build and run

```bash
cd cerberus-flex-gateway

make sync-fixtures    # one-time: symlink ../parity-fixtures into tests/fixtures
make build            # compile to wasm32-wasip1 + emit GCL artifacts
make test             # 28 unit tests + 6 parity tests
make run              # docker compose up — blocks the terminal
```

`make run` boots two containers:

- `playground-local-flex-1` — Flex Gateway listening on `localhost:8081`
- `playground-echo-1` — `mendhak/http-https-echo` playing two roles:
  - the **upstream** the gateway routes traffic to
  - the **mock Cerberus backend** that the policy POSTs sanitized batches to
    (because `playground/config/api.yaml` sets `ingestService: http://echo:8080`)

Look for these in the logs to confirm a clean boot:

```
all dependencies initialized. starting workers
cerberus-flex-gateway: configured with token_len=9
```

## Verify end to end

In a second terminal, send a request that exercises sanitization:

```bash
curl -X POST 'http://localhost:8081/api/test?password=hunter2&user=alice' \
  -H 'Authorization: Bearer secret-token' \
  -H 'X-Forwarded-For: 1.2.3.4' \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"abc","note":"hi"}'
```

The upstream echoes the proxied request immediately (200 OK with the request
body). After ~2s the policy flushes a batch — find it with:

```bash
docker logs playground-echo-1 2>&1 | grep -B 1 -A 80 '"path": "/v1/ingest/batch"'
```

Expected sanitization in the batch payload:

| Field | Sent | In batch |
|---|---|---|
| `query.password` | `hunter2` | `[REDACTED]` |
| `query.user` | `alice` | `alice` (not sensitive) |
| `body.password` | `abc` | `[REDACTED]` |
| `body.email` | `alice@example.com` | passthrough (not in `SENSITIVE_KEYS`) |
| `Authorization` header | `Bearer secret-token` | HMAC-SHA256 hash |
| Source IP | `1.2.3.4` (from XFF) | HMAC-SHA256 hash |
| `endpoint` | — | `/api/test` |
| `timestamp` | — | RFC 3339 UTC, microsecond precision |

To test the no-secret fallback (PII passes through with a warn log), comment
out `secretKey:` in `playground/config/api.yaml` and `make run` again.

## Iteration loop

After editing Rust code: `make build` regenerates the wasm artifact and the
GCL implementation YAML. `make run` re-copies them into
`playground/config/custom-policies/` and restarts the gateway.

Editing `definition/gcl.yaml` regenerates `src/generated/config.rs` (commit
both files together — they're a paired set).

## Cleanup

```bash
docker compose -f playground/docker-compose.yaml down
```

To remove the registered server entry from Anypoint: console → Runtime Manager
→ Flex Gateway → find your gateway name → Delete. Stale entries block
re-registration with the same name.

## Known gotchas

- **Crate name uses underscores** (`cerberus_flex_gateway`) so
  `cargo anypoint get-name` matches the wasm artifact filename. Anypoint
  Exchange asset IDs in `[package.metadata.anypoint]` keep hyphens.
- **`src/generated/`** is committed (matches the `pdk policy-project create`
  scaffold convention). `make build-asset-files` regenerates `config.rs` from
  `definition/gcl.yaml` — diffs in PRs there are the signal that the GCL was
  edited.
- **`format: service`** on URL fields in `gcl.yaml` is what causes Flex to
  register an Envoy cluster for outbound dispatch. Without it,
  `dispatch_http_call` fails with `Proxy status problem: BadArgument`.
- **Node 16 breaks** the `anypoint-pdk-plugin` with an opaque `Unexpected
  token '{'` syntax error. Use Node 18+.
