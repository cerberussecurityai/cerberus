// Init-time HMAC secret resolution.
//
// Precedence:
//   1. If `secretKey` is configured → use it.
//   2. Else if `backendUrl` is configured → GET {backendUrl}/api/secret-key
//      with X-API-Key: {token}, parse {"secret_key": "..."}, cache.
//   3. Else → return None (PII emitted raw, with one-time warn log).
//
// `backendUrl` is declared `format: service` in `definition/gcl.yaml`, so
// the PDK registers an Envoy cluster for it at policy load (see the init
// hook in `src/generated/config.rs`) and hands us a `Service` handle.
// proxy-wasm `dispatch_http_call` only dispatches to registered clusters,
// so we must use that handle — a runtime-manufactured `Service` has no
// backing cluster and every fetch silently fails.
//
// Failure of step 2 is non-fatal: log a warn and degrade to "no
// hashing". Five-second timeout on the outbound call so a misconfigured
// backendUrl doesn't deadlock the gateway on policy load.

use std::time::Duration;

use pdk::hl::HttpClient;
use pdk::logger;
use serde::Deserialize;

use crate::config::Config;

const SECRET_KEY_PATH: &str = "/api/secret-key";
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
struct SecretKeyResponse {
    secret_key: Option<String>,
}

pub async fn resolve_secret(config: &Config, client: &HttpClient) -> Option<String> {
    if let Some(key) = config.secret_key.as_ref() {
        if !key.is_empty() {
            logger::info!("cerberus-flex-gateway: using secretKey from config");
            return Some(key.clone());
        }
    }

    let backend_service = config.backend_url.as_ref()?;

    // Scheme check on the parsed URI so casing (e.g. `HTTPS://`) doesn't
    // slip a plaintext warning past us.
    if !backend_service.uri().scheme().eq_ignore_ascii_case("https") {
        logger::warn!(
            "cerberus-flex-gateway: backendUrl does not use https:// — token will be transmitted unencrypted"
        );
    }

    logger::info!(
        "cerberus-flex-gateway: fetching secret from backendUrl ({}{})",
        backend_service.uri().authority(),
        SECRET_KEY_PATH
    );

    let response = client
        .request(backend_service)
        .path(SECRET_KEY_PATH)
        .timeout(FETCH_TIMEOUT)
        .headers(vec![("X-API-Key", config.token.as_str())])
        .get()
        .await;

    let response = match response {
        Ok(r) => r,
        Err(err) => {
            logger::warn!(
                "cerberus-flex-gateway: secret fetch failed: {} — falling back to raw PII",
                err
            );
            return None;
        }
    };

    if response.status_code() != 200 {
        logger::warn!(
            "cerberus-flex-gateway: secret fetch returned status {} — falling back to raw PII",
            response.status_code()
        );
        return None;
    }

    match serde_json::from_slice::<SecretKeyResponse>(response.body()) {
        Ok(parsed) => parsed.secret_key,
        Err(err) => {
            logger::warn!(
                "cerberus-flex-gateway: secret fetch response not parseable: {} — falling back to raw PII",
                err
            );
            None
        }
    }
}
