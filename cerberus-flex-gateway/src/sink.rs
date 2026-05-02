// Outbound batch sender.
//
// Wraps a drained Vec<CerberusEvent> in the batch envelope expected by
// the Cerberus backend's POST /v1/ingest/batch endpoint:
//
//   {
//     "events": [...]
//   }
//
// Auth is via the X-API-Key HTTP header.
//
// Delivery semantics: at-most-once. On HTTP failure the batch is
// dropped — we log and move on. Retry+backoff and a circuit breaker
// are v1.1 work; the comments below mark where they'd land.

use std::time::Duration;

use anyhow::{anyhow, Result};
use pdk::hl::{HttpClient, Service};
use pdk::logger;
use serde::Serialize;

use crate::config::Config;
use crate::event::CerberusEvent;

const BATCH_PATH: &str = "/v1/ingest/batch";
const POST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Serialize)]
struct BatchEnvelope<'a> {
    events: &'a [CerberusEvent],
}

pub async fn post_batch(
    client: &HttpClient,
    ingest_service: &Service,
    config: &Config,
    events: &[CerberusEvent],
) -> Result<()> {
    if events.is_empty() {
        return Ok(());
    }

    let envelope = BatchEnvelope { events };

    let body = serde_json::to_vec(&envelope)?;

    // TODO(v1.1): retry with exponential backoff and circuit breaker.
    // Without these, every flush during a backend outage posts into a
    // black hole.
    let response = client
        .request(ingest_service)
        .path(BATCH_PATH)
        .timeout(POST_TIMEOUT)
        .headers(vec![
            ("content-type", "application/json"),
            ("x-api-key", &config.token),
        ])
        .body(&body)
        .post()
        .await
        .map_err(|err| anyhow!("dispatch_http_call failed: {}", err))?;

    let status = response.status_code();
    if (200..300).contains(&status) {
        logger::debug!(
            "cerberus-flex-gateway: posted batch of {} events ({})",
            events.len(),
            status
        );
        Ok(())
    } else {
        Err(anyhow!(
            "ingestService returned status {}: {}",
            status,
            String::from_utf8_lossy(response.body())
        ))
    }
}
