// Outbound batch sender.
//
// Wraps a drained Vec<CerberusEvent> in the batch envelope expected by
// event_ingest's POST /v1/ingest/batch endpoint:
//
//   {
//     "events": [...]
//   }
//
// Auth is via the X-API-Key HTTP header (same scheme as /api/secret-key).
// The server looks up client_id from the api_key (1:1) and stamps both
// client_id and token onto each event server-side before publishing to
// Kafka, so the resulting message is byte-compatible with the WS path's
// output. Missing/invalid header → 401; valid header but unknown key →
// 403. See cerberus-int/services/event_ingest/main.py (ingest_batch
// handler) for the contract.
//
// Delivery semantics: at-most-once (per flex_gateway_plan.md §7). On
// HTTP failure the batch is dropped — we log and move on. The plan
// flagged retry+backoff and a circuit breaker as v1.1 work; the comments
// below mark where they'd land.

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
    events: Vec<CerberusEvent>,
) -> Result<()> {
    if events.is_empty() {
        return Ok(());
    }

    let envelope = BatchEnvelope { events: &events };

    let body = serde_json::to_vec(&envelope)?;

    // TODO(v1.1): retry with exponential backoff. flex_gateway_plan.md
    // §7 explicitly leaves the retry policy unspecified ("ignore
    // retries for now ... figure out later"). Need to decide:
    //   - max attempts
    //   - backoff curve (exponential? jittered?)
    //   - what happens to the batch on persistent failure (currently
    //     drop; could re-enqueue at the head of the queue with a TTL)
    //
    // TODO(v1.1): circuit breaker. Without one, every flush during an
    // ingest outage posts into a black hole. Suggested behavior: skip
    // the next N flushes after K consecutive failures, exponentially
    // backing off. Plan §7 calls this out as a future improvement.
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
