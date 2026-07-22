use serde::Deserialize;
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(
        alias = "backendUrl",
        default,
        deserialize_with = "pdk::serde::deserialize_service_opt"
    )]
    pub backend_url: Option<pdk::hl::Service>,
    #[serde(alias = "batchSize")]
    pub batch_size: Option<i64>,
    #[serde(alias = "captureAiContent")]
    pub capture_ai_content: Option<bool>,
    #[serde(alias = "captureHeaders")]
    pub capture_headers: Option<Vec<String>>,
    #[serde(alias = "capturePaths")]
    pub capture_paths: Option<Vec<String>>,
    #[serde(alias = "captureRequestBody")]
    pub capture_request_body: Option<bool>,
    #[serde(alias = "clientIpHeader")]
    pub client_ip_header: Option<String>,
    #[serde(alias = "excludePaths")]
    pub exclude_paths: Option<Vec<String>>,
    #[serde(alias = "flushIntervalMs")]
    pub flush_interval_ms: Option<i64>,
    #[serde(
        alias = "ingestService",
        deserialize_with = "pdk::serde::deserialize_service"
    )]
    pub ingest_service: pdk::hl::Service,
    #[serde(alias = "logLevel")]
    pub log_level: Option<String>,
    #[serde(alias = "queueCapacity")]
    pub queue_capacity: Option<i64>,
    #[serde(alias = "sampleRate")]
    pub sample_rate: Option<f64>,
    #[serde(alias = "secretKey")]
    pub secret_key: Option<String>,
    #[serde(alias = "token")]
    pub token: String,
    #[serde(alias = "userIdHeader")]
    pub user_id_header: Option<String>,
}
#[pdk::hl::entrypoint_flex]
fn init(abi: &dyn pdk::flex_abi::api::FlexAbi) -> Result<(), anyhow::Error> {
    let config: Config = serde_json::from_slice(abi.get_configuration())
        .map_err(|err| {
            anyhow::anyhow!(
                "Failed to parse configuration '{}'. Cause: {}",
                String::from_utf8_lossy(abi.get_configuration()), err
            )
        })?;
    if config.backend_url.is_some() {
        let service = config.backend_url.unwrap();
        abi.service_create(service)?;
    }
    abi.service_create(config.ingest_service)?;
    abi.setup()?;
    Ok(())
}
