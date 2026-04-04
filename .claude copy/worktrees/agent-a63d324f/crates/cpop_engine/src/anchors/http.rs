

//! Shared HTTP helpers for anchor providers.
//!
//! Extracts the duplicated JSON-RPC request/response pattern used by
//! Ethereum and Bitcoin providers, and the common HTTP client construction
//! used across all anchor backends.

use super::AnchorError;

/
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/
/
/
pub(crate) fn build_http_client(timeout_secs: Option<u64>) -> Result<reqwest::Client, AnchorError> {
    let secs = timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(secs))
        .build()
        .map_err(|e| AnchorError::Network(format!("HTTP client init failed: {e}")))
}

/
/
/
/
/
pub(crate) async fn json_rpc_call(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, AnchorError> {
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    });

    let response = client
        .post(url)
        .json(&request)
        .send()
        .await
        .map_err(|e| AnchorError::Network(e.to_string()))?;

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| AnchorError::Network(e.to_string()))?;

    check_json_rpc_error(&body)?;

    Ok(body["result"].clone())
}

/
/
/
pub(crate) async fn json_rpc_call_with_auth(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: serde_json::Value,
    username: &str,
    password: &str,
) -> Result<serde_json::Value, AnchorError> {
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    });

    let response = client
        .post(url)
        .basic_auth(username, Some(password))
        .json(&request)
        .send()
        .await
        .map_err(|e| AnchorError::Network(e.to_string()))?;

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| AnchorError::Network(e.to_string()))?;

    check_json_rpc_error(&body)?;

    Ok(body["result"].clone())
}

/
/
/
pub(crate) fn check_json_rpc_error(body: &serde_json::Value) -> Result<(), AnchorError> {
    if let Some(error) = body.get("error") {
        if !error.is_null() {
            let msg = error
                .get("message")
                .and_then(|m| m.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| error.to_string());
            return Err(AnchorError::Submission(msg));
        }
    }
    Ok(())
}
