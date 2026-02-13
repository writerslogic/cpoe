use super::{AnchorError, AnchorProvider, Proof, ProofStatus, ProviderType};
use async_trait::async_trait;

pub struct EthereumProvider {
    rpc_url: String,
    raw_tx_template: String,
    client: reqwest::Client,
}

impl EthereumProvider {
    pub fn new(rpc_url: String, raw_tx_template: String) -> Self {
        Self {
            rpc_url,
            raw_tx_template,
            client: reqwest::Client::new(),
        }
    }

    pub fn from_env() -> Result<Self, AnchorError> {
        let rpc_url = std::env::var("ETHEREUM_RPC_URL")
            .map_err(|_| AnchorError::Unavailable("ETHEREUM_RPC_URL not set".into()))?;
        let raw_tx_template = std::env::var("ETHEREUM_RAW_TX_TEMPLATE")
            .map_err(|_| AnchorError::Unavailable("ETHEREUM_RAW_TX_TEMPLATE not set".into()))?;
        Ok(Self::new(rpc_url, raw_tx_template))
    }

    async fn rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, AnchorError> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        });

        let response = self
            .client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|e| AnchorError::Network(e.to_string()))?;

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AnchorError::Network(e.to_string()))?;

        if let Some(error) = result.get("error") {
            if !error.is_null() {
                return Err(AnchorError::Submission(error.to_string()));
            }
        }

        Ok(result["result"].clone())
    }

    async fn send_tx(&self, hash: &[u8; 32]) -> Result<String, AnchorError> {
        let raw_tx = self.raw_tx_template.replace("{hash}", &hex::encode(hash));
        let txid = self
            .rpc_call("eth_sendRawTransaction", serde_json::json!([raw_tx]))
            .await?;
        Ok(txid.as_str().unwrap_or("").to_string())
    }

    async fn get_receipt(&self, txid: &str) -> Result<serde_json::Value, AnchorError> {
        self.rpc_call("eth_getTransactionReceipt", serde_json::json!([txid]))
            .await
    }
}

#[async_trait]
impl AnchorProvider for EthereumProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Ethereum
    }

    fn name(&self) -> &str {
        "Ethereum"
    }

    async fn is_available(&self) -> bool {
        self.rpc_call("eth_chainId", serde_json::json!([]))
            .await
            .is_ok()
    }

    async fn submit(&self, hash: &[u8; 32]) -> Result<Proof, AnchorError> {
        let txid = self.send_tx(hash).await?;
        Ok(Proof {
            id: txid.clone(),
            provider: ProviderType::Ethereum,
            status: ProofStatus::Pending,
            anchored_hash: *hash,
            submitted_at: chrono::Utc::now(),
            confirmed_at: None,
            proof_data: txid.as_bytes().to_vec(),
            location: Some(txid),
            attestation_path: None,
            extra: Default::default(),
        })
    }

    async fn check_status(&self, proof: &Proof) -> Result<Proof, AnchorError> {
        let txid = proof.location.clone().unwrap_or_default();
        if txid.is_empty() {
            return Err(AnchorError::InvalidFormat("Missing txid".into()));
        }

        let receipt = self.get_receipt(&txid).await?;
        let mut updated = proof.clone();
        if !receipt.is_null() && receipt.get("blockNumber").is_some() {
            updated.status = ProofStatus::Confirmed;
            updated.confirmed_at = Some(chrono::Utc::now());
        }
        Ok(updated)
    }

    async fn verify(&self, proof: &Proof) -> Result<bool, AnchorError> {
        let txid = proof.location.clone().unwrap_or_default();
        if txid.is_empty() {
            return Err(AnchorError::InvalidFormat("Missing txid".into()));
        }
        let receipt = self.get_receipt(&txid).await?;
        Ok(!receipt.is_null() && receipt.get("blockNumber").is_some())
    }
}
