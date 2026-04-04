

//! HTTP client for the WritersProof attestation API.

use ed25519_dalek::{Signer, SigningKey};
use reqwest::Client;
use zeroize::Zeroizing;

use super::types::{
    AnchorRequest, AnchorResponse, AttestResponse, BeaconRequest, BeaconResponse, EnrollRequest,
    EnrollResponse, NonceResponse, VerifyResponse,
};
use crate::error::{Error, Result};

/
pub struct WritersProofClient {
    base_url: String,
    jwt: Option<Zeroizing<String>>,
    client: Client,
}

impl WritersProofClient {
    /
    /
    /
    /
    /
    pub fn new(base_url: &str) -> Result<Self> {
        let url = base_url.trim_end_matches('/').to_string();
        #[cfg(not(debug_assertions))]
        if !url.starts_with("https:
            return Err(Error::crypto(format!(
                "WritersProof base_url must use HTTPS in release builds: {}",
                &url[..url.len().min(40)]
            )));
        }
        #[cfg(debug_assertions)]
        if !url.starts_with("https:
            log::warn!(
                "WritersProof base_url using HTTP (debug build only): {}",
                &url[..url.len().min(40)]
            );
        }
        Ok(Self {
            base_url: url,
            jwt: None,
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|e| Error::crypto(format!("HTTP client build failed: {e}")))?,
        })
    }

    /
    pub fn with_jwt(mut self, token: String) -> Self {
        self.jwt = Some(Zeroizing::new(token));
        self
    }

    /
    /
    /
    pub async fn request_nonce(&self, hardware_key_id: &str) -> Result<NonceResponse> {
        let url = format!("{}/v1/nonce", self.base_url);
        let body = serde_json::json!({ "hardwareKeyId": hardware_key_id });
        let mut req = self.client.post(&url).json(&body);
        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt.as_str());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("nonce request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "nonce request failed: HTTP {}",
                resp.status()
            )));
        }

        resp.json::<NonceResponse>()
            .await
            .map_err(|e| Error::crypto(format!("nonce response parse failed: {e}")))
    }

    /
    /
    /
    pub async fn enroll(&self, req: EnrollRequest) -> Result<EnrollResponse> {
        let url = format!("{}/v1/enroll", self.base_url);
        let mut http_req = self.client.post(&url).json(&req);
        if let Some(ref jwt) = self.jwt {
            http_req = http_req.bearer_auth(jwt.as_str());
        }

        let resp = http_req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("enroll request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "enroll request failed: HTTP {}",
                resp.status()
            )));
        }

        resp.json::<EnrollResponse>()
            .await
            .map_err(|e| Error::crypto(format!("enroll response parse failed: {e}")))
    }

    /
    /
    /
    /
    /
    /
    pub async fn attest(
        &self,
        evidence_cbor: &[u8],
        nonce: &[u8; 32],
        hardware_key_id: &str,
        signing_key: &SigningKey,
    ) -> Result<AttestResponse> {
        let hkid_bytes = hardware_key_id.as_bytes();
        let mut sign_payload = zeroize::Zeroizing::new(Vec::with_capacity(
            4 + nonce.len() + 4 + hkid_bytes.len() + 4 + evidence_cbor.len(),
        ));
        sign_payload.extend_from_slice(&(nonce.len() as u32).to_be_bytes());
        sign_payload.extend_from_slice(nonce);
        sign_payload.extend_from_slice(&(hkid_bytes.len() as u32).to_be_bytes());
        sign_payload.extend_from_slice(hkid_bytes);
        sign_payload.extend_from_slice(&(evidence_cbor.len() as u32).to_be_bytes());
        sign_payload.extend_from_slice(evidence_cbor);
        let signature = signing_key.sign(&sign_payload);
        let url = format!("{}/v1/attest", self.base_url);

        let mut req = self
            .client
            .post(&url)
            .header("Content-Type", "application/cbor")
            .header("X-CPOP-Nonce", hex::encode(nonce))
            .header("X-CPOP-Hardware-Key-Id", hardware_key_id)
            .header("X-CPOP-Signature", hex::encode(signature.to_bytes()))
            .body(evidence_cbor.to_vec());

        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt.as_str());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("attest request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "attest request failed: HTTP {}",
                resp.status()
            )));
        }

        resp.json::<AttestResponse>()
            .await
            .map_err(|e| Error::crypto(format!("attest response parse failed: {e}")))
    }

    /
    /
    /
    pub async fn get_certificate(&self, id: &str) -> Result<Vec<u8>> {
        
        if !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(Error::crypto(format!(
                "invalid certificate ID: must be alphanumeric/dash/underscore, got: {}",
                &id[..id.len().min(32)]
            )));
        }
        let url = format!("{}/v1/certificates/{}", self.base_url, id);
        let mut req = self.client.get(&url);
        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt.as_str());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("certificate request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "certificate request failed: HTTP {}",
                resp.status()
            )));
        }

        const MAX_CERT_SIZE: u64 = 10_000_000; 
        if let Some(cl) = resp.content_length() {
            if cl > MAX_CERT_SIZE {
                return Err(Error::crypto(format!(
                    "certificate Content-Length too large: {cl} bytes (max {MAX_CERT_SIZE})"
                )));
            }
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| Error::crypto(format!("certificate response read failed: {e}")))?;
        if body.len() as u64 > MAX_CERT_SIZE {
            return Err(Error::crypto(format!(
                "certificate response too large: {} bytes (max {MAX_CERT_SIZE})",
                body.len()
            )));
        }
        Ok(body.to_vec())
    }

    /
    /
    /
    pub async fn get_crl(&self) -> Result<Vec<u8>> {
        let url = format!("{}/v1/crl", self.base_url);
        let mut req = self.client.get(&url);
        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt.as_str());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("CRL request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "CRL request failed: HTTP {}",
                resp.status()
            )));
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| Error::crypto(format!("CRL response read failed: {e}")))?;
        if body.len() > 50_000_000 {
            return Err(Error::crypto(format!(
                "CRL response too large: {} bytes (max 50MB)",
                body.len()
            )));
        }
        Ok(body.to_vec())
    }

    /
    /
    /
    pub async fn anchor(&self, req: AnchorRequest) -> Result<AnchorResponse> {
        let url = format!("{}/v1/anchor", self.base_url);
        let mut http_req = self.client.post(&url).json(&req);
        if let Some(ref jwt) = self.jwt {
            http_req = http_req.bearer_auth(jwt.as_str());
        }

        let resp = http_req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("anchor request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "anchor request failed: HTTP {}",
                resp.status()
            )));
        }

        resp.json::<AnchorResponse>()
            .await
            .map_err(|e| Error::crypto(format!("anchor response parse failed: {e}")))
    }

    /
    /
    /
    /
    /
    /
    /
    /
    pub async fn fetch_beacon(
        &self,
        checkpoint_hash: &str,
        timeout_secs: u64,
    ) -> Result<BeaconResponse> {
        let url = format!("{}/v1/beacon", self.base_url);
        let req = BeaconRequest {
            checkpoint_hash: checkpoint_hash.to_string(),
        };

        let effective_timeout = timeout_secs.max(1); 
        let mut http_req = self
            .client
            .post(&url)
            .json(&req)
            .timeout(std::time::Duration::from_secs(effective_timeout));

        if let Some(ref jwt) = self.jwt {
            http_req = http_req.bearer_auth(jwt.as_str());
        }

        let resp = http_req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("beacon request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "beacon request failed: HTTP {}",
                resp.status()
            )));
        }

        resp.json::<BeaconResponse>()
            .await
            .map_err(|e| Error::crypto(format!("beacon response parse failed: {e}")))
    }

    /
    /
    /
    pub async fn verify(&self, evidence_cbor: &[u8]) -> Result<VerifyResponse> {
        let url = format!("{}/v1/verify", self.base_url);
        let mut req = self
            .client
            .post(&url)
            .header("Content-Type", "application/vnd.writersproof.cpop+cbor")
            .body(evidence_cbor.to_vec());

        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt.as_str());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("verify request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "verify request failed: HTTP {}",
                resp.status()
            )));
        }

        let mut response = resp
            .json::<VerifyResponse>()
            .await
            .map_err(|e| Error::crypto(format!("verify response parse failed: {e}")))?;
        response.sanitize();
        Ok(response)
    }

    /
    /
    /
    pub async fn is_online(&self) -> bool {
        let url = format!("{}/health", self.base_url);
        match self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(r) => r.status().is_success(),
            Err(e) => {
                log::debug!("Health check failed: {e}");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_construction() {
        let client = WritersProofClient::new("https:
        assert_eq!(client.base_url, "https:
        assert!(client.jwt.is_none());
    }

    #[test]
    fn test_client_with_jwt() {
        let client = WritersProofClient::new("https:
            .unwrap()
            .with_jwt("test-token".to_string());
        assert!(client
            .jwt
            .as_ref()
            .is_some_and(|j| j.as_str() == "test-token"));
    }

    #[test]
    fn test_trailing_slash_stripped() {
        let client = WritersProofClient::new("https:
        assert_eq!(client.base_url, "https:
    }
}
