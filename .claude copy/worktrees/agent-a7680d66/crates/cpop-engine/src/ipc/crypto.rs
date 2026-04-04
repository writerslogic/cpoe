

use super::messages::IpcMessage;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce as AesNonce};
use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum WireProtocol {
    /
    #[allow(dead_code)]
    Bincode,
    /
    Json,
    /
    SecureJson,
}

/
/
#[cfg(test)]
pub(crate) const JSON_PROTOCOL_MAGIC: [u8; 2] = [0x57, 0x4A];

/
/
pub(crate) const SECURE_JSON_PROTOCOL_MAGIC: [u8; 2] = [0x57, 0x53];

pub(crate) const SECURE_PROTOCOL_VERSION_MIN: u8 = 1;
pub(crate) const SECURE_PROTOCOL_VERSION_MAX: u8 = 1;

/
pub(crate) const P256_PUBLIC_KEY_SIZE: usize = 65;

pub(crate) const IPC_HKDF_SALT: &[u8] = b"witnessd-ipc-v1";

/
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/
pub(crate) const KEY_CONFIRM_PLAINTEXT: &[u8] = b"witnessd-key-confirm-ok";

/
/
pub(crate) struct SecureSession {
    cipher: Aes256Gcm,
    /
    tx_sequence: AtomicU64,
    rx_sequence: AtomicU64,
    key_bytes: [u8; 32],
    /
    tx_nonce_prefix: [u8; 4],
    /
    rx_nonce_prefix: [u8; 4],
}

/
fn construct_nonce(prefix: &[u8; 4], seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(prefix);
    nonce[4..].copy_from_slice(&seq.to_le_bytes());
    nonce
}

impl SecureSession {
    /
    /
    pub(crate) fn from_shared_secret(
        shared_secret: &[u8],
        client_pubkey: &[u8],
        server_pubkey: &[u8],
        is_server: bool,
    ) -> Result<Self> {
        let mut info = Vec::with_capacity(15 + P256_PUBLIC_KEY_SIZE * 2);
        info.extend_from_slice(b"aes-256-gcm-key");
        info.extend_from_slice(client_pubkey);
        info.extend_from_slice(server_pubkey);

        let hk = Hkdf::<Sha256>::new(Some(IPC_HKDF_SALT), shared_secret);
        let mut key_bytes = [0u8; 32];
        hk.expand(&info, &mut key_bytes)
            .map_err(|_| anyhow!("HKDF expand failed"))?;

        
        
        let mut client_prefix = [0u8; 4];
        hk.expand(b"nonce-prefix-client", &mut client_prefix)
            .map_err(|_| anyhow!("HKDF expand for client nonce prefix failed"))?;

        let mut server_prefix = [0u8; 4];
        hk.expand(b"nonce-prefix-server", &mut server_prefix)
            .map_err(|_| anyhow!("HKDF expand for server nonce prefix failed"))?;

        let (tx_nonce_prefix, rx_nonce_prefix) = if is_server {
            (server_prefix, client_prefix)
        } else {
            (client_prefix, server_prefix)
        };

        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|_| anyhow!("AES-GCM key init failed"))?;

        let tx_start = if is_server { 1u64 } else { 0u64 };
        let rx_start = if is_server { 0u64 } else { 1u64 };

        Ok(Self {
            cipher,
            tx_sequence: AtomicU64::new(tx_start),
            rx_sequence: AtomicU64::new(rx_start),
            key_bytes,
            tx_nonce_prefix,
            rx_nonce_prefix,
        })
    }

    /
    pub(crate) fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        
        
        let seq = loop {
            let current = self.tx_sequence.load(Ordering::SeqCst);
            if current > u64::MAX - 2 {
                return Err(anyhow!(
                    "tx_sequence exhausted (would overflow); session must be rekeyed"
                ));
            }
            match self.tx_sequence.compare_exchange(
                current,
                current + 2,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(v) => break v,
                Err(_) => continue, 
            }
        };
        let nonce_bytes = construct_nonce(&self.tx_nonce_prefix, seq);
        let nonce = AesNonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| anyhow!("AES-GCM encrypt failed"))?;

        let mut out = Vec::with_capacity(8 + 12 + ciphertext.len());
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /
    /
    /
    pub(crate) fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 36 {
            return Err(anyhow!("Encrypted message too short: {} bytes", data.len()));
        }

        let seq = u64::from_le_bytes(
            data[..8]
                .try_into()
                .map_err(|_| anyhow!("Invalid sequence number bytes"))?,
        );

        
        
        
        let expected_seq = loop {
            let current = self.rx_sequence.load(Ordering::SeqCst);
            if seq.to_le_bytes().ct_eq(&current.to_le_bytes()).unwrap_u8() != 1 {
                return Err(anyhow!(
                    "Sequence validation failed (possible replay attack)"
                ));
            }
            match self.rx_sequence.compare_exchange(
                current,
                current + 2,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(v) => break v,
                Err(_) => continue, 
            }
        };

        
        
        
        
        let expected_nonce = construct_nonce(&self.rx_nonce_prefix, expected_seq);
        let wire_nonce = &data[8..20];
        if expected_nonce.ct_eq(wire_nonce).unwrap_u8() != 1 {
            return Err(anyhow!("Nonce mismatch (possible tampering)"));
        }
        let nonce = AesNonce::from_slice(&expected_nonce);
        let ciphertext = &data[20..];

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("AES-GCM decrypt failed (tampered or wrong key)"))?;

        Ok(plaintext)
    }
}

impl Drop for SecureSession {
    fn drop(&mut self) {
        self.key_bytes.zeroize();
    }
}

/
/
/
/
pub(crate) struct RateLimiter {
    operations: HashMap<String, (u32, Instant)>,
    window_secs: u64,
}

pub(crate) struct RateLimitConfig;

impl RateLimitConfig {
    pub(crate) fn max_ops(category: &str) -> u32 {
        match category {
            "heartbeat" | "status" => 120,
            "witnessing" => 30,
            "verify" | "export" | "forensics" | "process_score" => 10,
            "checkpoint" => 20,
            _ => 60,
        }
    }
}

impl RateLimiter {
    pub(crate) fn new(window_secs: u64) -> Self {
        Self {
            operations: HashMap::new(),
            window_secs,
        }
    }

    pub(crate) fn check(&mut self, operation: &str) -> bool {
        let now = Instant::now();
        let max_ops = RateLimitConfig::max_ops(operation);

        if let Some(entry) = self.operations.get_mut(operation) {
            if now.duration_since(entry.1).as_secs() >= self.window_secs {
                *entry = (1, now);
                return true;
            } else if entry.0 < max_ops {
                entry.0 += 1;
                return true;
            }
            return false;
        }

        self.operations.insert(operation.to_string(), (1, now));
        true
    }
}

/
pub(crate) async fn secure_handshake_server<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
>(
    stream: &mut S,
    protocol_version: u8,
) -> Result<SecureSession> {
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::{ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    if protocol_version < SECURE_PROTOCOL_VERSION_MIN
        || protocol_version > SECURE_PROTOCOL_VERSION_MAX
    {
        return Err(anyhow!(
            "Unsupported secure protocol version: {} (supported: {}-{})",
            protocol_version,
            SECURE_PROTOCOL_VERSION_MIN,
            SECURE_PROTOCOL_VERSION_MAX
        ));
    }

    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let mut client_pubkey_bytes = [0u8; P256_PUBLIC_KEY_SIZE];
        stream
            .read_exact(&mut client_pubkey_bytes)
            .await
            .map_err(|e| anyhow!("Failed to read client public key: {}", e))?;

        let client_pubkey = PublicKey::from_sec1_bytes(&client_pubkey_bytes)
            .map_err(|_| anyhow!("Invalid client P-256 public key"))?;

        let server_secret = EphemeralSecret::random(&mut OsRng);
        let server_pubkey_point = server_secret.public_key().to_encoded_point(false);
        let server_pubkey_bytes = server_pubkey_point.as_bytes();
        stream
            .write_all(server_pubkey_bytes)
            .await
            .map_err(|e| anyhow!("Failed to send server public key: {}", e))?;
        stream.flush().await?;

        let shared_secret = server_secret.diffie_hellman(&client_pubkey);

        let session = SecureSession::from_shared_secret(
            shared_secret.raw_secret_bytes().as_slice(),
            &client_pubkey_bytes,
            server_pubkey_bytes,
            true,
        )?;

        
        drop(shared_secret);
        drop(server_secret);
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);

        let confirm_encrypted = session.encrypt(KEY_CONFIRM_PLAINTEXT)?;
        let confirm_len = confirm_encrypted.len() as u32;
        stream.write_all(&confirm_len.to_le_bytes()).await?;
        stream.write_all(&confirm_encrypted).await?;
        stream.flush().await?;

        let mut client_confirm_len_buf = [0u8; 4];
        stream.read_exact(&mut client_confirm_len_buf).await?;
        let client_confirm_len = u32::from_le_bytes(client_confirm_len_buf) as usize;
        if client_confirm_len == 0 {
            return Err(anyhow!("Empty key confirmation token"));
        }
        if client_confirm_len > 1024 {
            return Err(anyhow!("Key confirmation token too large"));
        }
        let mut client_confirm_buf = vec![0u8; client_confirm_len];
        stream.read_exact(&mut client_confirm_buf).await?;

        let client_confirm_plaintext = session
            .decrypt(&client_confirm_buf)
            .map_err(|_| anyhow!("Key confirmation failed: client derived different key"))?;

        if client_confirm_plaintext
            .ct_eq(KEY_CONFIRM_PLAINTEXT)
            .unwrap_u8()
            == 0
        {
            return Err(anyhow!(
                "Key confirmation mismatch: client sent wrong token"
            ));
        }

        Ok(session)
    })
    .await
    .map_err(|_| anyhow!("Secure handshake timed out after {:?}", HANDSHAKE_TIMEOUT))?
}

/
pub(crate) async fn send_encrypted<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    session: &SecureSession,
    json_bytes: &[u8],
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let encrypted = session.encrypt(json_bytes)?;
    let len = encrypted.len() as u32;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&encrypted).await?;
    stream.flush().await?;
    Ok(())
}

/
pub(crate) fn rate_limit_key(msg: &IpcMessage) -> &'static str {
    match msg {
        IpcMessage::ExportFile { .. } | IpcMessage::ExportWithNonce { .. } => "export",
        IpcMessage::VerifyFile { .. } | IpcMessage::VerifyWithNonce { .. } => "verify",
        IpcMessage::GetFileForensics { .. } => "forensics",
        IpcMessage::ComputeProcessScore { .. } => "process_score",
        IpcMessage::CreateFileCheckpoint { .. } => "checkpoint",
        IpcMessage::StartWitnessing { .. } | IpcMessage::StopWitnessing { .. } => "witnessing",
        _ => "general",
    }
}

pub(crate) fn encode_message(msg: &IpcMessage) -> Result<Vec<u8>> {
    bincode::serde::encode_to_vec(msg, bincode::config::standard())
        .map_err(|e| anyhow!("Failed to encode message: {}", e))
}

pub(crate) fn decode_message(bytes: &[u8]) -> Result<IpcMessage> {
    let (msg, _): (IpcMessage, usize) =
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map_err(|e| anyhow!("Failed to decode message: {}", e))?;
    Ok(msg)
}

pub(crate) fn encode_message_json(msg: &IpcMessage) -> Result<Vec<u8>> {
    serde_json::to_vec(msg).map_err(|e| anyhow!("JSON encode: {}", e))
}

pub(crate) fn decode_message_json(bytes: &[u8]) -> Result<IpcMessage> {
    serde_json::from_slice(bytes).map_err(|e| anyhow!("JSON decode: {}", e))
}

pub(crate) fn encode_for_protocol(msg: &IpcMessage, protocol: WireProtocol) -> Result<Vec<u8>> {
    match protocol {
        WireProtocol::Bincode => encode_message(msg),
        WireProtocol::Json | WireProtocol::SecureJson => encode_message_json(msg),
    }
}

pub(crate) fn decode_for_protocol(bytes: &[u8], protocol: WireProtocol) -> Result<IpcMessage> {
    match protocol {
        WireProtocol::Bincode => decode_message(bytes),
        WireProtocol::Json | WireProtocol::SecureJson => decode_message_json(bytes),
    }
}
