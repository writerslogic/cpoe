// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::messages::IpcMessage;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce as AesNonce};
use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

/// Protocol encoding mode negotiated per connection.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum WireProtocol {
    /// Legacy bincode format (Rust-to-Rust only)
    Bincode,
    /// JSON format for Swift/C# clients (magic: 0x57 0x4A = "WJ")
    Json,
    /// Encrypted JSON format with ECDH key exchange (magic: 0x57 0x53 = "WS")
    SecureJson,
}

/// JSON protocol magic bytes: "WJ" (0x57 0x4A).
/// Client sends these after connecting to indicate JSON mode.
/// Legacy bincode clients send a 4-byte length prefix directly,
/// which is backward compatible since "WJ" is not a valid length prefix
/// for any real message (0x4A57 = 19031 bytes minimum).
#[cfg(test)]
pub(crate) const JSON_PROTOCOL_MAGIC: [u8; 2] = [0x57, 0x4A];

/// Secure JSON protocol magic bytes: "WS" (0x57 0x53).
/// Client sends [0x57, 0x53, version_byte] to indicate encrypted JSON mode.
/// After this:
///   1. Client sends 65-byte uncompressed P-256 public key
///   2. Server sends 65-byte uncompressed P-256 public key
///   3. Both derive shared secret via ECDH → HKDF-SHA256 (channel-bound) → AES-256-GCM key
///   4. Both exchange encrypted confirmation token to verify key agreement
///   5. All subsequent messages: [4-byte len][8-byte seq][12-byte nonce][ciphertext+tag]
pub(crate) const SECURE_JSON_PROTOCOL_MAGIC: [u8; 2] = [0x57, 0x53];

/// Minimum supported secure protocol version
pub(crate) const SECURE_PROTOCOL_VERSION_MIN: u8 = 1;

/// Maximum supported secure protocol version
pub(crate) const SECURE_PROTOCOL_VERSION_MAX: u8 = 1;

/// Size of an uncompressed P-256 public key (0x04 prefix + 32-byte X + 32-byte Y)
pub(crate) const P256_PUBLIC_KEY_SIZE: usize = 65;

/// HKDF salt for IPC session key derivation
pub(crate) const IPC_HKDF_SALT: &[u8] = b"witnessd-ipc-v1";

/// Timeout for the ECDH handshake phase (prevents hanging connections)
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Key confirmation token that both sides encrypt after key derivation
/// to verify they derived the same session key.
pub(crate) const KEY_CONFIRM_PLAINTEXT: &[u8] = b"witnessd-key-confirm-ok";

/// Per-connection secure session state after ECDH key exchange.
/// Provides AES-256-GCM encryption with sequence number replay protection.
/// Key material is zeroized on drop.
pub(crate) struct SecureSession {
    cipher: Aes256Gcm,
    /// Transmit sequence counter. Server uses odd (1,3,5...), client uses even (0,2,4...).
    tx_sequence: AtomicU64,
    /// Expected receive sequence counter.
    rx_sequence: AtomicU64,
    /// Copy of key bytes for zeroization on drop
    key_bytes: [u8; 32],
}

impl SecureSession {
    /// Create a secure session from a P-256 ECDH shared secret with channel binding.
    /// `is_server` determines sequence number parity (server=odd tx, client=even tx).
    /// `client_pubkey` and `server_pubkey` are included in the HKDF info for channel binding,
    /// preventing MITM relay attacks.
    pub(crate) fn from_shared_secret(
        shared_secret: &[u8],
        client_pubkey: &[u8],
        server_pubkey: &[u8],
        is_server: bool,
    ) -> Result<Self> {
        // Channel-bound HKDF info: "aes-256-gcm-key" + client pubkey + server pubkey
        // This binds the derived key to the specific ECDH key pair, preventing relay attacks.
        let mut info = Vec::with_capacity(15 + P256_PUBLIC_KEY_SIZE * 2);
        info.extend_from_slice(b"aes-256-gcm-key");
        info.extend_from_slice(client_pubkey);
        info.extend_from_slice(server_pubkey);

        let hk = Hkdf::<Sha256>::new(Some(IPC_HKDF_SALT), shared_secret);
        let mut key_bytes = [0u8; 32];
        hk.expand(&info, &mut key_bytes)
            .map_err(|_| anyhow!("HKDF expand failed"))?;

        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|_| anyhow!("AES-GCM key init failed"))?;

        let tx_start = if is_server { 1u64 } else { 0u64 };
        let rx_start = if is_server { 0u64 } else { 1u64 };

        Ok(Self {
            cipher,
            tx_sequence: AtomicU64::new(tx_start),
            rx_sequence: AtomicU64::new(rx_start),
            key_bytes,
        })
    }

    /// Encrypt a JSON message payload. Returns wire bytes: [8-byte seq][12-byte nonce][ciphertext+tag].
    pub(crate) fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let seq = self.tx_sequence.fetch_add(2, Ordering::SeqCst);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&seq.to_le_bytes());
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

    /// Decrypt a wire message. Verifies sequence number for replay protection.
    /// Input format: [8-byte seq][12-byte nonce][ciphertext+tag].
    pub(crate) fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Minimum: 8 (seq) + 12 (nonce) + 16 (GCM tag) = 36 bytes
        if data.len() < 36 {
            return Err(anyhow!("Encrypted message too short: {} bytes", data.len()));
        }

        let seq = u64::from_le_bytes(
            data[..8]
                .try_into()
                .map_err(|_| anyhow!("Invalid sequence number bytes"))?,
        );
        let expected_seq = self.rx_sequence.fetch_add(2, Ordering::SeqCst);

        let nonce = AesNonce::from_slice(&data[8..20]);
        let ciphertext = &data[20..];

        // Decrypt before checking sequence number to prevent timing oracle.
        // AES-GCM is constant-time; checking seq after eliminates the timing
        // difference between match (proceed to decrypt) and mismatch (early return).
        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("AES-GCM decrypt failed (tampered or wrong key)"))?;

        if seq != expected_seq {
            return Err(anyhow!(
                "Sequence number mismatch: expected {}, got {} (possible replay attack)",
                expected_seq,
                seq
            ));
        }

        Ok(plaintext)
    }
}

impl Drop for SecureSession {
    fn drop(&mut self) {
        self.key_bytes.zeroize();
    }
}

/// Per-connection rate limiter with per-category limits.
pub(crate) struct RateLimiter {
    /// Map of operation name → (count, window_start)
    operations: HashMap<String, (u32, Instant)>,
    /// Window duration in seconds
    window_secs: u64,
}

/// Per-category rate limit configuration
pub(crate) struct RateLimitConfig;

impl RateLimitConfig {
    /// Get the maximum operations per window for a given operation category.
    pub(crate) fn max_ops(category: &str) -> u32 {
        match category {
            "heartbeat" | "status" => 120, // Frequent, cheap operations
            "witnessing" => 30,            // Moderate — start/stop tracking
            "verify" | "export" | "forensics" | "process_score" => 10, // Expensive crypto ops
            "checkpoint" => 20,            // Moderately expensive
            _ => 60,                       // General operations
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

    /// Check if an operation is allowed. Returns true if within rate limit.
    /// Uses per-category limits from RateLimitConfig.
    pub(crate) fn check(&mut self, operation: &str) -> bool {
        let now = Instant::now();
        let max_ops = RateLimitConfig::max_ops(operation);

        let entry = self
            .operations
            .entry(operation.to_string())
            .or_insert((0, now));

        if now.duration_since(entry.1).as_secs() >= self.window_secs {
            // Reset window
            *entry = (1, now);
            true
        } else if entry.0 < max_ops {
            entry.0 += 1;
            true
        } else {
            false
        }
    }
}

/// Perform server-side ECDH key exchange with timeout, channel binding, and key confirmation.
///
/// Protocol (v1):
///   1. [Already read] Client sent magic "WS" + version byte
///   2. Client sends 65-byte uncompressed P-256 public key
///   3. Server sends 65-byte uncompressed P-256 public key
///   4. Both derive shared key via ECDH → HKDF-SHA256 (channel-bound to both pubkeys)
///   5. Server sends encrypted confirmation token
///   6. Client sends encrypted confirmation token (server verifies)
pub(crate) async fn secure_handshake_server<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
>(
    stream: &mut S,
    protocol_version: u8,
) -> Result<SecureSession> {
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::{ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Validate protocol version
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

    // Wrap the handshake in a timeout
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        // 1. Read client's uncompressed P-256 public key (65 bytes)
        let mut client_pubkey_bytes = [0u8; P256_PUBLIC_KEY_SIZE];
        stream
            .read_exact(&mut client_pubkey_bytes)
            .await
            .map_err(|e| anyhow!("Failed to read client public key: {}", e))?;

        let client_pubkey = PublicKey::from_sec1_bytes(&client_pubkey_bytes)
            .map_err(|_| anyhow!("Invalid client P-256 public key"))?;

        // 2. Generate server ephemeral keypair and send public key
        let server_secret = EphemeralSecret::random(&mut OsRng);
        let server_pubkey_point = server_secret.public_key().to_encoded_point(false);
        let server_pubkey_bytes = server_pubkey_point.as_bytes();
        stream
            .write_all(server_pubkey_bytes)
            .await
            .map_err(|e| anyhow!("Failed to send server public key: {}", e))?;
        stream.flush().await?;

        // 3. Compute ECDH shared secret
        let shared_secret = server_secret.diffie_hellman(&client_pubkey);

        // 4. Derive session key via channel-bound HKDF (includes both public keys)
        let session = SecureSession::from_shared_secret(
            shared_secret.raw_secret_bytes().as_slice(),
            &client_pubkey_bytes,
            server_pubkey_bytes,
            true,
        )?;

        // 5. Key confirmation: server sends encrypted known token
        let confirm_encrypted = session.encrypt(KEY_CONFIRM_PLAINTEXT)?;
        let confirm_len = confirm_encrypted.len() as u32;
        stream.write_all(&confirm_len.to_le_bytes()).await?;
        stream.write_all(&confirm_encrypted).await?;
        stream.flush().await?;

        // 6. Read and verify client's confirmation token
        let mut client_confirm_len_buf = [0u8; 4];
        stream.read_exact(&mut client_confirm_len_buf).await?;
        let client_confirm_len = u32::from_le_bytes(client_confirm_len_buf) as usize;
        if client_confirm_len > 1024 {
            return Err(anyhow!("Key confirmation token too large"));
        }
        let mut client_confirm_buf = vec![0u8; client_confirm_len];
        stream.read_exact(&mut client_confirm_buf).await?;

        let client_confirm_plaintext = session
            .decrypt(&client_confirm_buf)
            .map_err(|_| anyhow!("Key confirmation failed: client derived different key"))?;

        if client_confirm_plaintext != KEY_CONFIRM_PLAINTEXT {
            return Err(anyhow!(
                "Key confirmation mismatch: client sent wrong token"
            ));
        }

        Ok(session)
    })
    .await
    .map_err(|_| anyhow!("Secure handshake timed out after {:?}", HANDSHAKE_TIMEOUT))?
}

/// Send an encrypted message over a stream using the secure session.
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

/// Get the operation name for rate limiting from an IPC message.
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

// Helper functions for bincode 2.0 serialization
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

/// JSON encode helper for Swift/C# clients
pub(crate) fn encode_message_json(msg: &IpcMessage) -> Result<Vec<u8>> {
    serde_json::to_vec(msg).map_err(|e| anyhow!("JSON encode: {}", e))
}

/// JSON decode helper for Swift/C# clients
pub(crate) fn decode_message_json(bytes: &[u8]) -> Result<IpcMessage> {
    serde_json::from_slice(bytes).map_err(|e| anyhow!("JSON decode: {}", e))
}

/// Encode a message using the specified protocol
pub(crate) fn encode_for_protocol(msg: &IpcMessage, protocol: WireProtocol) -> Result<Vec<u8>> {
    match protocol {
        WireProtocol::Bincode => encode_message(msg),
        WireProtocol::Json | WireProtocol::SecureJson => encode_message_json(msg),
    }
}

/// Decode a message using the specified protocol
pub(crate) fn decode_for_protocol(bytes: &[u8], protocol: WireProtocol) -> Result<IpcMessage> {
    match protocol {
        WireProtocol::Bincode => decode_message(bytes),
        WireProtocol::Json | WireProtocol::SecureJson => decode_message_json(bytes),
    }
}
