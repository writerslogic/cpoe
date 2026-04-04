

use super::crypto::{
    decode_message, decode_message_json, encode_message, encode_message_json, SecureSession,
    KEY_CONFIRM_PLAINTEXT, SECURE_JSON_PROTOCOL_MAGIC,
};
use super::messages::MAX_MESSAGE_SIZE;
use super::messages::{IpcErrorCode, IpcMessage};
use p256::{ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use std::path::PathBuf;
use std::time::Duration;

/
/
const IO_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(unix)]
type PlatformStream = tokio::net::UnixStream;
#[cfg(target_os = "windows")]
type PlatformStream = tokio::net::windows::named_pipe::NamedPipeClient;

/
#[derive(Debug, thiserror::Error)]
pub enum AsyncIpcClientError {
    /
    #[error("connection failed: {0}")]
    ConnectionFailed(#[source] std::io::Error),
    /
    #[error("send failed: {0}")]
    SendFailed(#[source] std::io::Error),
    /
    #[error("receive failed: {0}")]
    ReceiveFailed(#[source] std::io::Error),
    /
    #[error("serialization failed: {0}")]
    SerializationFailed(String),
    /
    #[error("deserialization failed: {0}")]
    DeserializationFailed(String),
    /
    #[error("connection closed by peer")]
    ConnectionClosed,
    /
    #[error("not connected")]
    NotConnected,
    /
    #[error("message too large: {0} bytes (max: {1})")]
    MessageTooLarge(usize, usize),
    /
    #[error("protocol error: {0}")]
    ProtocolError(String),
    /
    #[error("operation timed out after {0:?}")]
    Timeout(Duration),
}

/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
/
pub struct AsyncIpcClient {
    stream: Option<PlatformStream>,
    secure_session: Option<SecureSession>,
}

impl AsyncIpcClient {
    /
    pub fn new() -> Self {
        Self {
            stream: None,
            secure_session: None,
        }
    }

    /
    #[cfg(unix)]
    pub async fn connect<P: AsRef<std::path::Path>>(
        path: P,
    ) -> std::result::Result<Self, AsyncIpcClientError> {
        let stream = tokio::net::UnixStream::connect(path.as_ref())
            .await
            .map_err(AsyncIpcClientError::ConnectionFailed)?;

        let mut client = Self {
            stream: Some(stream),
            secure_session: None,
        };

        client.establish_secure_session().await?;

        Ok(client)
    }

    /
    #[cfg(target_os = "windows")]
    pub async fn connect<P: AsRef<std::path::Path>>(
        path: P,
    ) -> std::result::Result<Self, AsyncIpcClientError> {
        let stream = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(path.as_ref())
            .map_err(AsyncIpcClientError::ConnectionFailed)?;

        let mut client = Self {
            stream: Some(stream),
            secure_session: None,
        };

        client.establish_secure_session().await?;

        Ok(client)
    }

    async fn establish_secure_session(&mut self) -> std::result::Result<(), AsyncIpcClientError> {
        use p256::elliptic_curve::rand_core::OsRng;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let stream = self
            .stream
            .as_mut()
            .ok_or(AsyncIpcClientError::NotConnected)?;

        let session = tokio::time::timeout(IO_TIMEOUT, async {
            let mut magic_packet = Vec::with_capacity(3);
            magic_packet.extend_from_slice(&SECURE_JSON_PROTOCOL_MAGIC);
            magic_packet.push(1u8);
            stream
                .write_all(&magic_packet)
                .await
                .map_err(AsyncIpcClientError::SendFailed)?;
            stream
                .flush()
                .await
                .map_err(AsyncIpcClientError::SendFailed)?;

            let client_secret = EphemeralSecret::random(&mut OsRng);
            let client_pubkey_point = client_secret.public_key().to_encoded_point(false);
            let client_pubkey_bytes = client_pubkey_point.as_bytes();

            stream
                .write_all(client_pubkey_bytes)
                .await
                .map_err(AsyncIpcClientError::SendFailed)?;
            stream
                .flush()
                .await
                .map_err(AsyncIpcClientError::SendFailed)?;

            let mut server_pubkey_bytes = [0u8; 65];
            stream
                .read_exact(&mut server_pubkey_bytes)
                .await
                .map_err(AsyncIpcClientError::ReceiveFailed)?;

            let server_pubkey = PublicKey::from_sec1_bytes(&server_pubkey_bytes).map_err(|e| {
                AsyncIpcClientError::ProtocolError(format!("Invalid server public key: {}", e))
            })?;

            let shared_secret = client_secret.diffie_hellman(&server_pubkey);

            let session = SecureSession::from_shared_secret(
                shared_secret.raw_secret_bytes().as_slice(),
                client_pubkey_bytes,
                &server_pubkey_bytes,
                false, 
            )
            .map_err(|e| {
                AsyncIpcClientError::ProtocolError(format!("Key derivation failed: {}", e))
            })?;

            
            
            
            drop(shared_secret);
            drop(client_secret);
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);

            let mut len_buf = [0u8; 4];
            stream
                .read_exact(&mut len_buf)
                .await
                .map_err(AsyncIpcClientError::ReceiveFailed)?;
            let len = u32::from_le_bytes(len_buf) as usize;
            if len > 1024 {
                return Err(AsyncIpcClientError::ProtocolError(
                    "Server confirmation too large".into(),
                ));
            }
            let mut server_confirm_buf = vec![0u8; len];
            stream
                .read_exact(&mut server_confirm_buf)
                .await
                .map_err(AsyncIpcClientError::ReceiveFailed)?;

            let server_confirm_plaintext = session.decrypt(&server_confirm_buf).map_err(|e| {
                AsyncIpcClientError::ProtocolError(format!(
                    "Server confirmation decrypt failed: {}",
                    e
                ))
            })?;

            if server_confirm_plaintext != KEY_CONFIRM_PLAINTEXT {
                return Err(AsyncIpcClientError::ProtocolError(
                    "Server confirmation mismatch".into(),
                ));
            }

            let client_confirm_encrypted = session.encrypt(KEY_CONFIRM_PLAINTEXT).map_err(|e| {
                AsyncIpcClientError::ProtocolError(format!(
                    "Client confirmation encrypt failed: {}",
                    e
                ))
            })?;
            let client_confirm_len = client_confirm_encrypted.len() as u32;
            stream
                .write_all(&client_confirm_len.to_le_bytes())
                .await
                .map_err(AsyncIpcClientError::SendFailed)?;
            stream
                .write_all(&client_confirm_encrypted)
                .await
                .map_err(AsyncIpcClientError::SendFailed)?;
            stream
                .flush()
                .await
                .map_err(AsyncIpcClientError::SendFailed)?;

            Ok(session)
        })
        .await
        .map_err(|_| AsyncIpcClientError::Timeout(IO_TIMEOUT))??;

        self.secure_session = Some(session);
        Ok(())
    }

    /
    /
    /
    pub async fn send_message(
        &mut self,
        msg: &IpcMessage,
    ) -> std::result::Result<(), AsyncIpcClientError> {
        use tokio::io::AsyncWriteExt;

        let stream = self
            .stream
            .as_mut()
            .ok_or(AsyncIpcClientError::NotConnected)?;

        let encoded = if self.secure_session.is_some() {
            encode_message_json(msg)
                .map_err(|e| AsyncIpcClientError::SerializationFailed(e.to_string()))?
        } else {
            encode_message(msg)
                .map_err(|e| AsyncIpcClientError::SerializationFailed(e.to_string()))?
        };

        let payload = if let Some(session) = &self.secure_session {
            session.encrypt(&encoded).map_err(|e| {
                AsyncIpcClientError::ProtocolError(format!("Encryption failed: {}", e))
            })?
        } else {
            encoded
        };

        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(AsyncIpcClientError::MessageTooLarge(
                payload.len(),
                MAX_MESSAGE_SIZE,
            ));
        }

        let len = payload.len() as u32;
        tokio::time::timeout(IO_TIMEOUT, async {
            stream
                .write_all(&len.to_le_bytes())
                .await
                .map_err(AsyncIpcClientError::SendFailed)?;
            stream
                .write_all(&payload)
                .await
                .map_err(AsyncIpcClientError::SendFailed)?;
            stream
                .flush()
                .await
                .map_err(AsyncIpcClientError::SendFailed)?;
            Ok(())
        })
        .await
        .map_err(|_| AsyncIpcClientError::Timeout(IO_TIMEOUT))?
    }

    /
    /
    /
    pub async fn recv_message(&mut self) -> std::result::Result<IpcMessage, AsyncIpcClientError> {
        use tokio::io::AsyncReadExt;

        let stream = self
            .stream
            .as_mut()
            .ok_or(AsyncIpcClientError::NotConnected)?;

        let buffer = tokio::time::timeout(IO_TIMEOUT, async {
            let mut len_buf = [0u8; 4];
            match stream.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Err(AsyncIpcClientError::ConnectionClosed);
                }
                Err(e) => return Err(AsyncIpcClientError::ReceiveFailed(e)),
            }

            let len = u32::from_le_bytes(len_buf) as usize;

            if len > MAX_MESSAGE_SIZE {
                return Err(AsyncIpcClientError::MessageTooLarge(len, MAX_MESSAGE_SIZE));
            }

            let mut buffer = vec![0u8; len];
            stream
                .read_exact(&mut buffer)
                .await
                .map_err(AsyncIpcClientError::ReceiveFailed)?;

            Ok(buffer)
        })
        .await
        .map_err(|_| AsyncIpcClientError::Timeout(IO_TIMEOUT))??;

        let plaintext = if let Some(session) = &self.secure_session {
            session.decrypt(&buffer).map_err(|e| {
                AsyncIpcClientError::ProtocolError(format!("Decryption failed: {}", e))
            })?
        } else {
            buffer
        };

        let msg = if self.secure_session.is_some() {
            decode_message_json(&plaintext)
                .map_err(|e| AsyncIpcClientError::DeserializationFailed(e.to_string()))?
        } else {
            decode_message(&plaintext)
                .map_err(|e| AsyncIpcClientError::DeserializationFailed(e.to_string()))?
        };

        Ok(msg)
    }

    /
    pub async fn request(
        &mut self,
        msg: &IpcMessage,
    ) -> std::result::Result<IpcMessage, AsyncIpcClientError> {
        self.send_message(msg).await?;
        self.recv_message().await
    }

    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    /
    #[cfg(unix)]
    pub async fn disconnect(&mut self) {
        if let Some(stream) = self.stream.take() {
            
            let _ = stream.into_std();
        }
    }

    /
    #[cfg(target_os = "windows")]
    pub async fn disconnect(&mut self) {
        self.stream = None;
    }

    /
    /
    /
    pub async fn handshake(
        &mut self,
        client_version: &str,
    ) -> std::result::Result<String, AsyncIpcClientError> {
        let response = self
            .request(&IpcMessage::Handshake {
                version: client_version.to_string(),
            })
            .await?;

        match response {
            IpcMessage::HandshakeAck { server_version, .. } => Ok(server_version),
            IpcMessage::Error { message, .. } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Handshake failed: {}",
                message
            ))),
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response to handshake: {:?}",
                other
            ))),
        }
    }

    /
    pub async fn heartbeat(&mut self) -> std::result::Result<u64, AsyncIpcClientError> {
        let response = self.request(&IpcMessage::Heartbeat).await?;

        match response {
            IpcMessage::HeartbeatAck { timestamp_ns } => Ok(timestamp_ns),
            IpcMessage::Error { message, .. } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Heartbeat failed: {}",
                message
            ))),
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response to heartbeat: {:?}",
                other
            ))),
        }
    }

    /
    pub async fn start_witnessing(
        &mut self,
        file_path: PathBuf,
    ) -> std::result::Result<(), AsyncIpcClientError> {
        let response = self
            .request(&IpcMessage::StartWitnessing { file_path })
            .await?;

        match response {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message, .. } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Start witnessing failed: {}",
                message
            ))),
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /
    pub async fn stop_witnessing(
        &mut self,
        file_path: Option<PathBuf>,
    ) -> std::result::Result<(), AsyncIpcClientError> {
        let response = self
            .request(&IpcMessage::StopWitnessing { file_path })
            .await?;

        match response {
            IpcMessage::Ok { .. } => Ok(()),
            IpcMessage::Error { message, .. } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Stop witnessing failed: {}",
                message
            ))),
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /
    pub async fn get_status(
        &mut self,
    ) -> std::result::Result<(bool, Vec<String>, u64), AsyncIpcClientError> {
        let response = self.request(&IpcMessage::GetStatus).await?;

        match response {
            IpcMessage::StatusResponse {
                running,
                tracked_files,
                uptime_secs,
            } => Ok((running, tracked_files, uptime_secs)),
            IpcMessage::Error { message, .. } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Get status failed: {}",
                message
            ))),
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /
    /
    /
    /
    pub async fn get_attestation_nonce(
        &mut self,
    ) -> std::result::Result<[u8; 32], AsyncIpcClientError> {
        let response = self.request(&IpcMessage::GetAttestationNonce).await?;

        match response {
            IpcMessage::AttestationNonceResponse { nonce } => Ok(nonce),
            IpcMessage::Error { code, message } => {
                if code == IpcErrorCode::NotInitialized {
                    Err(AsyncIpcClientError::ProtocolError(
                        "Identity not initialized - no attestation nonce available".to_string(),
                    ))
                } else {
                    Err(AsyncIpcClientError::ProtocolError(format!(
                        "Get attestation nonce failed: {}",
                        message
                    )))
                }
            }
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /
    /
    /
    /
    pub async fn export_with_nonce(
        &mut self,
        file_path: PathBuf,
        title: String,
        verifier_nonce: [u8; 32],
    ) -> std::result::Result<(String, String, Option<String>, Option<String>), AsyncIpcClientError>
    {
        let response = self
            .request(&IpcMessage::ExportWithNonce {
                file_path,
                title,
                verifier_nonce,
            })
            .await?;

        match response {
            IpcMessage::NonceExportResponse {
                success: true,
                output_path: Some(path),
                packet_hash: Some(hash),
                verifier_nonce,
                attestation_nonce,
                ..
            } => Ok((path, hash, verifier_nonce, attestation_nonce)),
            IpcMessage::NonceExportResponse {
                success: false,
                error: Some(err),
                ..
            } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Export with nonce failed: {}",
                err
            ))),
            IpcMessage::Error { message, .. } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Export with nonce failed: {}",
                message
            ))),
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }

    /
    /
    /
    /
    pub async fn verify_with_nonce(
        &mut self,
        evidence_path: PathBuf,
        expected_nonce: Option<[u8; 32]>,
    ) -> std::result::Result<(bool, bool, u64, f64, Vec<String>), AsyncIpcClientError> {
        let response = self
            .request(&IpcMessage::VerifyWithNonce {
                evidence_path,
                expected_nonce,
            })
            .await?;

        match response {
            IpcMessage::NonceVerifyResponse {
                valid,
                nonce_valid,
                checkpoint_count,
                total_elapsed_time_secs,
                errors,
                ..
            } => Ok((
                valid,
                nonce_valid,
                checkpoint_count,
                total_elapsed_time_secs,
                errors,
            )),
            IpcMessage::Error { message, .. } => Err(AsyncIpcClientError::ProtocolError(format!(
                "Verify with nonce failed: {}",
                message
            ))),
            other => Err(AsyncIpcClientError::ProtocolError(format!(
                "Unexpected response: {:?}",
                other
            ))),
        }
    }
}

impl Default for AsyncIpcClient {
    fn default() -> Self {
        Self::new()
    }
}
