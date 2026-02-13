#![cfg(target_os = "windows")]

//! Windows TPM provider stub.
//!
//! The tss-esapi crate does not support Windows. Until native Windows TPM
//! support via the TBS API is implemented, this module returns None from
//! try_init() to use the software fallback provider.

use super::{Binding, Capabilities, Provider, Quote, TPMError};

pub struct WindowsTpmProvider;

/// Always returns None to use software fallback.
/// Windows native TPM support via TBS API is not yet implemented.
pub fn try_init() -> Option<WindowsTpmProvider> {
    // TODO: Implement Windows TPM support using the native TBS API
    // via the windows crate. For now, use software fallback.
    None
}

impl Provider for WindowsTpmProvider {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hardware_backed: false,
            supports_pcrs: false,
            supports_sealing: false,
            supports_attestation: false,
            monotonic_counter: false,
            secure_clock: false,
        }
    }

    fn device_id(&self) -> String {
        "windows-stub".to_string()
    }

    fn public_key(&self) -> Vec<u8> {
        Vec::new()
    }

    fn quote(&self, _nonce: &[u8], _pcrs: &[u32]) -> Result<Quote, TPMError> {
        Err(TPMError::NotAvailable)
    }

    fn bind(&self, _data: &[u8]) -> Result<Binding, TPMError> {
        Err(TPMError::NotAvailable)
    }

    fn verify(&self, _binding: &Binding) -> Result<(), TPMError> {
        Err(TPMError::NotAvailable)
    }

    fn seal(&self, _data: &[u8], _policy: &[u8]) -> Result<Vec<u8>, TPMError> {
        Err(TPMError::NotAvailable)
    }

    fn unseal(&self, _sealed: &[u8]) -> Result<Vec<u8>, TPMError> {
        Err(TPMError::NotAvailable)
    }
}
