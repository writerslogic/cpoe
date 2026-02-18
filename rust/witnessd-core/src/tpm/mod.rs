mod software;
mod types;
mod verification;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod secure_enclave;
#[cfg(target_os = "windows")]
mod windows;

pub use software::SoftwareProvider;
pub use types::*;
pub use verification::{verify_binding_chain, verify_quote};

use std::sync::Arc;

pub trait Provider: Send + Sync {
    fn capabilities(&self) -> Capabilities;
    fn device_id(&self) -> String;
    fn public_key(&self) -> Vec<u8>;
    fn quote(&self, nonce: &[u8], pcrs: &[u32]) -> Result<Quote, TPMError>;
    fn bind(&self, data: &[u8]) -> Result<Binding, TPMError>;
    fn verify(&self, binding: &Binding) -> Result<(), TPMError>;
    fn seal(&self, data: &[u8], policy: &[u8]) -> Result<Vec<u8>, TPMError>;
    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, TPMError>;
}

pub type ProviderHandle = Arc<dyn Provider + Send + Sync>;

pub fn detect_provider() -> ProviderHandle {
    #[cfg(target_os = "macos")]
    if let Some(provider) = secure_enclave::try_init() {
        log::info!("Initialized macOS Secure Enclave provider");
        return Arc::new(provider);
    }

    #[cfg(target_os = "windows")]
    if let Some(provider) = windows::try_init() {
        log::info!("Initialized Windows TPM 2.0 provider");
        return Arc::new(provider);
    }

    #[cfg(target_os = "linux")]
    if let Some(provider) = linux::try_init() {
        log::info!("Initialized Linux TPM 2.0 provider");
        return Arc::new(provider);
    }

    log::warn!("No hardware TPM available, using software provider");
    Arc::new(SoftwareProvider::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_software_provider_binding_chain() {
        let provider = SoftwareProvider::new();
        let binding1 = provider.bind(b"checkpoint-1").expect("bind");
        let binding2 = provider.bind(b"checkpoint-2").expect("bind");
        verify_binding_chain(&[binding1, binding2], &[]).expect("verify chain");
    }

    #[test]
    fn test_verify_quote_valid() {
        let provider = SoftwareProvider::new();
        let quote = provider.quote(b"nonce-a", &[]).expect("quote");
        assert!(verify_quote(&quote).is_ok());
    }
}
