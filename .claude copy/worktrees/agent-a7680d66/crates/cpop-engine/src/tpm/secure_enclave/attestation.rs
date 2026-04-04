

use super::counter::save_counter;
use super::platform::is_secure_enclave_available;
use super::signing::{sign, sign_with_key, verify_ecdsa_signature};
use super::types::{
    KeyAttestation, SecureEnclaveKeyInfo, SecureEnclaveProvider, SE_ATTESTATION_KEY_TAG, SE_KEY_TAG,
};
use crate::tpm::TpmError;
use crate::DateTimeNanosExt;
use crate::MutexRecover;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use subtle::ConstantTimeEq;

#[allow(dead_code)]
impl SecureEnclaveProvider {
    /
    pub fn generate_key_attestation(&self, challenge: &[u8]) -> Result<KeyAttestation, TpmError> {
        let state = self.state.lock_recover();
        let timestamp = Utc::now();

        let mut attestation_data = Vec::new();
        attestation_data.extend_from_slice(b"CPOP-ATTEST-V2\n");

        let challenge_hash = Sha256::digest(challenge);
        attestation_data.extend_from_slice(&challenge_hash);
        attestation_data.extend_from_slice(&state.public_key);
        let device_id_bytes = state.device_id.as_bytes();
        attestation_data.extend_from_slice(&(device_id_bytes.len() as u32).to_be_bytes());
        attestation_data.extend_from_slice(device_id_bytes);

        let ts_bytes = timestamp.timestamp_nanos_safe().to_le_bytes();
        attestation_data.extend_from_slice(&ts_bytes);

        if let Some(ref uuid) = state.hardware_info.uuid {
            let uuid_hash = Sha256::digest(uuid.as_bytes());
            attestation_data.extend_from_slice(&uuid_hash);
        }

        if let Some(ref model) = state.hardware_info.model {
            let model_bytes = model.as_bytes();
            attestation_data.extend_from_slice(&(model_bytes.len() as u32).to_be_bytes());
            attestation_data.extend_from_slice(model_bytes);
        }

        
        
        
        
        let attestation_proof = Sha256::digest(&attestation_data).to_vec();

        let signature = if let Some(attest_key) = state.attestation_key_ref {
            sign_with_key(attest_key, &attestation_data)?
        } else {
            sign(&state, &attestation_data)?
        };

        let mut metadata = HashMap::new();
        if let Some(ref model) = state.hardware_info.model {
            metadata.insert("model".to_string(), model.clone());
        }
        if let Some(ref version) = state.hardware_info.os_version {
            metadata.insert("os_version".to_string(), version.clone());
        }
        metadata.insert(
            "se_available".to_string(),
            state.hardware_info.se_available.to_string(),
        );

        Ok(KeyAttestation {
            version: 1,
            public_key: state.public_key.clone(),
            device_id: state.device_id.clone(),
            timestamp,
            attestation_proof,
            signature,
            metadata,
        })
    }

    /
    /
    /
    pub fn verify_key_attestation(
        &self,
        attestation: &KeyAttestation,
        expected_challenge: &[u8],
    ) -> Result<bool, TpmError> {
        let state = self.state.lock_recover();

        let mut expected_data = Vec::new();
        expected_data.extend_from_slice(b"CPOP-ATTEST-V2\n");

        let challenge_hash = Sha256::digest(expected_challenge);
        expected_data.extend_from_slice(&challenge_hash);

        expected_data.extend_from_slice(&attestation.public_key);
        let device_id_bytes = attestation.device_id.as_bytes();
        expected_data.extend_from_slice(&(device_id_bytes.len() as u32).to_be_bytes());
        expected_data.extend_from_slice(device_id_bytes);

        let ts_bytes = attestation.timestamp.timestamp_nanos_safe().to_le_bytes();
        expected_data.extend_from_slice(&ts_bytes);

        if let Some(ref uuid) = state.hardware_info.uuid {
            let uuid_hash = Sha256::digest(uuid.as_bytes());
            expected_data.extend_from_slice(&uuid_hash);
        }

        if let Some(ref model) = state.hardware_info.model {
            let model_bytes = model.as_bytes();
            expected_data.extend_from_slice(&(model_bytes.len() as u32).to_be_bytes());
            expected_data.extend_from_slice(model_bytes);
        }

        let expected_proof = Sha256::digest(&expected_data).to_vec();
        
        if attestation
            .attestation_proof
            .ct_eq(&expected_proof)
            .unwrap_u8()
            == 0
        {
            return Ok(false);
        }

        let verify_key = state
            .attestation_public_key
            .as_ref()
            .unwrap_or(&state.public_key);

        verify_ecdsa_signature(verify_key, &expected_data, &attestation.signature)
    }

    /
    pub fn get_key_info(&self) -> SecureEnclaveKeyInfo {
        let state = self.state.lock_recover();
        SecureEnclaveKeyInfo {
            tag: SE_KEY_TAG.to_string(),
            public_key: state.public_key.clone(),
            created_at: None, 
            hardware_backed: true,
            key_size: 256,
        }
    }

    /
    pub fn get_attestation_key_info(&self) -> Option<SecureEnclaveKeyInfo> {
        let state = self.state.lock_recover();
        state
            .attestation_public_key
            .as_ref()
            .map(|pk| SecureEnclaveKeyInfo {
                tag: SE_ATTESTATION_KEY_TAG.to_string(),
                public_key: pk.clone(),
                created_at: None,
                hardware_backed: true,
                key_size: 256,
            })
    }

    /
    pub fn get_hardware_info(&self) -> HashMap<String, String> {
        let state = self.state.lock_recover();
        let mut info = HashMap::new();

        if let Some(ref model) = state.hardware_info.model {
            info.insert("model".to_string(), model.clone());
        }
        if let Some(ref version) = state.hardware_info.os_version {
            info.insert("os_version".to_string(), version.clone());
        }
        info.insert("device_id".to_string(), state.device_id.clone());
        info.insert(
            "secure_enclave".to_string(),
            state.hardware_info.se_available.to_string(),
        );

        info
    }

    /
    pub fn get_counter(&self) -> u64 {
        self.state.lock_recover().counter
    }

    /
    pub fn increment_counter(&self) -> u64 {
        let mut state = self.state.lock_recover();
        state.counter += 1;
        save_counter(&state);
        state.counter
    }

    /
    pub fn is_hardware_available() -> bool {
        is_secure_enclave_available()
    }
}
