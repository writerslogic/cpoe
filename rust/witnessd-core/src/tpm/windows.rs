#![cfg(target_os = "windows")]

use super::{
    default_pcr_selection, Attestation, Binding, Capabilities, PCRSelection, PcrValue, Provider,
    Quote, TPMError,
};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use tss_esapi::attributes::{NvIndexAttributes, ObjectAttributesBuilder};
use tss_esapi::constants::CapabilityType;
use tss_esapi::handles::{AuthHandle, KeyHandle, NvIndexTpmHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{
    HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm, SignatureSchemeAlgorithm,
};
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    Auth, Data, Digest, DigestList, EccScheme, NvPublicBuilder, PcrSelectionList,
    PcrSelectionListBuilder, PcrSlot, Public, PublicBuilder, PublicEccKey,
    PublicEccParametersBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent, RsaScheme,
    SignatureScheme, SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::traits::Marshall;
use tss_esapi::Context;

const NV_COUNTER_INDEX: u32 = 0x01500001;
const NV_COUNTER_SIZE: u16 = 8;

struct WindowsState {
    context: Context,
    ak_handle: Option<KeyHandle>,
    ak_public: Vec<u8>,
    counter_init: bool,
    manufacturer: String,
    fw_version: String,
}

pub struct WindowsTpmProvider {
    inner: Mutex<WindowsState>,
}

pub fn try_init() -> Option<WindowsTpmProvider> {
    let tcti = TctiNameConf::from_environment_variable().unwrap_or_else(|_| TctiNameConf::Tbs);
    let context = Context::new(tcti).ok()?;

    let mut state = WindowsState {
        context,
        ak_handle: None,
        ak_public: Vec::new(),
        counter_init: false,
        manufacturer: String::new(),
        fw_version: String::new(),
    };

    if read_properties(&mut state).is_err() {
        return None;
    }

    if let Ok((ak, pub_bytes)) = create_ak(&mut state) {
        state.ak_handle = Some(ak);
        state.ak_public = pub_bytes;
    } else {
        return None;
    }

    Some(WindowsTpmProvider {
        inner: Mutex::new(state),
    })
}

impl Provider for WindowsTpmProvider {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hardware_backed: true,
            supports_pcrs: true,
            supports_sealing: true,
            supports_attestation: true,
            monotonic_counter: true,
            secure_clock: false,
        }
    }

    fn device_id(&self) -> String {
        let mut state = self.inner.lock().unwrap();
        match get_device_id(&mut state) {
            Ok(id) => format!("tpm-{}", hex::encode(&id[..8])),
            Err(_) => "tpm-unknown".to_string(),
        }
    }

    fn public_key(&self) -> Vec<u8> {
        self.inner.lock().unwrap().ak_public.clone()
    }

    fn quote(&self, nonce: &[u8], pcrs: &[u32]) -> Result<Quote, TPMError> {
        let mut state = self.inner.lock().unwrap();
        let ak_handle = state.ak_handle.ok_or(TPMError::NotAvailable)?;

        let pcr_list = if pcrs.is_empty() {
            default_pcr_selection().pcrs
        } else {
            pcrs.to_vec()
        };
        let selection = build_pcr_selection(&pcr_list)?;
        let qualifying = if nonce.len() > 64 {
            Sha256::digest(nonce).to_vec()
        } else {
            nonce.to_vec()
        };

        let (attest, signature) = state
            .context
            .quote(
                ak_handle,
                Data::try_from(qualifying).map_err(|_| TPMError::Quote("bad nonce".into()))?,
                SignatureScheme::create(SignatureSchemeAlgorithm::RsaSsa, HashingAlgorithm::Sha256)
                    .map_err(|_| TPMError::Quote("scheme".into()))?,
                selection,
            )
            .map_err(|_| TPMError::Quote("quote failed".into()))?;

        let pcr_values = read_pcrs(&mut state, &pcr_list)?;

        let attest_data = attest
            .marshall()
            .map_err(|_| TPMError::Quote("attest marshal".into()))?;
        let sig_data = signature
            .marshall()
            .map_err(|_| TPMError::Quote("sig marshal".into()))?;

        Ok(Quote {
            provider_type: "tpm2-windows".to_string(),
            device_id: self.device_id(),
            timestamp: Utc::now(),
            nonce: nonce.to_vec(),
            attested_data: attest_data,
            signature: sig_data,
            public_key: state.ak_public.clone(),
            pcr_values,
            extra: Default::default(),
        })
    }

    fn bind(&self, data: &[u8]) -> Result<Binding, TPMError> {
        let mut state = self.inner.lock().unwrap();
        let ak_handle = state.ak_handle.ok_or(TPMError::NotAvailable)?;

        let timestamp = Utc::now();
        let data_hash = Sha256::digest(data).to_vec();

        let mut payload = Vec::new();
        payload.extend_from_slice(&data_hash);
        payload.extend_from_slice(&timestamp.timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
        payload.extend_from_slice(self.device_id().as_bytes());

        let digest = Sha256::digest(&payload);
        let signature = state
            .context
            .sign(
                ak_handle,
                Digest::try_from(digest.as_slice())
                    .map_err(|_| TPMError::Signing("digest".into()))?,
                SignatureScheme::create(SignatureSchemeAlgorithm::RsaSsa, HashingAlgorithm::Sha256)
                    .map_err(|_| TPMError::Signing("scheme".into()))?,
                None,
            )
            .map_err(|_| TPMError::Signing("sign failed".into()))?
            .marshall()
            .map_err(|_| TPMError::Signing("sig marshal".into()))?;

        let counter = increment_counter(&mut state).ok();

        Ok(Binding {
            version: 1,
            provider_type: "tpm2-windows".to_string(),
            device_id: self.device_id(),
            timestamp,
            attested_hash: data_hash,
            signature,
            public_key: state.ak_public.clone(),
            monotonic_counter: counter,
            safe_clock: None,
            attestation: Some(Attestation {
                payload,
                quote: None,
            }),
        })
    }

    fn verify(&self, binding: &Binding) -> Result<(), TPMError> {
        super::verification::verify_binding(binding)
    }

    fn seal(&self, data: &[u8], _policy: &[u8]) -> Result<Vec<u8>, TPMError> {
        let mut state = self.inner.lock().unwrap();
        let pcrs = default_pcr_selection();
        let srk = create_srk(&mut state)?;

        let session = create_policy_session(&mut state, &pcrs)?;

        let (private, public) = state
            .context
            .create(
                srk.key_handle,
                None,
                None,
                Some(Data::try_from(data.to_vec()).map_err(|_| TPMError::Sealing("data".into()))?),
                None,
            )
            .map_err(|_| TPMError::Sealing("create".into()))?;

        let pub_bytes = public
            .marshall()
            .map_err(|_| TPMError::Sealing("public".into()))?;
        let priv_bytes = private
            .marshall()
            .map_err(|_| TPMError::Sealing("private".into()))?;

        let mut sealed = Vec::with_capacity(8 + pub_bytes.len() + priv_bytes.len());
        sealed.extend_from_slice(&(pub_bytes.len() as u32).to_be_bytes());
        sealed.extend_from_slice(&pub_bytes);
        sealed.extend_from_slice(&(priv_bytes.len() as u32).to_be_bytes());
        sealed.extend_from_slice(&priv_bytes);

        let _ = state.context.flush_context(srk.key_handle.into());
        let _ = state.context.flush_context(session.into());

        Ok(sealed)
    }

    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, TPMError> {
        let mut state = self.inner.lock().unwrap();

        if sealed.len() < 8 {
            return Err(TPMError::SealedDataTooShort);
        }
        let pub_len = u32::from_be_bytes([sealed[0], sealed[1], sealed[2], sealed[3]]) as usize;
        if sealed.len() < 4 + pub_len + 4 {
            return Err(TPMError::SealedCorrupted);
        }
        let pub_bytes = &sealed[4..4 + pub_len];
        let offset = 4 + pub_len;
        let priv_len = u32::from_be_bytes([
            sealed[offset],
            sealed[offset + 1],
            sealed[offset + 2],
            sealed[offset + 3],
        ]) as usize;
        if sealed.len() < offset + 4 + priv_len {
            return Err(TPMError::SealedCorrupted);
        }
        let priv_bytes = &sealed[offset + 4..offset + 4 + priv_len];

        let public =
            Public::unmarshall(pub_bytes).map_err(|_| TPMError::Unsealing("public".into()))?;
        let private = tss_esapi::structures::Private::unmarshall(priv_bytes)
            .map_err(|_| TPMError::Unsealing("private".into()))?;

        let srk = create_srk(&mut state)?;

        let load_handle = state
            .context
            .load(srk.key_handle, private, public)
            .map_err(|_| TPMError::Unsealing("load".into()))?;

        let session = create_policy_session(&mut state, &default_pcr_selection())?;

        let unsealed = state
            .context
            .unseal(load_handle, session)
            .map_err(|_| TPMError::Unsealing("unseal".into()))?;

        let _ = state.context.flush_context(load_handle.into());
        let _ = state.context.flush_context(srk.key_handle.into());
        let _ = state.context.flush_context(session.into());

        Ok(unsealed.value().to_vec())
    }
}

fn read_properties(state: &mut WindowsState) -> Result<(), TPMError> {
    let caps = state
        .context
        .get_capability(CapabilityType::TpmProperties, 0x00000105, 1)
        .map_err(|_| TPMError::NotAvailable)?;
    if let Ok(props) = caps.1.data().tpm_properties() {
        if let Some(prop) = props.tpm_property().first() {
            let mfr = prop.value();
            state.manufacturer = format!(
                "{}{}{}{}",
                (mfr >> 24) as u8 as char,
                (mfr >> 16) as u8 as char,
                (mfr >> 8) as u8 as char,
                mfr as u8 as char
            );
        }
    }

    let caps = state
        .context
        .get_capability(CapabilityType::TpmProperties, 0x00000106, 2)
        .map_err(|_| TPMError::NotAvailable)?;
    if let Ok(props) = caps.1.data().tpm_properties() {
        let entries = props.tpm_property();
        if entries.len() >= 2 {
            state.fw_version = format!("{}.{}", entries[0].value(), entries[1].value());
        }
    }

    Ok(())
}

fn create_ak(state: &mut WindowsState) -> Result<(KeyHandle, Vec<u8>), TPMError> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_sign_encrypt(true)
        .build()
        .map_err(|_| TPMError::NotAvailable)?;

    let rsa_params = PublicRsaParametersBuilder::new()
        .with_symmetric(SymmetricDefinitionObject::Null)
        .with_scheme(
            RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
                .map_err(|_| TPMError::NotAvailable)?,
        )
        .with_key_bits(2048)
        .with_exponent(RsaExponent::default())
        .build()
        .map_err(|_| TPMError::NotAvailable)?;

    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(rsa_params)
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .map_err(|_| TPMError::NotAvailable)?;

    let result = state
        .context
        .create_primary(Hierarchy::Endorsement, public, None, None, None)
        .map_err(|_| TPMError::NotAvailable)?;

    let pub_bytes = result
        .out_public
        .marshall()
        .map_err(|_| TPMError::NotAvailable)?;

    Ok((result.key_handle, pub_bytes))
}

fn create_srk(
    state: &mut WindowsState,
) -> Result<tss_esapi::handles::CreatePrimaryKeyResult, TPMError> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .map_err(|_| TPMError::Sealing("attributes".into()))?;

    let ecc_params = tss_esapi::structures::PublicEccParametersBuilder::new()
        .with_symmetric(SymmetricDefinitionObject::Null)
        .with_scheme(tss_esapi::structures::EccScheme::Null)
        .with_curve_id(tss_esapi::interface_types::ecc::EccCurve::NistP256)
        .build()
        .map_err(|_| TPMError::Sealing("ecc params".into()))?;

    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(tss_esapi::structures::PublicEccKey::default())
        .build()
        .map_err(|_| TPMError::Sealing("public".into()))?;

    state
        .context
        .create_primary(Hierarchy::Owner, public, None, None, None)
        .map_err(|_| TPMError::Sealing("create primary".into()))
}

fn get_device_id(state: &mut WindowsState) -> Result<Vec<u8>, TPMError> {
    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(
            ObjectAttributesBuilder::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(false)
                .with_decrypt(true)
                .with_restricted(true)
                .build()
                .map_err(|_| TPMError::NotAvailable)?,
        )
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new()
                .with_symmetric(SymmetricDefinitionObject::Aes128Cfb)
                .with_scheme(
                    RsaScheme::create(RsaSchemeAlgorithm::Null, None)
                        .map_err(|_| TPMError::NotAvailable)?,
                )
                .with_key_bits(2048)
                .with_exponent(RsaExponent::default())
                .build()
                .map_err(|_| TPMError::NotAvailable)?,
        )
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .map_err(|_| TPMError::NotAvailable)?;

    let result = state
        .context
        .create_primary(Hierarchy::Endorsement, public, None, None, None)
        .map_err(|_| TPMError::NotAvailable)?;

    let pub_bytes = result
        .out_public
        .marshall()
        .map_err(|_| TPMError::NotAvailable)?;

    state.context.flush_context(result.key_handle.into()).ok();

    let hash = Sha256::digest(&pub_bytes);
    Ok(hash.to_vec())
}

fn build_pcr_selection(pcrs: &[u32]) -> Result<PcrSelectionList, TPMError> {
    let mut selection = vec![];
    for pcr in pcrs {
        selection.push(PcrSlot::try_from(*pcr as u8).map_err(|_| TPMError::NotAvailable)?);
    }
    let list = tss_esapi::structures::PcrSelection::create(HashingAlgorithm::Sha256, selection)
        .map_err(|_| TPMError::NotAvailable)?;

    let list = PcrSelectionListBuilder::new()
        .with_selection(
            PcrSelectionList::from_selections(vec![list]).map_err(|_| TPMError::NotAvailable)?,
        )
        .build();

    Ok(list)
}

fn read_pcrs(state: &mut WindowsState, pcrs: &[u32]) -> Result<Vec<PcrValue>, TPMError> {
    let selection = build_pcr_selection(pcrs)?;
    let (_, digests) = state
        .context
        .pcr_read(selection)
        .map_err(|_| TPMError::Quote("pcr read".into()))?;

    let digest_list = match digests {
        DigestList::Digests(list) => list,
        _ => Vec::new(),
    };

    let mut values = Vec::new();
    for (idx, pcr) in pcrs.iter().enumerate() {
        if let Some(digest) = digest_list.get(idx) {
            values.push(PcrValue {
                index: *pcr,
                value: digest.value().to_vec(),
            });
        }
    }

    Ok(values)
}

fn init_counter(state: &mut WindowsState) -> Result<(), TPMError> {
    let nv_index = NvIndexTpmHandle::new(NV_COUNTER_INDEX).map_err(|_| TPMError::CounterNotInit)?;
    let handle = TpmHandle::NvIndex(nv_index);

    if state.context.nv_read_public(handle).is_ok() {
        state.counter_init = true;
        return Ok(());
    }

    let attributes = NvIndexAttributes::builder()
        .with_nv_counter(true)
        .with_owner_write(true)
        .with_owner_read(true)
        .build()
        .map_err(|_| TPMError::CounterNotInit)?;

    let public = NvPublicBuilder::new()
        .with_nv_index(handle)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_attributes(attributes)
        .with_data_size(NV_COUNTER_SIZE)
        .build()
        .map_err(|_| TPMError::CounterNotInit)?;

    state
        .context
        .nv_define_space(AuthHandle::Owner, Auth::default(), public)
        .map_err(|_| TPMError::CounterNotInit)?;

    state.counter_init = true;
    Ok(())
}

fn read_counter(state: &mut WindowsState) -> Result<u64, TPMError> {
    let nv_index = NvIndexTpmHandle::new(NV_COUNTER_INDEX).map_err(|_| TPMError::CounterNotInit)?;
    let handle = TpmHandle::NvIndex(nv_index);
    let data = state
        .context
        .nv_read(AuthHandle::NvIndex(handle), handle, NV_COUNTER_SIZE, 0)
        .map_err(|_| TPMError::CounterNotInit)?;

    let bytes = data.value();
    if bytes.len() < 8 {
        return Err(TPMError::CounterNotInit);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    Ok(u64::from_be_bytes(buf))
}

fn increment_counter(state: &mut WindowsState) -> Result<u64, TPMError> {
    if !state.counter_init {
        init_counter(state)?;
    }

    let nv_index = NvIndexTpmHandle::new(NV_COUNTER_INDEX).map_err(|_| TPMError::CounterNotInit)?;
    let handle = TpmHandle::NvIndex(nv_index);
    state
        .context
        .nv_increment(AuthHandle::NvIndex(handle), handle)
        .map_err(|_| TPMError::CounterNotInit)?;
    read_counter(state)
}

fn create_policy_session(
    state: &mut WindowsState,
    pcrs: &PCRSelection,
) -> Result<tss_esapi::handles::SessionHandle, TPMError> {
    let selection = build_pcr_selection(&pcrs.pcrs)?;
    let session = state
        .context
        .start_auth_session(
            None,
            None,
            None,
            tss_esapi::interface_types::session_handles::SessionType::Policy,
            SymmetricDefinitionObject::Null,
            HashingAlgorithm::Sha256,
        )
        .map_err(|_| TPMError::Sealing("session".into()))?;

    state
        .context
        .policy_pcr(session, Digest::default(), selection)
        .map_err(|_| TPMError::Sealing("policy".into()))?;

    Ok(session)
}
