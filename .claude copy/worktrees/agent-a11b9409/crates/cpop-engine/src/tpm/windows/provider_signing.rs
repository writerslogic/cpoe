

//! TPM2 signing operations: sign_payload, create_signing_key, tpm2_sign.

use sha2::{Digest, Sha256};

use super::context::TbsContext;
use super::helpers::{build_empty_auth_area, build_srk_public_ecc};
use super::provider::WindowsTpmProvider;
use super::types::*;
use crate::tpm::TpmError;

impl WindowsTpmProvider {
    /
    /
    /
    /
    pub(super) fn sign_payload(&self, ctx: &TbsContext, data: &[u8]) -> Result<Vec<u8>, TpmError> {
        
        let srk_response = self
            .create_primary_srk(ctx)
            .map_err(|e| TpmError::Signing(format!("SRK creation: {e}")))?;
        if srk_response.len() < 14 {
            return Err(TpmError::Signing("SRK response too short".into()));
        }
        let srk_handle = super::helpers::read_u32_be(&srk_response, 10)
            .map_err(|e| TpmError::Signing(format!("SRK handle parse: {e}")))?;

        
        let signing_key_blob = self
            .create_signing_key(ctx, srk_handle)
            .map_err(|e| TpmError::Signing(format!("signing key create: {e}")))?;

        
        let key_handle = self
            .load_key(ctx, srk_handle, &signing_key_blob)
            .map_err(|e| TpmError::Signing(format!("signing key load: {e}")))?;

        
        let digest: [u8; 32] = Sha256::digest(data).into();

        
        let sign_result = self.tpm2_sign(ctx, key_handle, &digest);

        
        let _ = self.flush_context(ctx, key_handle);
        let _ = self.flush_context(ctx, srk_handle);

        sign_result
    }

    /
    fn create_signing_key(
        &self,
        ctx: &TbsContext,
        parent_handle: u32,
    ) -> Result<Vec<u8>, TpmError> {
        let mut body = Vec::new();
        body.extend_from_slice(&parent_handle.to_be_bytes());

        let auth_area = build_empty_auth_area(parent_handle);
        body.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
        body.extend_from_slice(&auth_area);

        
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());

        let public_area = super::helpers::build_signing_key_public_ecc();
        body.extend_from_slice(&(public_area.len() as u16).to_be_bytes());
        body.extend_from_slice(&public_area);

        body.extend_from_slice(&0u16.to_be_bytes()); 
        body.extend_from_slice(&0u32.to_be_bytes()); 

        let mut cmd = Vec::with_capacity(10 + body.len());
        let command_size = (10 + body.len()) as u32;
        cmd.extend_from_slice(&TPM2_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&command_size.to_be_bytes());
        cmd.extend_from_slice(&TPM2_CC_CREATE.to_be_bytes());
        cmd.extend_from_slice(&body);

        let response = ctx
            .submit_command(&cmd)
            .map_err(|e| TpmError::Signing(format!("TPM2_Create: {e}")))?;

        
        self.parse_create_response(&response)
            .map_err(|e| TpmError::Signing(format!("parse signing key: {e}")))
    }

    /
    pub(super) fn load_key(
        &self,
        ctx: &TbsContext,
        parent_handle: u32,
        blob: &[u8],
    ) -> Result<u32, TpmError> {
        
        let pub_len = super::helpers::read_u32_be(blob, 0)
            .map_err(|e| TpmError::Signing(format!("load key blob parse: {e}")))?
            as usize;
        if 4 + pub_len > blob.len() {
            return Err(TpmError::Signing(
                "load key blob: pub_len exceeds blob size".into(),
            ));
        }
        let pub_bytes = &blob[4..4 + pub_len];
        let priv_offset = 4 + pub_len;
        let priv_len = super::helpers::read_u32_be(blob, priv_offset)
            .map_err(|e| TpmError::Signing(format!("load key blob parse: {e}")))?
            as usize;
        if priv_offset + 4 + priv_len > blob.len() {
            return Err(TpmError::Signing(
                "load key blob: priv_len exceeds blob size".into(),
            ));
        }
        let priv_bytes = &blob[priv_offset + 4..priv_offset + 4 + priv_len];

        let mut body = Vec::new();
        body.extend_from_slice(&parent_handle.to_be_bytes());

        let auth_area = build_empty_auth_area(parent_handle);
        body.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
        body.extend_from_slice(&auth_area);

        
        body.extend_from_slice(&(priv_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(priv_bytes);

        
        body.extend_from_slice(&(pub_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(pub_bytes);

        let mut cmd = Vec::with_capacity(10 + body.len());
        let command_size = (10 + body.len()) as u32;
        cmd.extend_from_slice(&TPM2_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&command_size.to_be_bytes());
        cmd.extend_from_slice(&TPM2_CC_LOAD.to_be_bytes());
        cmd.extend_from_slice(&body);

        let response = ctx
            .submit_command(&cmd)
            .map_err(|e| TpmError::Signing(format!("TPM2_Load: {e}")))?;

        if response.len() < 14 {
            return Err(TpmError::Signing("TPM2_Load response too short".into()));
        }
        let rc = super::helpers::read_u32_be(&response, 6)
            .map_err(|e| TpmError::Signing(format!("Load rc parse: {e}")))?;
        if rc != TPM_RC_SUCCESS {
            return Err(TpmError::Signing(format!("TPM2_Load rc=0x{rc:08X}")));
        }

        super::helpers::read_u32_be(&response, 10)
            .map_err(|e| TpmError::Signing(format!("Load handle parse: {e}")))
    }

    /
    /
    /
    fn tpm2_sign(
        &self,
        ctx: &TbsContext,
        key_handle: u32,
        digest: &[u8; 32],
    ) -> Result<Vec<u8>, TpmError> {
        let mut body = Vec::new();
        body.extend_from_slice(&key_handle.to_be_bytes());

        let auth_area = build_empty_auth_area(key_handle);
        body.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
        body.extend_from_slice(&auth_area);

        
        body.extend_from_slice(&(digest.len() as u16).to_be_bytes());
        body.extend_from_slice(digest);

        
        body.extend_from_slice(&TPM2_ALG_ECDSA.to_be_bytes());
        body.extend_from_slice(&TPM2_ALG_SHA256.to_be_bytes());

        
        body.extend_from_slice(&TPM2_ST_HASHCHECK.to_be_bytes());
        body.extend_from_slice(&TPM2_RH_NULL.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes()); 

        let mut cmd = Vec::with_capacity(10 + body.len());
        let command_size = (10 + body.len()) as u32;
        cmd.extend_from_slice(&TPM2_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&command_size.to_be_bytes());
        cmd.extend_from_slice(&TPM2_CC_SIGN.to_be_bytes());
        cmd.extend_from_slice(&body);

        let response = ctx
            .submit_command(&cmd)
            .map_err(|e| TpmError::Signing(format!("TPM2_Sign: {e}")))?;

        if response.len() < 10 {
            return Err(TpmError::Signing("TPM2_Sign response too short".into()));
        }
        let rc = super::helpers::read_u32_be(&response, 6)
            .map_err(|e| TpmError::Signing(format!("Sign rc parse: {e}")))?;
        if rc != TPM_RC_SUCCESS {
            return Err(TpmError::Signing(format!("TPM2_Sign rc=0x{rc:08X}")));
        }

        self.parse_ecdsa_signature(&response)
    }

    /
    fn parse_ecdsa_signature(&self, response: &[u8]) -> Result<Vec<u8>, TpmError> {
        if response.len() < 14 {
            return Err(TpmError::Signing("TPM2_Sign response too short".into()));
        }
        let rc = super::helpers::read_u32_be(response, 6)
            .map_err(|e| TpmError::Signing(format!("Sign rc parse: {e}")))?;
        if rc != TPM_RC_SUCCESS {
            return Err(TpmError::Signing(format!("TPM2_Sign rc=0x{rc:08X}")));
        }

        
        
        let mut offset = 14;
        if offset + 4 > response.len() {
            return Err(TpmError::Signing("missing signature header".into()));
        }
        offset += 2; 
        offset += 2; 

        
        if offset + 2 > response.len() {
            return Err(TpmError::Signing("missing r size".into()));
        }
        let r_size = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
        offset += 2;
        if offset + r_size > response.len() || r_size > 32 {
            return Err(TpmError::Signing("r truncated or oversized".into()));
        }
        
        let mut r = [0u8; 32];
        r[32 - r_size..].copy_from_slice(&response[offset..offset + r_size]);
        offset += r_size;

        
        if offset + 2 > response.len() {
            return Err(TpmError::Signing("missing s size".into()));
        }
        let s_size = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
        offset += 2;
        if offset + s_size > response.len() || s_size > 32 {
            return Err(TpmError::Signing("s truncated or oversized".into()));
        }
        let mut s = [0u8; 32];
        s[32 - s_size..].copy_from_slice(&response[offset..offset + s_size]);

        let mut signature = Vec::with_capacity(64);
        signature.extend_from_slice(&r);
        signature.extend_from_slice(&s);
        Ok(signature)
    }

    /
    pub(super) fn create_primary_srk(&self, ctx: &TbsContext) -> Result<Vec<u8>, TbsError> {
        let mut cmd = Vec::with_capacity(128);
        let mut body = Vec::new();

        body.extend_from_slice(&TPM2_RH_OWNER.to_be_bytes());

        let auth_area = build_empty_auth_area(TPM2_RH_OWNER);
        body.extend_from_slice(&(auth_area.len() as u32).to_be_bytes());
        body.extend_from_slice(&auth_area);

        body.extend_from_slice(&4u16.to_be_bytes()); 
        body.extend_from_slice(&0u16.to_be_bytes()); 
        body.extend_from_slice(&0u16.to_be_bytes()); 

        let public_area = build_srk_public_ecc();
        body.extend_from_slice(&(public_area.len() as u16).to_be_bytes());
        body.extend_from_slice(&public_area);

        body.extend_from_slice(&0u16.to_be_bytes()); 
        body.extend_from_slice(&0u32.to_be_bytes()); 

        let command_size = (10 + body.len()) as u32;
        cmd.extend_from_slice(&TPM2_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&command_size.to_be_bytes());
        cmd.extend_from_slice(&TPM2_CC_CREATE_PRIMARY.to_be_bytes());
        cmd.extend_from_slice(&body);

        ctx.submit_command(&cmd)
    }

    /
    pub(super) fn parse_create_response(&self, response: &[u8]) -> Result<Vec<u8>, String> {
        if response.len() < 16 {
            return Err("response too short".into());
        }

        let mut offset = 14; 

        if offset + 2 > response.len() {
            return Err("missing outPrivate size".into());
        }
        let priv_size = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
        offset += 2;
        if offset + priv_size > response.len() {
            return Err("outPrivate truncated".into());
        }
        let priv_bytes = &response[offset..offset + priv_size];
        offset += priv_size;

        if offset + 2 > response.len() {
            return Err("missing outPublic size".into());
        }
        let pub_size = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
        offset += 2;
        if offset + pub_size > response.len() {
            return Err("outPublic truncated".into());
        }
        let pub_bytes = &response[offset..offset + pub_size];

        let mut blob = Vec::with_capacity(8 + pub_bytes.len() + priv_bytes.len());
        blob.extend_from_slice(&(pub_bytes.len() as u32).to_be_bytes());
        blob.extend_from_slice(pub_bytes);
        blob.extend_from_slice(&(priv_bytes.len() as u32).to_be_bytes());
        blob.extend_from_slice(priv_bytes);

        Ok(blob)
    }

    pub(super) fn flush_context(&self, ctx: &TbsContext, handle: u32) -> Result<(), TbsError> {
        let mut cmd = Vec::with_capacity(14);
        let command_size: u32 = 14;
        cmd.extend_from_slice(&TPM2_ST_NO_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&command_size.to_be_bytes());
        cmd.extend_from_slice(&TPM2_CC_FLUSH_CONTEXT.to_be_bytes());
        cmd.extend_from_slice(&handle.to_be_bytes());
        ctx.submit_command(&cmd)?;
        Ok(())
    }

    pub(super) fn build_quote_attestation_data(
        &self,
        nonce: &[u8],
        pcr_values: &[super::super::PcrValue],
        timestamp: &chrono::DateTime<chrono::Utc>,
    ) -> Vec<u8> {
        let mut data = Vec::new();

        data.extend_from_slice(&0xFF544347u32.to_be_bytes()); 
        data.extend_from_slice(&0x8018u16.to_be_bytes()); 
        data.extend_from_slice(&0u16.to_be_bytes()); 

        let nonce_len = nonce.len().min(64) as u16;
        data.extend_from_slice(&nonce_len.to_be_bytes());
        data.extend_from_slice(&nonce[..nonce_len as usize]);

        let clock = timestamp.timestamp() as u64;
        data.extend_from_slice(&clock.to_be_bytes()); 
        data.extend_from_slice(&0u32.to_be_bytes()); 
        data.extend_from_slice(&0u32.to_be_bytes()); 
        data.push(1); 

        data.extend_from_slice(&0u64.to_be_bytes()); 
        let mut pcr_digest = Sha256::new();
        for pcr in pcr_values {
            pcr_digest.update(&pcr.value);
        }
        let digest = pcr_digest.finalize();
        data.extend_from_slice(&(digest.len() as u16).to_be_bytes());
        data.extend_from_slice(&digest);

        data
    }
}
