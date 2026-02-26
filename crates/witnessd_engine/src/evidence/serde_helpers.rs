// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Serialization helpers for hex-encoded byte arrays used in evidence packets.

use serde::{Deserialize, Deserializer, Serializer};

pub(crate) fn serialize_optional_nonce<S>(
    nonce: &Option<[u8; 32]>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match nonce {
        Some(n) => serializer.serialize_some(&hex::encode(n)),
        None => serializer.serialize_none(),
    }
}

pub(crate) fn deserialize_optional_nonce<'de, D>(
    deserializer: D,
) -> Result<Option<[u8; 32]>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        Some(hex_str) => {
            let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
            if bytes.len() != 32 {
                return Err(serde::de::Error::custom("nonce must be 32 bytes"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(Some(arr))
        }
        None => Ok(None),
    }
}

pub(crate) fn serialize_optional_signature<S>(
    sig: &Option<[u8; 64]>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match sig {
        Some(s) => serializer.serialize_some(&hex::encode(s)),
        None => serializer.serialize_none(),
    }
}

pub(crate) fn deserialize_optional_signature<'de, D>(
    deserializer: D,
) -> Result<Option<[u8; 64]>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        Some(hex_str) => {
            let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
            if bytes.len() != 64 {
                return Err(serde::de::Error::custom("signature must be 64 bytes"));
            }
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&bytes);
            Ok(Some(arr))
        }
        None => Ok(None),
    }
}

pub(crate) fn serialize_optional_pubkey<S>(
    key: &Option<[u8; 32]>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match key {
        Some(k) => serializer.serialize_some(&hex::encode(k)),
        None => serializer.serialize_none(),
    }
}

pub(crate) fn deserialize_optional_pubkey<'de, D>(
    deserializer: D,
) -> Result<Option<[u8; 32]>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        Some(hex_str) => {
            let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
            if bytes.len() != 32 {
                return Err(serde::de::Error::custom("public key must be 32 bytes"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(Some(arr))
        }
        None => Ok(None),
    }
}
