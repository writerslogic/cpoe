

//! IETF SCITT (Supply Chain Integrity, Transparency, and Trust) types.
//!
//! Per draft-ietf-scitt-architecture. SCITT provides standards-based transparency
//! receipts that can replace CPOP's proprietary beacon attestation format.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::evidence::WpBeaconAttestation;

/
const CPOP_CONTENT_TYPE: &str = "application/vnd.writersproof.cpop+cbor";

/
/
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedStatement {
    /
    pub envelope: Vec<u8>,
    /
    pub content_type: String,
    /
    pub subject: String,
}

/
/
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyReceipt {
    /
    pub receipt_cbor: Vec<u8>,
    /
    pub registered_at: String,
    /
    pub service_id: String,
}

/
/
/
/
pub fn evidence_to_signed_statement(evidence_cbor: &[u8], doc_hash: &[u8; 32]) -> SignedStatement {
    let subject = doc_hash.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    });

    SignedStatement {
        envelope: evidence_cbor.to_vec(),
        content_type: CPOP_CONTENT_TYPE.to_string(),
        subject,
    }
}

/
/
/
/
/
pub fn beacon_to_receipt_format(beacon: &WpBeaconAttestation) -> Result<TransparencyReceipt> {
    
    let mut buf = Vec::new();
    ciborium::into_writer(
        &ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("drand_round".to_string()),
                ciborium::value::Value::Integer(beacon.drand_round.into()),
            ),
            (
                ciborium::value::Value::Text("drand_randomness".to_string()),
                ciborium::value::Value::Text(beacon.drand_randomness.clone()),
            ),
            (
                ciborium::value::Value::Text("nist_pulse_index".to_string()),
                ciborium::value::Value::Integer(beacon.nist_pulse_index.into()),
            ),
            (
                ciborium::value::Value::Text("nist_output_value".to_string()),
                ciborium::value::Value::Text(beacon.nist_output_value.clone()),
            ),
            (
                ciborium::value::Value::Text("wp_signature".to_string()),
                ciborium::value::Value::Text(beacon.wp_signature.clone()),
            ),
        ]),
        &mut buf,
    )
    .map_err(|e| crate::error::Error::Internal(format!("CBOR serialization failed: {e}")))?;

    Ok(TransparencyReceipt {
        receipt_cbor: buf,
        registered_at: beacon.fetched_at.clone(),
        service_id: "writersproof-beacon-v1".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_to_signed_statement() {
        let evidence = vec![0xD2, 0x84, 0x01, 0x02];
        let doc_hash = [0xABu8; 32];

        let stmt = evidence_to_signed_statement(&evidence, &doc_hash);

        assert_eq!(stmt.envelope, evidence);
        assert_eq!(stmt.content_type, CPOP_CONTENT_TYPE);
        assert_eq!(stmt.subject.len(), 64);
        assert!(stmt.subject.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(stmt.subject.starts_with("ab"));
    }

    #[test]
    fn test_signed_statement_subject_is_hex_of_hash() {
        let doc_hash = [0x00u8; 32];
        let stmt = evidence_to_signed_statement(&[], &doc_hash);
        assert_eq!(
            stmt.subject,
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_beacon_to_receipt_format() {
        let beacon = WpBeaconAttestation {
            drand_round: 12345,
            drand_randomness: "aa".repeat(32),
            nist_pulse_index: 67890,
            nist_output_value: "bb".repeat(64),
            nist_timestamp: "2026-03-24T00:00:00Z".to_string(),
            fetched_at: "2026-03-24T00:00:01Z".to_string(),
            wp_signature: "cc".repeat(64),
        };

        let receipt = beacon_to_receipt_format(&beacon).unwrap();

        assert_eq!(receipt.registered_at, "2026-03-24T00:00:01Z");
        assert_eq!(receipt.service_id, "writersproof-beacon-v1");
        assert!(!receipt.receipt_cbor.is_empty());

        
        let val: ciborium::value::Value =
            ciborium::de::from_reader(&receipt.receipt_cbor[..]).expect("valid CBOR");
        let map = match val {
            ciborium::value::Value::Map(m) => m,
            _ => panic!("expected CBOR map"),
        };
        assert_eq!(map.len(), 5);
    }

    #[test]
    fn test_transparency_receipt_serde_roundtrip() {
        let receipt = TransparencyReceipt {
            receipt_cbor: vec![0xA0],
            registered_at: "2026-01-01T00:00:00Z".to_string(),
            service_id: "test-service".to_string(),
        };
        let json = serde_json::to_string(&receipt).expect("serialize");
        let decoded: TransparencyReceipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn test_scitt_signed_statement_structure() {
        let evidence = vec![0xD2, 0x84, 0x43, 0x50, 0x4F, 0x50];
        let doc_hash = [0x42u8; 32];
        let stmt = evidence_to_signed_statement(&evidence, &doc_hash);

        
        assert_eq!(stmt.envelope, evidence);
        
        assert_eq!(stmt.content_type, "application/vnd.writersproof.cpop+cbor");
        
        assert_eq!(stmt.subject.len(), 64);
        assert!(stmt.subject.starts_with("42"));
        assert!(stmt.subject.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_scitt_beacon_to_receipt() {
        let beacon = WpBeaconAttestation {
            drand_round: 99999,
            drand_randomness: "deadbeef".repeat(8),
            nist_pulse_index: 55555,
            nist_output_value: "cafebabe".repeat(16),
            nist_timestamp: "2026-03-25T12:00:00Z".to_string(),
            fetched_at: "2026-03-25T12:00:05Z".to_string(),
            wp_signature: "ff".repeat(64),
        };

        let receipt = beacon_to_receipt_format(&beacon).unwrap();

        
        assert_eq!(receipt.registered_at, "2026-03-25T12:00:05Z");
        
        assert_eq!(receipt.service_id, "writersproof-beacon-v1");
        
        let val: ciborium::value::Value =
            ciborium::de::from_reader(&receipt.receipt_cbor[..]).expect("valid CBOR");
        let map = match val {
            ciborium::value::Value::Map(m) => m,
            _ => panic!("expected CBOR map in receipt"),
        };
        assert_eq!(map.len(), 5);

        
        let has_drand_round = map.iter().any(|(k, v)| {
            matches!(k, ciborium::value::Value::Text(s) if s == "drand_round")
                && matches!(v, ciborium::value::Value::Integer(i) if {
                    let n: i128 = (*i).into();
                    n == 99999
                })
        });
        assert!(has_drand_round, "receipt should contain drand_round=99999");
    }

    #[test]
    fn test_signed_statement_serde_roundtrip() {
        let stmt = SignedStatement {
            envelope: vec![0x01, 0x02],
            content_type: CPOP_CONTENT_TYPE.to_string(),
            subject: "abcd".to_string(),
        };
        let json = serde_json::to_string(&stmt).expect("serialize");
        let decoded: SignedStatement = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(stmt, decoded);
    }
}
