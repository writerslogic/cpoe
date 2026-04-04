

use super::orcid::OrcidIdentity;
use serde::Serialize;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum IdentityBridgeMode {
    /
    IdentityClaimsAggregator,
    /
    DidWebWithX509,
    /
    SelfSovereign,
}

/
#[derive(Debug, Clone, Serialize)]
pub struct BridgedIdentity {
    pub mode: IdentityBridgeMode,
    /
    pub author_did: String,
    /
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ica_credential: Option<serde_json::Value>,
    /
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_pem: Option<String>,
    /
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orcid: Option<OrcidIdentity>,
}

impl BridgedIdentity {
    /
    pub fn self_sovereign(did: &str) -> Self {
        Self {
            mode: IdentityBridgeMode::SelfSovereign,
            author_did: did.to_string(),
            ica_credential: None,
            x509_pem: None,
            orcid: None,
        }
    }

    /
    pub fn with_ica(did: &str, ica_credential: serde_json::Value) -> Self {
        Self {
            mode: IdentityBridgeMode::IdentityClaimsAggregator,
            author_did: did.to_string(),
            ica_credential: Some(ica_credential),
            x509_pem: None,
            orcid: None,
        }
    }

    /
    pub fn with_x509(did: &str, x509_pem: String) -> Self {
        Self {
            mode: IdentityBridgeMode::DidWebWithX509,
            author_did: did.to_string(),
            ica_credential: None,
            x509_pem: Some(x509_pem),
            orcid: None,
        }
    }

    /
    pub fn with_orcid(mut self, orcid: OrcidIdentity) -> Self {
        self.orcid = Some(orcid);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_bridge_modes() {
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

        
        let ss = BridgedIdentity::self_sovereign(did);
        assert_eq!(ss.mode, IdentityBridgeMode::SelfSovereign);
        assert_eq!(ss.author_did, did);
        assert!(ss.ica_credential.is_none());
        assert!(ss.x509_pem.is_none());
        assert!(ss.orcid.is_none());

        
        let cred = serde_json::json!({"type": "IdentityClaimsAggregation", "holder": did});
        let ica = BridgedIdentity::with_ica(did, cred.clone());
        assert_eq!(ica.mode, IdentityBridgeMode::IdentityClaimsAggregator);
        assert_eq!(ica.ica_credential.as_ref().unwrap()["holder"], did);

        
        let x509 = BridgedIdentity::with_x509(
            "did:web:writerslogic.com",
            "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----".to_string(),
        );
        assert_eq!(x509.mode, IdentityBridgeMode::DidWebWithX509);
        assert!(x509.x509_pem.is_some());

        
        let orcid = OrcidIdentity {
            orcid_id: "0000-0002-1694-233X".to_string(),
            display_name: Some("Jane Doe".to_string()),
            verified: true,
        };
        let with_orcid = BridgedIdentity::self_sovereign(did).with_orcid(orcid);
        assert!(with_orcid.orcid.is_some());
        assert_eq!(
            with_orcid.orcid.as_ref().unwrap().orcid_id,
            "0000-0002-1694-233X"
        );
    }

    #[test]
    fn test_identity_bridge_ica_mode() {
        let did = "did:key:z6MkTest";
        let cred = serde_json::json!({
            "@context": ["https:
            "type": ["VerifiableCredential", "IdentityClaimsAggregation"],
            "issuer": "did:web:writersproof.com",
            "holder": did,
            "credentialSubject": {
                "id": did,
                "authorDid": did
            }
        });

        let bridged = BridgedIdentity::with_ica(did, cred);
        assert_eq!(bridged.mode, IdentityBridgeMode::IdentityClaimsAggregator);
        assert_eq!(bridged.author_did, did);
        assert!(bridged.ica_credential.is_some());
        assert!(bridged.x509_pem.is_none());

        
        let holder = bridged.ica_credential.as_ref().unwrap()["holder"]
            .as_str()
            .unwrap();
        assert_eq!(holder, did);

        
        let json = serde_json::to_value(&bridged).expect("serialize");
        assert!(json.get("ica_credential").is_some());
        assert!(json.get("x509_pem").is_none());
    }

    #[test]
    fn test_identity_bridge_self_sovereign() {
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let bridged = BridgedIdentity::self_sovereign(did);

        assert_eq!(bridged.mode, IdentityBridgeMode::SelfSovereign);
        assert_eq!(bridged.author_did, did);
        assert!(bridged.ica_credential.is_none());
        assert!(bridged.x509_pem.is_none());
        assert!(bridged.orcid.is_none());

        
        let json = serde_json::to_value(&bridged).expect("serialize");
        assert!(json.get("ica_credential").is_none());
        assert!(json.get("x509_pem").is_none());
        assert!(json.get("orcid").is_none());
        assert_eq!(json["mode"], "SelfSovereign");
    }
}
