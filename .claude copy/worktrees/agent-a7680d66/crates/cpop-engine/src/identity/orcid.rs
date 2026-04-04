

use serde::Serialize;

/
#[derive(Debug, Clone, Serialize)]
pub struct OrcidIdentity {
    /
    pub orcid_id: String,
    /
    pub display_name: Option<String>,
    /
    pub verified: bool,
}

/
/
/
/
pub fn validate_orcid(orcid: &str) -> bool {
    let stripped: String = orcid.chars().filter(|c| *c != '-').collect();
    if stripped.len() != 16 {
        return false;
    }

    
    let (body, check_char) = stripped.split_at(15);
    if !body.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let last = check_char.chars().next().unwrap_or(' ');
    if !last.is_ascii_digit() && last != 'X' {
        return false;
    }

    
    let mut total: u32 = 0;
    for c in body.chars() {
        let digit = c.to_digit(10).unwrap_or(0);
        total = (total + digit) * 2;
    }
    let remainder = total % 11;
    let expected = (12 - remainder) % 11;
    let check_value = if last == 'X' {
        10
    } else {
        last.to_digit(10).unwrap_or(99)
    };

    expected == check_value
}

/
/
/
pub fn orcid_to_did(orcid: &str) -> String {
    if validate_orcid(orcid) {
        format!("did:orcid:{}", orcid)
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orcid_validation() {
        
        assert!(validate_orcid("0000-0002-1694-233X"));
        
        assert!(validate_orcid("0000-0001-5109-3700"));
        
        assert!(validate_orcid("0000-0002-1825-0097"));
        
        assert!(validate_orcid("0000000218250097"));
        
        assert!(!validate_orcid("0000-0002-1825"));
        
        assert!(!validate_orcid("AAAA-0002-1825-0097"));
        
        assert!(!validate_orcid(""));
        
        assert!(!validate_orcid("0000-0002-1825-0091"));

        
        let did = orcid_to_did("0000-0002-1694-233X");
        assert_eq!(did, "did:orcid:0000-0002-1694-233X");

        
        assert_eq!(orcid_to_did("invalid"), "");
    }

    #[test]
    fn test_orcid_checksum_validation_iso7064() {
        
        
        assert!(validate_orcid("0000-0002-1694-233X"));
        
        assert!(validate_orcid("0000-0002-1825-0097"));
        
        assert!(validate_orcid("0000-0001-5109-3700"));

        
        assert!(!validate_orcid("0000-0002-1694-2339")); 
        assert!(!validate_orcid("0000-0002-1825-0098")); 
        assert!(!validate_orcid("0000-0001-5109-3701")); 

        
        assert!(!validate_orcid("0000-0002-1694-233x"));

        
        assert!(!validate_orcid("0000-0002-1825-00977"));

        
        assert!(!validate_orcid("0000-000A-1825-0097"));
    }

    #[test]
    fn test_orcid_to_did_format() {
        let did = orcid_to_did("0000-0002-1825-0097");
        assert!(did.starts_with("did:orcid:"));
        assert_eq!(did, "did:orcid:0000-0002-1825-0097");

        
        let did_x = orcid_to_did("0000-0002-1694-233X");
        assert!(did_x.ends_with("233X"));

        
        let did_no_hyphens = orcid_to_did("0000000218250097");
        assert_eq!(did_no_hyphens, "did:orcid:0000000218250097");

        
        let bad = orcid_to_did("not-an-orcid");
        assert!(bad.is_empty());
    }
}
