

//! End-to-end and edge case tests for cpop-jitter.

use cpop_jitter::{
    derive_session_secret, Evidence, EvidenceChain, HumanModel, HybridEngine, Jitter, Session,
};





#[test]
fn test_full_session_lifecycle() {
    
    let secret = [42u8; 32];
    let mut session = Session::new(&secret);

    
    let mut inputs: Vec<Vec<u8>> = Vec::new();
    for i in 0..30 {
        let input = format!("keystroke event {}", i);
        inputs.push(input.as_bytes().to_vec());
        let jitter = session.sample(input.as_bytes()).unwrap();
        assert!(jitter >= 500, "jitter {} below minimum", jitter);
        assert!(jitter < 5000, "jitter {} above maximum", jitter);
    }

    
    let chain = session.evidence();
    assert_eq!(chain.records.len(), 30);
    assert!(chain.validate_sequences());
    assert!(chain.validate_timestamps());

    
    assert!(chain.verify_integrity(&secret));

    
    let validation = session.validate();
    assert!(validation.stats.count == 30);
    assert!(validation.stats.mean > 0.0);

    
    let json = session.export_json().unwrap();
    let reimported: EvidenceChain = serde_json::from_str(&json).unwrap();
    assert_eq!(reimported.records.len(), 30);
    assert!(reimported.verify_integrity(&secret));
}





#[test]
fn test_session_with_hardware_fallback() {
    
    let engine = HybridEngine::default().with_min_entropy(255);
    let secret = [7u8; 32];
    let mut session = Session::with_engine(&secret, engine);

    for i in 0..25 {
        let input = format!("fallback keystroke {}", i);
        session.sample(input.as_bytes()).unwrap();
    }

    
    let chain = session.evidence();
    assert_eq!(chain.records.len(), 25);
    for record in &chain.records {
        assert!(
            !record.is_phys(),
            "Record should be pure (fallback), not phys"
        );
    }
    assert_eq!(chain.phys_count(), 0);
    assert_eq!(chain.pure_count(), 25);
    assert_eq!(chain.phys_ratio(), 0.0);

    
    assert!(chain.verify_integrity(&secret));
}





#[test]
fn test_evidence_chain_tamper_detection() {
    let secret = [99u8; 32];
    let mut chain = EvidenceChain::with_secret(&secret);

    
    for i in 0..10 {
        let evidence = Evidence::pure_with_timestamp(1000 + i * 100, (i as u64 + 1) * 1000);
        chain.append(evidence).unwrap();
    }
    assert!(chain.verify_integrity(&secret));

    
    if let Evidence::Pure { jitter, .. } = &mut chain.records[5] {
        *jitter = 99999;
    }
    assert!(
        !chain.verify_integrity(&secret),
        "Tampered chain should fail integrity check"
    );

    
    let mut chain2 = EvidenceChain::with_secret(&secret);
    for i in 0..5 {
        chain2
            .append(Evidence::pure_with_timestamp(
                1000 + i * 100,
                (i as u64 + 1) * 1000,
            ))
            .unwrap();
    }
    assert!(chain2.verify_integrity(&secret));
    chain2.records.swap(1, 3);
    assert!(
        !chain2.verify_integrity(&secret),
        "Swapped records should fail integrity"
    );
    assert!(
        !chain2.validate_sequences(),
        "Swapped records should fail sequence validation"
    );
}





#[test]
fn test_human_model_realistic_typing() {
    let model = HumanModel::default();

    
    
    
    let human_jitters: Vec<Jitter> = (0..50)
        .map(|i| {
            let base = 1200u32;
            let variance = ((i * 37 + 13) % 1800) as u32;
            (base + variance).clamp(500, 3000)
        })
        .collect();

    let result = model.validate(&human_jitters);
    assert!(
        result.is_human,
        "Realistic typing should be classified as human; anomalies: {:?}",
        result.anomalies
    );
    assert!(result.confidence > 0.5);
    assert_eq!(result.stats.count, 50);
}





#[test]
fn test_human_model_bot_detection() {
    let model = HumanModel::default();

    
    let bot_jitters: Vec<Jitter> = vec![1000; 50];
    let result = model.validate(&bot_jitters);
    assert!(
        !result.is_human,
        "Constant-interval data should be detected as non-human"
    );
    assert!(result
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, cpop_jitter::AnomalyKind::LowVariance)));

    
    let pattern_jitters: Vec<Jitter> = (0..50).map(|i| [800, 1200][i % 2]).collect();
    let result2 = model.validate(&pattern_jitters);
    assert!(
        !result2.is_human,
        "Repeating pattern should be detected as non-human"
    );
    assert!(result2
        .anomalies
        .iter()
        .any(|a| matches!(a.kind, cpop_jitter::AnomalyKind::RepeatingPattern)));
}





#[test]
fn test_session_key_derivation_deterministic() {
    let master = [0xAA; 32];
    let context = b"session-2026-03-25-doc-abc";

    let key1 = derive_session_secret(&master, context, None);
    let key2 = derive_session_secret(&master, context, None);

    assert_eq!(*key1, *key2, "Same inputs must produce same session key");
    assert_ne!(*key1, [0u8; 32], "Derived key should not be all zeros");
}





#[test]
fn test_session_different_context_different_key() {
    let master = [0xBB; 32];

    let key_a = derive_session_secret(&master, b"context-alpha", None);
    let key_b = derive_session_secret(&master, b"context-beta", None);
    let key_c = derive_session_secret(&master, b"context-alpha-extended", None);

    assert_ne!(
        *key_a, *key_b,
        "Different contexts must produce different keys"
    );
    assert_ne!(*key_a, *key_c);
    assert_ne!(*key_b, *key_c);

    
    let other_master = [0xCC; 32];
    let key_d = derive_session_secret(&other_master, b"context-alpha", None);
    assert_ne!(
        *key_a, *key_d,
        "Different masters must produce different keys"
    );
}





#[test]
fn test_chain_serialization_across_versions() {
    let secret = [0xDD; 32];
    let mut chain = EvidenceChain::with_secret(&secret);

    
    chain
        .append(Evidence::phys_with_timestamp(
            [1u8; 32].into(),
            1000,
            100000,
        ))
        .unwrap();
    chain
        .append(Evidence::pure_with_timestamp(1500, 200000))
        .unwrap();
    chain
        .append(Evidence::phys_with_timestamp(
            [2u8; 32].into(),
            2000,
            300000,
        ))
        .unwrap();

    
    let json = serde_json::to_string(&chain).unwrap();

    
    assert!(json.contains("\"version\""));
    assert!(json.contains("\"records\""));
    assert!(json.contains("\"chain_mac\""));

    
    let restored: EvidenceChain = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.records.len(), 3);
    assert!(restored.records[0].is_phys());
    assert!(!restored.records[1].is_phys());
    assert!(restored.records[2].is_phys());
    assert_eq!(restored.records[0].jitter(), 1000);
    assert_eq!(restored.records[1].jitter(), 1500);
    assert_eq!(restored.records[2].jitter(), 2000);
    assert_eq!(restored.records[0].timestamp_us(), 100000);
    assert_eq!(restored.records[1].timestamp_us(), 200000);
    assert_eq!(restored.records[2].timestamp_us(), 300000);
    assert_eq!(restored.records[0].sequence(), 0);
    assert_eq!(restored.records[1].sequence(), 1);
    assert_eq!(restored.records[2].sequence(), 2);

    
    assert!(restored.verify_integrity(&secret));
    assert!(restored.validate_sequences());
    assert!(restored.validate_timestamps());

    
    assert!(!json.contains("secret"));
}
