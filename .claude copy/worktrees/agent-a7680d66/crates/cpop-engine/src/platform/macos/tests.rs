

use super::*;

#[test]
fn test_permission_check() {
    
    
    let _ = get_permission_status();
}

#[test]
fn test_strict_mode_toggle() {
    let original = get_strict_mode();
    set_strict_mode(!original);
    assert_eq!(get_strict_mode(), !original);
    set_strict_mode(original);
    assert_eq!(get_strict_mode(), original);
}

#[test]
fn test_dual_layer_no_hid() {
    
    let validation = validate_dual_layer(100, 0);
    assert!(!validation.synthetic_detected);
    assert_eq!(validation.discrepancy, 0);
}

#[test]
fn test_dual_layer_matching_counts() {
    let validation = validate_dual_layer(100, 100);
    assert!(!validation.synthetic_detected);
    assert_eq!(validation.discrepancy, 0);
}

#[test]
fn test_dual_layer_synthetic_detected() {
    
    let validation = validate_dual_layer(150, 100);
    assert!(validation.synthetic_detected);
    assert_eq!(validation.discrepancy, 50);
}

#[test]
fn test_dual_layer_small_discrepancy_ok() {
    
    let validation = validate_dual_layer(105, 100);
    assert!(!validation.synthetic_detected);
}

#[test]
fn test_synthetic_stats_reset() {
    reset_synthetic_stats();
    let stats = get_synthetic_stats();
    assert_eq!(stats.total_events, 0);
    assert_eq!(stats.verified_hardware, 0);
}
