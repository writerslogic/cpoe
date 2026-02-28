// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! macOS platform implementation using CGEventTap + IOKit HID.
//!
//! This module provides dual-layer keystroke verification:
//! 1. CGEventTap for key event interception with synthetic detection
//! 2. IOKit HID for direct hardware device access
//!
//! The dual-layer approach allows detection of CGEventPost injection attacks
//! by comparing keystroke counts between the two layers.

// Re-export types from types module
pub use super::{
    DualLayerValidation, EventVerificationResult, FocusInfo, HIDDeviceInfo, KeystrokeEvent,
    PermissionStatus, SyntheticStats, TransportType,
};
use super::{FocusMonitor, KeystrokeCapture};
use anyhow::{anyhow, Result};
use core_foundation::base::TCFType;
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::runloop::{kCFRunLoopCommonModes, CFRunLoop};
use core_foundation::string::CFString;
use core_foundation_sys::base::{
    kCFAllocatorDefault, CFAllocatorRef, CFIndex, CFTypeID, CFTypeRef,
};
use core_foundation_sys::dictionary::{
    kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks, CFDictionaryCreateMutable,
    CFDictionaryRef, CFDictionarySetValue,
};
use core_foundation_sys::number::{kCFNumberIntType, CFNumberCreate, CFNumberGetTypeID};
use core_foundation_sys::string::CFStringRef;
use core_graphics::event::{
    CGEvent, CGEventTap, CGEventTapLocation, CGEventTapOptions, CGEventTapPlacement, CGEventType,
};
use objc::runtime::Object;
use serde::{Deserialize, Serialize};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};

use crate::jitter::SimpleJitterSession;
use crate::DateTimeNanosExt;

// =============================================================================
// IOKit HID Framework bindings for device enumeration
// =============================================================================

#[allow(dead_code)]
#[link(name = "IOKit", kind = "framework")]
extern "C" {
    fn IOHIDManagerCreate(allocator: CFAllocatorRef, options: u32) -> *mut std::ffi::c_void;
    fn IOHIDManagerSetDeviceMatching(manager: *mut std::ffi::c_void, matching: CFDictionaryRef);
    fn IOHIDManagerCopyDevices(manager: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    fn IOHIDManagerOpen(manager: *mut std::ffi::c_void, options: u32) -> i32;
    fn IOHIDManagerClose(manager: *mut std::ffi::c_void, options: u32) -> i32;
    fn IOHIDManagerScheduleWithRunLoop(
        manager: *mut std::ffi::c_void,
        run_loop: *mut std::ffi::c_void,
        mode: CFStringRef,
    );
    fn IOHIDManagerUnscheduleFromRunLoop(
        manager: *mut std::ffi::c_void,
        run_loop: *mut std::ffi::c_void,
        mode: CFStringRef,
    );
    fn IOHIDManagerRegisterInputValueCallback(
        manager: *mut std::ffi::c_void,
        callback: extern "C" fn(
            *mut std::ffi::c_void,
            i32,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
        ),
        context: *mut std::ffi::c_void,
    );

    fn IOHIDDeviceGetProperty(device: *mut std::ffi::c_void, key: CFStringRef) -> CFTypeRef;

    fn CFSetGetCount(set: *mut std::ffi::c_void) -> CFIndex;
    fn CFSetGetValues(set: *mut std::ffi::c_void, values: *mut *const std::ffi::c_void);
    fn CFRelease(cf: *mut std::ffi::c_void);
    fn CFRetain(cf: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    fn CFGetTypeID(cf: CFTypeRef) -> CFTypeID;
    fn CFStringGetTypeID() -> CFTypeID;
    fn CFURLGetTypeID() -> CFTypeID;
    fn CFRunLoopGetCurrent() -> *mut std::ffi::c_void;
    fn CFRunLoopStop(rl: *mut std::ffi::c_void);

    fn IOHIDValueGetElement(value: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    fn IOHIDValueGetIntegerValue(value: *mut std::ffi::c_void) -> CFIndex;
    fn IOHIDElementGetUsagePage(element: *mut std::ffi::c_void) -> u32;
    fn IOHIDElementGetUsage(element: *mut std::ffi::c_void) -> u32;
}

// IOKit HID constants
const K_HID_PAGE_GENERIC_DESKTOP: i32 = 0x01;
#[allow(dead_code)]
const K_HID_PAGE_KEYBOARD_OR_KEYPAD: u32 = 0x07;
const K_HID_USAGE_GD_KEYBOARD: i32 = 0x06;
const K_IO_HID_OPTIONS_TYPE_NONE: u32 = 0;

// IOKit property keys
const K_IO_HID_DEVICE_USAGE_PAGE_KEY: &str = "DeviceUsagePage";
const K_IO_HID_DEVICE_USAGE_KEY: &str = "DeviceUsage";
const K_IO_HID_VENDOR_ID_KEY: &str = "VendorID";
const K_IO_HID_PRODUCT_ID_KEY: &str = "ProductID";
const K_IO_HID_PRODUCT_KEY: &str = "Product";
const K_IO_HID_MANUFACTURER_KEY: &str = "Manufacturer";
const K_IO_HID_SERIAL_NUMBER_KEY: &str = "SerialNumber";
const K_IO_HID_TRANSPORT_KEY: &str = "Transport";

// =============================================================================
// Accessibility API bindings for focus and document tracking
// =============================================================================

#[allow(dead_code)]
#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    fn AXIsProcessTrusted() -> bool;
    fn AXIsProcessTrustedWithOptions(options: CFDictionaryRef) -> bool;
    fn CGPreflightListenEventAccess() -> bool;
    fn CGRequestListenEventAccess() -> bool;

    fn AXUIElementCreateApplication(pid: i32) -> *mut std::ffi::c_void;
    fn AXUIElementCopyAttributeValue(
        element: *mut std::ffi::c_void,
        attribute: CFStringRef,
        value: *mut CFTypeRef,
    ) -> i32;
    fn AXUIElementCopyAttributeNames(element: *mut std::ffi::c_void, names: *mut CFTypeRef) -> i32;
}

// AXError codes
const K_AX_ERROR_SUCCESS: i32 = 0;

// AX attribute names
const K_AX_FOCUSED_WINDOW_ATTRIBUTE: &str = "AXFocusedWindow";
const K_AX_DOCUMENT_ATTRIBUTE: &str = "AXDocument";
const K_AX_TITLE_ATTRIBUTE: &str = "AXTitle";
const K_AX_DESCRIPTION_ATTRIBUTE: &str = "AXDescription";
const K_AX_FILENAME_ATTRIBUTE: &str = "AXFilename";
const K_AX_URL_ATTRIBUTE: &str = "AXURL";

// =============================================================================
// CGEvent field constants for synthetic event detection
// =============================================================================

// CGEventField constants (values from Apple's CGEventTypes.h / macOS SDK)
const K_CG_EVENT_SOURCE_STATE_ID: u32 = 45;
const K_CG_KEYBOARD_EVENT_KEYBOARD_TYPE: u32 = 10;
const K_CG_KEYBOARD_EVENT_KEYCODE: u32 = 9;
const K_CG_EVENT_SOURCE_UNIX_PROCESS_ID: u32 = 41;
#[allow(dead_code)]
const K_CG_KEYBOARD_EVENT_AUTOREPEAT: u32 = 8;

// CGEventSourceStateID values
const K_CG_EVENT_SOURCE_STATE_PRIVATE: i64 = -1;
#[allow(dead_code)]
const K_CG_EVENT_SOURCE_STATE_COMBINED_SESSION: i64 = 0;
const K_CG_EVENT_SOURCE_STATE_HID_SYSTEM: i64 = 1;

// =============================================================================
// Legacy Data structures (for backward compatibility)
// =============================================================================

/// Legacy synthetic event statistics (for backward compatibility).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyntheticEventStats {
    pub total_events: u64,
    pub verified_hardware: u64,
    pub rejected_synthetic: u64,
    pub suspicious_accepted: u64,
    pub rejected_bad_source_state: u64,
    pub rejected_bad_keyboard_type: u64,
    pub rejected_non_kernel_pid: u64,
    pub rejected_zero_timestamp: u64,
}

// =============================================================================
// Permission handling
// =============================================================================

/// Check if accessibility permissions are granted (without prompting).
pub fn check_accessibility_permissions() -> bool {
    let key = CFString::new("AXTrustedCheckOptionPrompt");
    let value = CFBoolean::false_value();
    let dict = CFDictionary::from_CFType_pairs(&[(key.as_CFType(), value.as_CFType())]);

    unsafe { AXIsProcessTrustedWithOptions(dict.as_concrete_TypeRef()) }
}

/// Request accessibility permissions (will prompt user if not granted).
pub fn request_accessibility_permissions() -> bool {
    let key = CFString::new("AXTrustedCheckOptionPrompt");
    let value = CFBoolean::true_value();
    let dict = CFDictionary::from_CFType_pairs(&[(key.as_CFType(), value.as_CFType())]);

    unsafe { AXIsProcessTrustedWithOptions(dict.as_concrete_TypeRef()) }
}

/// Check if Input Monitoring permissions are granted (without prompting).
pub fn check_input_monitoring_permissions() -> bool {
    unsafe { CGPreflightListenEventAccess() }
}

/// Request Input Monitoring permissions (will prompt user if not granted).
pub fn request_input_monitoring_permissions() -> bool {
    unsafe { CGRequestListenEventAccess() }
}

/// Get combined permission status.
pub fn get_permission_status() -> PermissionStatus {
    let accessibility = check_accessibility_permissions();
    let input_monitoring = check_input_monitoring_permissions();
    PermissionStatus {
        accessibility,
        input_monitoring,
        input_devices: true, // Always true on macOS
        all_granted: accessibility && input_monitoring,
    }
}

/// Request all required permissions, prompting user if needed.
pub fn request_all_permissions() -> PermissionStatus {
    let accessibility = request_accessibility_permissions();
    let input_monitoring = request_input_monitoring_permissions();
    PermissionStatus {
        accessibility,
        input_monitoring,
        input_devices: true,
        all_granted: accessibility && input_monitoring,
    }
}

/// Check if all required permissions are granted.
pub fn has_required_permissions() -> bool {
    check_accessibility_permissions() && check_input_monitoring_permissions()
}

// =============================================================================
// IOKit HID device enumeration
// =============================================================================

/// Enumerate all connected HID keyboard devices.
pub fn enumerate_hid_keyboards() -> Result<Vec<HIDDeviceInfo>> {
    unsafe {
        let manager = IOHIDManagerCreate(kCFAllocatorDefault, K_IO_HID_OPTIONS_TYPE_NONE);
        if manager.is_null() {
            return Err(anyhow!("Failed to create HID manager"));
        }

        // Create matching dictionary for keyboards
        let match_dict = CFDictionaryCreateMutable(
            kCFAllocatorDefault,
            0,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        );

        if !match_dict.is_null() {
            let usage_page_key = CFString::new(K_IO_HID_DEVICE_USAGE_PAGE_KEY);
            let usage_key = CFString::new(K_IO_HID_DEVICE_USAGE_KEY);

            let usage_page = K_HID_PAGE_GENERIC_DESKTOP;
            let usage = K_HID_USAGE_GD_KEYBOARD;

            let usage_page_num = CFNumberCreate(
                kCFAllocatorDefault,
                kCFNumberIntType,
                &usage_page as *const i32 as *const std::ffi::c_void,
            );
            let usage_num = CFNumberCreate(
                kCFAllocatorDefault,
                kCFNumberIntType,
                &usage as *const i32 as *const std::ffi::c_void,
            );

            if !usage_page_num.is_null() {
                CFDictionarySetValue(
                    match_dict,
                    usage_page_key.as_concrete_TypeRef() as *const std::ffi::c_void,
                    usage_page_num as *const std::ffi::c_void,
                );
                CFRelease(usage_page_num as *mut std::ffi::c_void);
            }
            if !usage_num.is_null() {
                CFDictionarySetValue(
                    match_dict,
                    usage_key.as_concrete_TypeRef() as *const std::ffi::c_void,
                    usage_num as *const std::ffi::c_void,
                );
                CFRelease(usage_num as *mut std::ffi::c_void);
            }
        }

        IOHIDManagerSetDeviceMatching(manager, match_dict);

        if !match_dict.is_null() {
            CFRelease(match_dict as *mut std::ffi::c_void);
        }

        // Open manager
        let result = IOHIDManagerOpen(manager, K_IO_HID_OPTIONS_TYPE_NONE);
        if result != 0 {
            CFRelease(manager);
            return Err(anyhow!("Failed to open HID manager: {}", result));
        }

        // Get devices
        let devices_set = IOHIDManagerCopyDevices(manager);
        if devices_set.is_null() {
            IOHIDManagerClose(manager, K_IO_HID_OPTIONS_TYPE_NONE);
            CFRelease(manager);
            return Ok(Vec::new());
        }

        let count = CFSetGetCount(devices_set).max(0) as usize;
        let mut devices = Vec::with_capacity(count);

        if count > 0 {
            let mut device_refs: Vec<*const std::ffi::c_void> = vec![std::ptr::null(); count];
            CFSetGetValues(devices_set, device_refs.as_mut_ptr());

            for device_ref in device_refs {
                if let Some(info) = get_hid_device_info(device_ref as *mut std::ffi::c_void) {
                    devices.push(info);
                }
            }
        }

        CFRelease(devices_set);
        IOHIDManagerClose(manager, K_IO_HID_OPTIONS_TYPE_NONE);
        CFRelease(manager);

        Ok(devices)
    }
}

/// Get device info from an IOHIDDevice reference.
unsafe fn get_hid_device_info(device: *mut std::ffi::c_void) -> Option<HIDDeviceInfo> {
    let vendor_id = get_device_int_property(device, K_IO_HID_VENDOR_ID_KEY)? as u32;
    let product_id = get_device_int_property(device, K_IO_HID_PRODUCT_ID_KEY)? as u32;

    let product_name = get_device_string_property(device, K_IO_HID_PRODUCT_KEY)
        .unwrap_or_else(|| "Unknown".to_string());
    let manufacturer = get_device_string_property(device, K_IO_HID_MANUFACTURER_KEY)
        .unwrap_or_else(|| "Unknown".to_string());
    let serial_number = get_device_string_property(device, K_IO_HID_SERIAL_NUMBER_KEY);
    let transport = get_device_string_property(device, K_IO_HID_TRANSPORT_KEY)
        .unwrap_or_else(|| "Unknown".to_string());

    Some(HIDDeviceInfo {
        vendor_id,
        product_id,
        product_name,
        manufacturer,
        serial_number,
        transport,
    })
}

unsafe fn get_device_int_property(device: *mut std::ffi::c_void, key: &str) -> Option<i64> {
    let key_cf = CFString::new(key);
    let value = IOHIDDeviceGetProperty(device, key_cf.as_concrete_TypeRef());
    if value.is_null() {
        return None;
    }

    // Verify the value is actually a CFNumber before casting
    if CFGetTypeID(value) != CFNumberGetTypeID() {
        return None;
    }

    let cf_number = CFNumber::wrap_under_get_rule(value as *mut _);
    cf_number.to_i64()
}

unsafe fn get_device_string_property(device: *mut std::ffi::c_void, key: &str) -> Option<String> {
    let key_cf = CFString::new(key);
    let value = IOHIDDeviceGetProperty(device, key_cf.as_concrete_TypeRef());
    if value.is_null() {
        return None;
    }

    // Verify the value is actually a CFString before casting
    if CFGetTypeID(value) != CFStringGetTypeID() {
        return None;
    }

    let cf_string =
        CFString::wrap_under_get_rule(value as core_foundation_sys::string::CFStringRef);
    Some(cf_string.to_string())
}

// =============================================================================
// Focus tracking with document path retrieval
// =============================================================================

unsafe fn nsstring_to_string(ns_str: *mut Object) -> String {
    if ns_str.is_null() {
        return String::new();
    }
    let char_ptr: *const std::os::raw::c_char = msg_send![ns_str, UTF8String];
    if char_ptr.is_null() {
        return String::new();
    }
    std::ffi::CStr::from_ptr(char_ptr)
        .to_string_lossy()
        .into_owned()
}

/// Get information about the currently focused application and document.
pub fn get_active_focus() -> Result<FocusInfo> {
    unsafe {
        let workspace: *mut Object = msg_send![class!(NSWorkspace), sharedWorkspace];
        let active_app: *mut Object = msg_send![workspace, frontmostApplication];
        if active_app.is_null() {
            return Err(anyhow!("No active application found"));
        }

        let name: *mut Object = msg_send![active_app, localizedName];
        let bundle_id: *mut Object = msg_send![active_app, bundleIdentifier];
        let pid: i32 = msg_send![active_app, processIdentifier];

        let app_name = nsstring_to_string(name);
        let bundle_id_str = nsstring_to_string(bundle_id);

        // Try to get document info via Accessibility API
        let (doc_path, doc_title, window_title) = get_document_info_for_pid(pid);

        Ok(FocusInfo {
            app_name,
            bundle_id: bundle_id_str,
            pid,
            doc_path,
            doc_title,
            window_title,
        })
    }
}

/// Get document information for a specific process using Accessibility API.
fn get_document_info_for_pid(pid: i32) -> (Option<String>, Option<String>, Option<String>) {
    if !check_accessibility_permissions() {
        return (None, None, None);
    }

    unsafe {
        let app_element = AXUIElementCreateApplication(pid);
        if app_element.is_null() {
            return (None, None, None);
        }

        // Get focused window
        let mut window_value: CFTypeRef = null_mut();
        let window_attr = CFString::new(K_AX_FOCUSED_WINDOW_ATTRIBUTE);
        let result = AXUIElementCopyAttributeValue(
            app_element,
            window_attr.as_concrete_TypeRef(),
            &mut window_value,
        );

        if result != K_AX_ERROR_SUCCESS || window_value.is_null() {
            CFRelease(app_element);
            return (None, None, None);
        }

        let window_element = window_value as *mut std::ffi::c_void;

        // Try to get document path
        let doc_path = get_ax_string_attribute(window_element, K_AX_DOCUMENT_ATTRIBUTE)
            .or_else(|| get_ax_url_as_path(window_element));

        // Get window title
        let window_title = get_ax_string_attribute(window_element, K_AX_TITLE_ATTRIBUTE);

        // Try to get document title (some apps expose this)
        let doc_title = get_ax_string_attribute(window_element, K_AX_DESCRIPTION_ATTRIBUTE)
            .or_else(|| get_ax_string_attribute(window_element, K_AX_FILENAME_ATTRIBUTE));

        CFRelease(window_element);
        CFRelease(app_element);

        (doc_path, doc_title, window_title)
    }
}

unsafe fn get_ax_string_attribute(
    element: *mut std::ffi::c_void,
    attribute: &str,
) -> Option<String> {
    let mut value: CFTypeRef = null_mut();
    let attr_name = CFString::new(attribute);
    let result =
        AXUIElementCopyAttributeValue(element, attr_name.as_concrete_TypeRef(), &mut value);

    if result != K_AX_ERROR_SUCCESS || value.is_null() {
        return None;
    }

    // Verify the value is actually a CFString before casting
    if CFGetTypeID(value) != CFStringGetTypeID() {
        CFRelease(value as *mut std::ffi::c_void);
        return None;
    }

    let cf_string =
        CFString::wrap_under_create_rule(value as core_foundation_sys::string::CFStringRef);
    let s = cf_string.to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

unsafe fn get_ax_url_as_path(element: *mut std::ffi::c_void) -> Option<String> {
    let mut value: CFTypeRef = null_mut();
    let attr_name = CFString::new(K_AX_URL_ATTRIBUTE);
    let result =
        AXUIElementCopyAttributeValue(element, attr_name.as_concrete_TypeRef(), &mut value);

    if result != K_AX_ERROR_SUCCESS || value.is_null() {
        return None;
    }

    // Verify the value is actually a CFURL before using it
    if CFGetTypeID(value) != CFURLGetTypeID() {
        CFRelease(value as *mut std::ffi::c_void);
        return None;
    }

    // URL is a CFURL, convert to file path if it's a file:// URL
    extern "C" {
        fn CFURLCopyFileSystemPath(
            url: CFTypeRef,
            path_style: i32,
        ) -> core_foundation_sys::string::CFStringRef;
    }

    const K_CF_URL_POSIX_PATH_STYLE: i32 = 0;

    let path_ref = CFURLCopyFileSystemPath(value, K_CF_URL_POSIX_PATH_STYLE);
    CFRelease(value as *mut std::ffi::c_void);

    if path_ref.is_null() {
        return None;
    }

    let cf_string = CFString::wrap_under_create_rule(path_ref);
    let path = cf_string.to_string();
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

// =============================================================================
// Synthetic event detection
// =============================================================================

/// Global statistics for synthetic event detection.
static SYNTHETIC_STATS: RwLock<SyntheticEventStats> = RwLock::new(SyntheticEventStats {
    total_events: 0,
    verified_hardware: 0,
    rejected_synthetic: 0,
    suspicious_accepted: 0,
    rejected_bad_source_state: 0,
    rejected_bad_keyboard_type: 0,
    rejected_non_kernel_pid: 0,
    rejected_zero_timestamp: 0,
});

/// Strictness mode for synthetic event detection.
static STRICT_MODE: AtomicBool = AtomicBool::new(true);

/// Set whether to use strict mode for synthetic event detection.
/// In strict mode, suspicious events are rejected.
/// In permissive mode, suspicious events are accepted but flagged.
pub fn set_strict_mode(strict: bool) {
    STRICT_MODE.store(strict, Ordering::SeqCst);
}

/// Get current strict mode setting.
pub fn get_strict_mode() -> bool {
    STRICT_MODE.load(Ordering::SeqCst)
}

/// Get synthetic event detection statistics.
pub fn get_synthetic_stats() -> SyntheticEventStats {
    SYNTHETIC_STATS
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
}

/// Reset synthetic event detection statistics.
pub fn reset_synthetic_stats() {
    let mut stats = SYNTHETIC_STATS.write().unwrap_or_else(|p| p.into_inner());
    *stats = SyntheticEventStats::default();
}

/// Verify if a CGEvent appears to be from hardware.
/// This detects CGEventPost injection attacks.
pub fn verify_event_source(event: &core_graphics::event::CGEvent) -> EventVerificationResult {
    let strict = STRICT_MODE.load(Ordering::SeqCst);

    // Read all FFI fields before acquiring the write lock to minimize lock contention
    let source_state_id = event.get_integer_value_field(K_CG_EVENT_SOURCE_STATE_ID);
    let keyboard_type = event.get_integer_value_field(K_CG_KEYBOARD_EVENT_KEYBOARD_TYPE);
    let source_pid = event.get_integer_value_field(K_CG_EVENT_SOURCE_UNIX_PROCESS_ID);

    // Determine result without holding the lock
    let mut suspicious = false;

    // Check 1: Event Source State ID
    // Hardware events come from kCGEventSourceStateHIDSystemState (1)
    if source_state_id == K_CG_EVENT_SOURCE_STATE_PRIVATE {
        let mut stats = SYNTHETIC_STATS.write().unwrap_or_else(|p| p.into_inner());
        stats.total_events += 1;
        stats.rejected_synthetic += 1;
        stats.rejected_bad_source_state += 1;
        return EventVerificationResult::Synthetic;
    }

    if source_state_id != K_CG_EVENT_SOURCE_STATE_HID_SYSTEM {
        suspicious = true;
    }

    // Check 2: Keyboard Type
    // Real keyboards report their type (ANSI, ISO, JIS)
    // Synthetic events often have keyboard type 0
    if keyboard_type == 0 {
        if strict {
            let mut stats = SYNTHETIC_STATS.write().unwrap_or_else(|p| p.into_inner());
            stats.total_events += 1;
            stats.rejected_synthetic += 1;
            stats.rejected_bad_keyboard_type += 1;
            return EventVerificationResult::Synthetic;
        }
        suspicious = true;
    }

    // Sanity check: keyboard type should be reasonable
    if keyboard_type > 100 {
        let mut stats = SYNTHETIC_STATS.write().unwrap_or_else(|p| p.into_inner());
        stats.total_events += 1;
        stats.rejected_synthetic += 1;
        stats.rejected_bad_keyboard_type += 1;
        return EventVerificationResult::Synthetic;
    }

    // Check 3: Source Unix Process ID
    // Hardware events from HID system have source PID of 0 (kernel)
    // CGEventPost events have the posting process's PID
    if source_pid != 0 {
        if strict {
            let mut stats = SYNTHETIC_STATS.write().unwrap_or_else(|p| p.into_inner());
            stats.total_events += 1;
            stats.rejected_synthetic += 1;
            stats.rejected_non_kernel_pid += 1;
            return EventVerificationResult::Synthetic;
        }
        suspicious = true;
    }

    // Acquire lock only for final stats update
    let mut stats = SYNTHETIC_STATS.write().unwrap_or_else(|p| p.into_inner());
    stats.total_events += 1;
    if suspicious {
        stats.suspicious_accepted += 1;
        EventVerificationResult::Suspicious
    } else {
        stats.verified_hardware += 1;
        EventVerificationResult::Hardware
    }
}

// =============================================================================
// Dual-layer HID monitoring
// =============================================================================

/// HID keystroke counter at IOKit layer.
static HID_KEYSTROKE_COUNT: AtomicU64 = AtomicU64::new(0);
static HID_MONITOR_RUNNING: AtomicBool = AtomicBool::new(false);

/// HID input callback - called for each HID keyboard event from actual hardware.
#[allow(dead_code)]
extern "C" fn hid_input_callback(
    _context: *mut std::ffi::c_void,
    _result: i32,
    _sender: *mut std::ffi::c_void,
    value: *mut std::ffi::c_void,
) {
    unsafe {
        let element = IOHIDValueGetElement(value);
        if element.is_null() {
            return;
        }
        let usage_page = IOHIDElementGetUsagePage(element);
        let usage = IOHIDElementGetUsage(element);

        // Filter to keyboard events only (usage page 0x07)
        if usage_page != K_HID_PAGE_KEYBOARD_OR_KEYPAD {
            return;
        }

        // Filter to actual key codes (4-231 are standard keys)
        if !(4..=231).contains(&usage) {
            return;
        }

        // Only count key-down events (value = 1)
        let int_value = IOHIDValueGetIntegerValue(value);
        if int_value != 1 {
            return;
        }

        // This is a genuine hardware keystroke
        HID_KEYSTROKE_COUNT.fetch_add(1, Ordering::SeqCst);
    }
}

/// Get the current HID-layer keystroke count.
pub fn get_hid_keystroke_count() -> u64 {
    HID_KEYSTROKE_COUNT.load(Ordering::SeqCst)
}

/// Reset the HID-layer keystroke count.
pub fn reset_hid_keystroke_count() {
    HID_KEYSTROKE_COUNT.store(0, Ordering::SeqCst);
}

/// Check if HID monitoring is running.
pub fn is_hid_monitoring_running() -> bool {
    HID_MONITOR_RUNNING.load(Ordering::SeqCst)
}

/// Validate keystroke counts between CGEventTap and IOKit HID layers.
/// If CGEventTap count significantly exceeds HID count, synthetic events were injected.
pub fn validate_dual_layer(cg_count: u64) -> DualLayerValidation {
    let hid_count = get_hid_keystroke_count();
    let cg_i64 = i64::try_from(cg_count).unwrap_or(i64::MAX);
    let hid_i64 = i64::try_from(hid_count).unwrap_or(i64::MAX);
    let discrepancy = cg_i64.saturating_sub(hid_i64);

    // Allow small discrepancy due to timing differences
    // But if CG count is significantly higher, synthetic events detected
    let synthetic_detected =
        discrepancy > 5 && (discrepancy as f64 / hid_count.max(1) as f64) > 0.1;

    DualLayerValidation {
        high_level_count: cg_count,
        low_level_count: hid_count,
        synthetic_detected,
        discrepancy,
    }
}

// =============================================================================
// Enhanced keystroke monitor
// =============================================================================

/// Extended keystroke information including device fingerprint.
#[derive(Debug, Clone)]
pub struct KeystrokeInfo {
    pub timestamp_ns: i64,
    pub keycode: i64,
    pub zone: u8,
    pub verification: EventVerificationResult,
    pub device_hint: Option<HIDDeviceInfo>,
}

/// Callback type for enhanced keystroke monitoring.
pub type KeystrokeCallback = Arc<dyn Fn(KeystrokeInfo) + Send + Sync>;

/// Enhanced keystroke monitor with synthetic event detection.
pub struct KeystrokeMonitor {
    thread: Option<std::thread::JoinHandle<()>>,
    keystroke_count: Arc<AtomicU64>,
    verified_count: Arc<AtomicU64>,
    rejected_count: Arc<AtomicU64>,
    run_loop: Arc<Mutex<Option<RunLoopHandle>>>,
}

impl KeystrokeMonitor {
    /// Start the keystroke monitor with a simple jitter session.
    pub fn start(session: Arc<Mutex<SimpleJitterSession>>) -> Result<Self> {
        Self::start_with_callback(session, None)
    }

    /// Start the keystroke monitor with optional callback for extended info.
    pub fn start_with_callback(
        session: Arc<Mutex<SimpleJitterSession>>,
        callback: Option<KeystrokeCallback>,
    ) -> Result<Self> {
        let session_clone = Arc::clone(&session);
        Self::start_event_tap(
            move |event: &CGEvent, verification: EventVerificationResult| {
                let now = chrono::Utc::now().timestamp_nanos_safe();
                let keycode = event.get_integer_value_field(K_CG_KEYBOARD_EVENT_KEYCODE);
                let zone_i = crate::jitter::keycode_to_zone(keycode as u16);
                let zone = if zone_i >= 0 { zone_i as u8 } else { 0xFF };

                if let Ok(mut s) = session_clone.lock() {
                    s.add_sample(now, zone);
                }

                if let Some(ref cb) = callback {
                    cb(KeystrokeInfo {
                        timestamp_ns: now,
                        keycode,
                        zone,
                        verification,
                        device_hint: None,
                    });
                }
            },
        )
    }

    /// Get total keystroke count (verified events only).
    pub fn keystroke_count(&self) -> u64 {
        self.keystroke_count.load(Ordering::SeqCst)
    }

    /// Get count of verified hardware events.
    pub fn verified_count(&self) -> u64 {
        self.verified_count.load(Ordering::SeqCst)
    }

    /// Get count of rejected synthetic events.
    pub fn rejected_count(&self) -> u64 {
        self.rejected_count.load(Ordering::SeqCst)
    }

    /// Check if synthetic injection has been detected.
    pub fn synthetic_injection_detected(&self) -> bool {
        self.rejected_count.load(Ordering::SeqCst) > 0
    }

    /// Start the keystroke monitor with a hybrid jitter session (witnessd_jitter-backed).
    ///
    /// This variant uses witnessd_jitter's hardware entropy when available,
    /// with automatic fallback to HMAC-based jitter.
    #[cfg(feature = "witnessd_jitter")]
    pub fn start_with_hybrid(
        session: Arc<Mutex<crate::witnessd_jitter_bridge::HybridJitterSession>>,
    ) -> Result<Self> {
        Self::start_with_hybrid_callback(session, None)
    }

    /// Start the keystroke monitor with a hybrid jitter session and optional callback.
    #[cfg(feature = "witnessd_jitter")]
    pub fn start_with_hybrid_callback(
        session: Arc<Mutex<crate::witnessd_jitter_bridge::HybridJitterSession>>,
        callback: Option<KeystrokeCallback>,
    ) -> Result<Self> {
        let session_clone = Arc::clone(&session);
        Self::start_event_tap(
            move |event: &CGEvent, verification: EventVerificationResult| {
                let keycode = event.get_integer_value_field(K_CG_KEYBOARD_EVENT_KEYCODE) as u16;
                let zone = crate::jitter::keycode_to_zone(keycode);

                // Record keystroke in hybrid session
                if let Ok(mut s) = session_clone.lock() {
                    let _ = s.record_keystroke(keycode);
                }

                if let Some(ref cb) = callback {
                    let now = chrono::Utc::now().timestamp_nanos_safe();
                    cb(KeystrokeInfo {
                        timestamp_ns: now,
                        keycode: keycode as i64,
                        zone: if zone >= 0 { zone as u8 } else { 0xFF },
                        verification,
                        device_hint: None,
                    });
                }
            },
        )
    }

    /// Shared CGEventTap setup for all keystroke monitor variants.
    ///
    /// Handles event tap creation, source verification, run loop lifecycle,
    /// and counter management. The `on_keystroke` closure is called for each
    /// verified (non-synthetic) KeyDown event.
    fn start_event_tap<F>(on_keystroke: F) -> Result<Self>
    where
        F: FnMut(&CGEvent, EventVerificationResult) + Send + 'static,
    {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let keystroke_count = Arc::new(AtomicU64::new(0));
        let verified_count = Arc::new(AtomicU64::new(0));
        let rejected_count = Arc::new(AtomicU64::new(0));

        let ks_count = Arc::clone(&keystroke_count);
        let ver_count = Arc::clone(&verified_count);
        let rej_count = Arc::clone(&rejected_count);

        let run_loop: Arc<Mutex<Option<RunLoopHandle>>> = Arc::new(Mutex::new(None));
        let run_loop_clone = Arc::clone(&run_loop);

        // Wrap in Mutex so the FnMut closure can be called from FnOnce context
        let on_keystroke = Mutex::new(on_keystroke);

        let thread = std::thread::spawn(move || {
            let events = vec![CGEventType::KeyDown];
            let tap = CGEventTap::new(
                CGEventTapLocation::HID,
                CGEventTapPlacement::HeadInsertEventTap,
                CGEventTapOptions::ListenOnly,
                events,
                move |_proxy, event_type, event| {
                    if matches!(event_type, CGEventType::KeyDown) {
                        let verification = verify_event_source(event);

                        match verification {
                            EventVerificationResult::Synthetic => {
                                rej_count.fetch_add(1, Ordering::SeqCst);
                                return Some(event.to_owned());
                            }
                            EventVerificationResult::Hardware
                            | EventVerificationResult::Suspicious => {
                                ver_count.fetch_add(1, Ordering::SeqCst);
                            }
                        }

                        ks_count.fetch_add(1, Ordering::SeqCst);

                        if let Ok(mut handler) = on_keystroke.lock() {
                            handler(event, verification);
                        }
                    }
                    Some(event.to_owned())
                },
            );

            let tap = match tap {
                Ok(tap) => tap,
                Err(_) => {
                    let _ = ready_tx.send(Err(anyhow!("Failed to create CGEventTap")));
                    return;
                }
            };

            let loop_source = match tap.mach_port.create_runloop_source(0) {
                Ok(source) => source,
                Err(_) => {
                    let _ = ready_tx.send(Err(anyhow!("Failed to create runloop source")));
                    return;
                }
            };

            let _ = ready_tx.send(Ok(()));
            let current_loop = CFRunLoop::get_current();
            unsafe {
                let rl_ref = CFRunLoopGetCurrent();
                CFRetain(rl_ref);
                if let Ok(mut rl) = run_loop_clone.lock() {
                    *rl = Some(RunLoopHandle(rl_ref));
                }
                current_loop.add_source(&loop_source, kCFRunLoopCommonModes);
            }
            tap.enable();
            CFRunLoop::run_current();
        });

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                thread: Some(thread),
                keystroke_count,
                verified_count,
                rejected_count,
                run_loop,
            }),
            Ok(Err(err)) => Err(err),
            Err(_) => Err(anyhow!("Failed to initialize CGEventTap thread")),
        }
    }

    /// Stop the keystroke monitor, terminating its run loop and joining the thread.
    pub fn stop(&mut self) {
        if let Ok(mut rl) = self.run_loop.lock() {
            if let Some(handle) = rl.take() {
                unsafe {
                    CFRunLoopStop(handle.0);
                    CFRelease(handle.0);
                }
            }
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for KeystrokeMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

// =============================================================================
// Trait implementations
// =============================================================================

/// Thread-safe handle to a CFRunLoop that can be stopped from another thread.
/// SAFETY: CFRunLoopStop is documented as thread-safe in Apple's documentation.
struct RunLoopHandle(*mut std::ffi::c_void);
unsafe impl Send for RunLoopHandle {}
unsafe impl Sync for RunLoopHandle {}

/// macOS keystroke capture implementation.
pub struct MacOSKeystrokeCapture {
    running: Arc<AtomicBool>,
    sender: Option<mpsc::Sender<KeystrokeEvent>>,
    thread: Option<std::thread::JoinHandle<()>>,
    strict_mode: bool,
    stats: Arc<RwLock<SyntheticStats>>,
    run_loop: Arc<Mutex<Option<RunLoopHandle>>>,
}

impl MacOSKeystrokeCapture {
    /// Create a new macOS keystroke capture instance.
    pub fn new() -> Result<Self> {
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
            sender: None,
            thread: None,
            strict_mode: true,
            stats: Arc::new(RwLock::new(SyntheticStats::default())),
            run_loop: Arc::new(Mutex::new(None)),
        })
    }
}

impl KeystrokeCapture for MacOSKeystrokeCapture {
    fn start(&mut self) -> Result<mpsc::Receiver<KeystrokeEvent>> {
        if self.running.load(Ordering::SeqCst) {
            return Err(anyhow!("Keystroke capture already running"));
        }

        let (tx, rx) = mpsc::channel();
        self.sender = Some(tx.clone());

        let running = Arc::clone(&self.running);
        let stats = Arc::clone(&self.stats);
        let strict = self.strict_mode;
        let run_loop = Arc::clone(&self.run_loop);

        running.store(true, Ordering::SeqCst);

        let (ready_tx, ready_rx) = mpsc::channel();

        let thread = std::thread::spawn(move || {
            let events = vec![CGEventType::KeyDown];
            let tap = CGEventTap::new(
                CGEventTapLocation::HID,
                CGEventTapPlacement::HeadInsertEventTap,
                CGEventTapOptions::ListenOnly,
                events,
                move |_proxy, event_type, event| {
                    if !running.load(Ordering::SeqCst) {
                        return Some(event.to_owned());
                    }

                    if matches!(event_type, CGEventType::KeyDown) {
                        let verification = verify_event_source(event);

                        let is_hardware = match verification {
                            EventVerificationResult::Hardware => true,
                            EventVerificationResult::Suspicious => !strict,
                            EventVerificationResult::Synthetic => false,
                        };

                        // Update stats
                        if let Ok(mut s) = stats.write() {
                            s.total_events += 1;
                            if is_hardware {
                                s.verified_hardware += 1;
                            } else {
                                s.rejected_synthetic += 1;
                            }
                        }

                        if is_hardware {
                            let now = chrono::Utc::now().timestamp_nanos_safe();
                            let keycode =
                                event.get_integer_value_field(K_CG_KEYBOARD_EVENT_KEYCODE) as u16;
                            let zone = crate::jitter::keycode_to_zone(keycode);

                            let keystroke = KeystrokeEvent {
                                timestamp_ns: now,
                                keycode,
                                zone: if zone >= 0 { zone as u8 } else { 0xFF },
                                char_value: None,
                                is_hardware: true,
                                device_id: None,
                                transport_type: None, // Populated at evidence export via HID enumeration
                            };

                            let _ = tx.send(keystroke);
                        }
                    }
                    Some(event.to_owned())
                },
            );

            let tap = match tap {
                Ok(tap) => tap,
                Err(_) => {
                    let _ = ready_tx.send(Err(anyhow!("Failed to create CGEventTap")));
                    return;
                }
            };

            let loop_source = match tap.mach_port.create_runloop_source(0) {
                Ok(source) => source,
                Err(_) => {
                    let _ = ready_tx.send(Err(anyhow!("Failed to create runloop source")));
                    return;
                }
            };

            let _ = ready_tx.send(Ok(()));
            let current_loop = CFRunLoop::get_current();
            unsafe {
                // Store the run loop ref so stop() can terminate it from another thread
                let rl_ref = CFRunLoopGetCurrent();
                CFRetain(rl_ref);
                if let Ok(mut rl) = run_loop.lock() {
                    *rl = Some(RunLoopHandle(rl_ref));
                }
                current_loop.add_source(&loop_source, kCFRunLoopCommonModes);
            }
            tap.enable();
            CFRunLoop::run_current();
        });

        match ready_rx.recv() {
            Ok(Ok(())) => {
                self.thread = Some(thread);
                Ok(rx)
            }
            Ok(Err(err)) => {
                self.running.store(false, Ordering::SeqCst);
                self.sender = None;
                Err(err)
            }
            Err(_) => {
                self.running.store(false, Ordering::SeqCst);
                self.sender = None;
                Err(anyhow!("Failed to initialize CGEventTap thread"))
            }
        }
    }

    fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        self.sender = None;
        // Stop the CFRunLoop so the thread can exit
        if let Ok(mut rl) = self.run_loop.lock() {
            if let Some(handle) = rl.take() {
                unsafe {
                    CFRunLoopStop(handle.0);
                    CFRelease(handle.0);
                }
            }
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        Ok(())
    }

    fn synthetic_stats(&self) -> SyntheticStats {
        self.stats.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn set_strict_mode(&mut self, strict: bool) {
        self.strict_mode = strict;
    }

    fn get_strict_mode(&self) -> bool {
        self.strict_mode
    }
}

/// macOS focus monitor implementation.
pub struct MacOSFocusMonitor {
    running: Arc<AtomicBool>,
    sender: Option<mpsc::Sender<FocusInfo>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl MacOSFocusMonitor {
    /// Create a new macOS focus monitor instance.
    pub fn new() -> Result<Self> {
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
            sender: None,
            thread: None,
        })
    }
}

impl FocusMonitor for MacOSFocusMonitor {
    fn get_active_focus(&self) -> Result<FocusInfo> {
        get_active_focus()
    }

    fn start_monitoring(&mut self) -> Result<mpsc::Receiver<FocusInfo>> {
        if self.running.load(Ordering::SeqCst) {
            return Err(anyhow!("Focus monitoring already running"));
        }

        let (tx, rx) = mpsc::channel();
        self.sender = Some(tx.clone());

        let running = Arc::clone(&self.running);
        running.store(true, Ordering::SeqCst);

        let thread = std::thread::spawn(move || {
            let mut last_focus: Option<FocusInfo> = None;

            while running.load(Ordering::SeqCst) {
                // Wrap each iteration in an autorelease pool to prevent
                // memory leaks from Objective-C calls in get_active_focus()
                objc::rc::autoreleasepool(|| {
                    if let Ok(focus) = get_active_focus() {
                        let should_send = match &last_focus {
                            Some(last) => {
                                last.pid != focus.pid
                                    || last.doc_path != focus.doc_path
                                    || last.window_title != focus.window_title
                            }
                            None => true,
                        };

                        if should_send {
                            let _ = tx.send(focus.clone());
                            last_focus = Some(focus);
                        }
                    }
                });

                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });

        self.thread = Some(thread);
        Ok(rx)
    }

    fn stop_monitoring(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        self.sender = None;
        // Join the polling thread (exits within ~100ms when running is false)
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        Ok(())
    }

    fn is_monitoring(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

// =============================================================================
// Mouse Capture Implementation
// =============================================================================

use super::MouseCapture;
use super::{MouseEvent, MouseIdleStats, MouseStegoParams};

/// macOS mouse capture implementation using CGEventTap.
pub struct MacOSMouseCapture {
    running: Arc<AtomicBool>,
    sender: Option<mpsc::Sender<MouseEvent>>,
    thread: Option<std::thread::JoinHandle<()>>,
    idle_stats: Arc<RwLock<MouseIdleStats>>,
    stego_params: MouseStegoParams,
    idle_only_mode: bool,
    last_position: Arc<RwLock<(f64, f64)>>,
    keyboard_active: Arc<AtomicBool>,
    last_keystroke_time: Arc<RwLock<std::time::Instant>>,
    run_loop: Arc<Mutex<Option<RunLoopHandle>>>,
}

impl MacOSMouseCapture {
    /// Create a new macOS mouse capture instance.
    pub fn new() -> Result<Self> {
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
            sender: None,
            thread: None,
            idle_stats: Arc::new(RwLock::new(MouseIdleStats::new())),
            stego_params: MouseStegoParams::default(),
            idle_only_mode: true, // Default to idle-only for fingerprinting
            last_position: Arc::new(RwLock::new((0.0, 0.0))),
            keyboard_active: Arc::new(AtomicBool::new(false)),
            last_keystroke_time: Arc::new(RwLock::new(std::time::Instant::now())),
            run_loop: Arc::new(Mutex::new(None)),
        })
    }

    /// Notify the mouse capture that a keystroke occurred.
    ///
    /// This is used to detect idle periods for mouse jitter capture.
    pub fn notify_keystroke(&self) {
        self.keyboard_active.store(true, Ordering::SeqCst);
        if let Ok(mut time) = self.last_keystroke_time.write() {
            *time = std::time::Instant::now();
        }
    }
}

impl MouseCapture for MacOSMouseCapture {
    fn start(&mut self) -> Result<mpsc::Receiver<MouseEvent>> {
        if self.running.load(Ordering::SeqCst) {
            return Err(anyhow!("Mouse capture already running"));
        }

        let (tx, rx) = mpsc::channel();
        self.sender = Some(tx.clone());

        let running = Arc::clone(&self.running);
        let idle_stats = Arc::clone(&self.idle_stats);
        let last_position = Arc::clone(&self.last_position);
        let keyboard_active = Arc::clone(&self.keyboard_active);
        let last_keystroke_time = Arc::clone(&self.last_keystroke_time);
        let idle_only_mode = self.idle_only_mode;
        let run_loop = Arc::clone(&self.run_loop);

        running.store(true, Ordering::SeqCst);

        let (ready_tx, ready_rx) = mpsc::channel::<Result<()>>();

        let thread = std::thread::spawn(move || {
            // Capture mouse moved events
            let events = vec![CGEventType::MouseMoved];

            let tap = CGEventTap::new(
                CGEventTapLocation::HID,
                CGEventTapPlacement::HeadInsertEventTap,
                CGEventTapOptions::ListenOnly, // Listen only, don't modify
                events,
                move |_proxy, event_type, event| {
                    if !running.load(Ordering::SeqCst) {
                        return Some(event.to_owned());
                    }

                    if matches!(event_type, CGEventType::MouseMoved) {
                        // Check if we should capture (idle-only mode consideration)
                        let should_capture = if idle_only_mode {
                            // Only capture if keyboard was active recently (within 2 seconds)
                            if let Ok(time) = last_keystroke_time.read() {
                                time.elapsed() < std::time::Duration::from_secs(2)
                            } else {
                                false
                            }
                        } else {
                            true
                        };

                        if !should_capture {
                            return Some(event.to_owned());
                        }

                        let now = chrono::Utc::now().timestamp_nanos_safe();

                        // Get mouse position from event
                        // CGEvent location is in screen coordinates
                        let location = event.location();
                        let x = location.x;
                        let y = location.y;

                        // Calculate delta from last position
                        let (dx, dy) = if let Ok(mut last_pos) = last_position.write() {
                            let delta = (x - last_pos.0, y - last_pos.1);
                            *last_pos = (x, y);
                            delta
                        } else {
                            (0.0, 0.0)
                        };

                        // Create mouse event
                        let is_idle = keyboard_active.load(Ordering::SeqCst);
                        let mouse_event = if is_idle {
                            MouseEvent::idle_jitter(now, x, y, dx, dy)
                        } else {
                            MouseEvent::new(now, x, y, dx, dy)
                        };

                        // Record idle statistics for micro-movements
                        if mouse_event.is_micro_movement() && is_idle {
                            if let Ok(mut stats) = idle_stats.write() {
                                stats.record(&mouse_event);
                            }
                        }

                        // Send event
                        let _ = tx.send(mouse_event);

                        // Reset keyboard active flag after processing
                        // (will be set again by next keystroke)
                        if !idle_only_mode {
                            keyboard_active.store(false, Ordering::SeqCst);
                        }
                    }

                    Some(event.to_owned())
                },
            );

            let tap = match tap {
                Ok(tap) => tap,
                Err(_) => {
                    let _ = ready_tx.send(Err(anyhow!("Failed to create CGEventTap")));
                    return;
                }
            };

            let loop_source = match tap.mach_port.create_runloop_source(0) {
                Ok(source) => source,
                Err(_) => {
                    let _ = ready_tx.send(Err(anyhow!("Failed to create runloop source")));
                    return;
                }
            };

            let _ = ready_tx.send(Ok(()));
            let current_loop = CFRunLoop::get_current();
            unsafe {
                // Store the run loop ref so stop() can terminate it
                let rl_ref = CFRunLoopGetCurrent();
                CFRetain(rl_ref);
                if let Ok(mut rl) = run_loop.lock() {
                    *rl = Some(RunLoopHandle(rl_ref));
                }
                current_loop.add_source(&loop_source, kCFRunLoopCommonModes);
            }
            tap.enable();
            CFRunLoop::run_current();
        });

        match ready_rx.recv() {
            Ok(Ok(())) => {
                self.thread = Some(thread);
                Ok(rx)
            }
            Ok(Err(err)) => {
                self.running.store(false, Ordering::SeqCst);
                self.sender = None;
                Err(err)
            }
            Err(_) => {
                self.running.store(false, Ordering::SeqCst);
                self.sender = None;
                Err(anyhow!("Failed to initialize mouse CGEventTap thread"))
            }
        }
    }

    fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        self.sender = None;
        // Stop the CFRunLoop so the thread can exit
        if let Ok(mut rl) = self.run_loop.lock() {
            if let Some(handle) = rl.take() {
                unsafe {
                    CFRunLoopStop(handle.0);
                    CFRelease(handle.0);
                }
            }
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn idle_stats(&self) -> MouseIdleStats {
        self.idle_stats
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn reset_idle_stats(&mut self) {
        if let Ok(mut stats) = self.idle_stats.write() {
            *stats = MouseIdleStats::new();
        }
    }

    fn set_stego_params(&mut self, params: MouseStegoParams) {
        self.stego_params = params;
    }

    fn get_stego_params(&self) -> MouseStegoParams {
        self.stego_params.clone()
    }

    fn set_idle_only_mode(&mut self, enabled: bool) {
        self.idle_only_mode = enabled;
    }

    fn is_idle_only_mode(&self) -> bool {
        self.idle_only_mode
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_check() {
        // This will return false in CI environments without permissions
        // Just verify it doesn't panic
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
    fn test_dual_layer_validation() {
        reset_hid_keystroke_count();
        let validation = validate_dual_layer(0);
        assert!(!validation.synthetic_detected);
        assert_eq!(validation.discrepancy, 0);
    }

    #[test]
    fn test_synthetic_stats_reset() {
        reset_synthetic_stats();
        let stats = get_synthetic_stats();
        assert_eq!(stats.total_events, 0);
        assert_eq!(stats.verified_hardware, 0);
    }
}
