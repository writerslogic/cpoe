// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! IOKit HID Manager keystroke capture for hardware-verified event counting.
//!
//! Registers an input value callback on all connected keyboards via IOKit HID.
//! Events arrive from the kernel HID driver and cannot be spoofed by user-space
//! event injection (CGEventPost, CGEventTapCreate). The count of HID keyDown
//! events serves as ground truth for dual-layer validation in `synthetic.rs`.

use super::ffi::*;
use core_foundation_sys::base::kCFAllocatorDefault;
use core_foundation_sys::dictionary::{CFDictionaryCreateMutable, CFDictionaryRef};
use core_foundation_sys::number::{kCFNumberSInt32Type, CFNumberCreate};
use core_foundation_sys::string::CFStringCreateWithCString;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Shared state between the HID callback and the owning thread.
struct HidCaptureContext {
    key_down_count: AtomicU64,
    key_up_count: AtomicU64,
    /// Mach timebase numerator for converting IOHIDValueGetTimeStamp to nanoseconds.
    #[allow(dead_code)]
    timebase_numer: u32,
    /// Mach timebase denominator for converting IOHIDValueGetTimeStamp to nanoseconds.
    #[allow(dead_code)]
    timebase_denom: u32,
}

/// IOKit HID Manager keystroke capture for dual-layer validation.
///
/// Runs on a dedicated thread with its own CFRunLoop, following the same
/// pattern as `EventTapRunner` in `keystroke.rs`.
pub struct HidInputCapture {
    context: Arc<HidCaptureContext>,
    running: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl HidInputCapture {
    /// Start HID capture on a background thread.
    ///
    /// Returns `None` if the HID manager could not be created or opened.
    pub fn start() -> Option<Self> {
        let mut info = MachTimebaseInfo { numer: 0, denom: 0 };
        unsafe {
            mach_timebase_info(&mut info);
        }
        if info.denom == 0 {
            log::warn!("mach_timebase_info returned zero denominator");
            return None;
        }

        let context = Arc::new(HidCaptureContext {
            key_down_count: AtomicU64::new(0),
            key_up_count: AtomicU64::new(0),
            timebase_numer: info.numer,
            timebase_denom: info.denom,
        });
        let running = Arc::new(AtomicBool::new(false));

        let ctx_clone = Arc::clone(&context);
        let running_clone = Arc::clone(&running);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let thread = std::thread::Builder::new()
            .name("cpop-hid-capture".into())
            .spawn(move || {
                let ok = unsafe { run_hid_loop(&ctx_clone, &running_clone) };
                if ok {
                    running_clone.store(true, Ordering::SeqCst);
                    let _ = ready_tx.send(true);
                    unsafe { CFRunLoopRun() };
                } else {
                    let _ = ready_tx.send(false);
                }
                running_clone.store(false, Ordering::SeqCst);
            })
            .ok()?;

        // Wait for the thread to signal readiness (or failure).
        let ok = ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap_or(false);
        if !ok {
            log::warn!("HID capture thread failed to start");
            return None;
        }

        log::info!("IOKit HID capture started for dual-layer validation");
        Some(Self {
            context,
            running,
            thread: Some(thread),
        })
    }

    /// Number of hardware keyDown events observed.
    pub fn key_down_count(&self) -> u64 {
        self.context.key_down_count.load(Ordering::Relaxed)
    }

    /// Number of hardware keyUp events observed.
    pub fn key_up_count(&self) -> u64 {
        self.context.key_up_count.load(Ordering::Relaxed)
    }

    /// Whether the HID capture thread is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Stop HID capture and join the thread.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        // The thread will exit when CFRunLoopRun returns after CFRunLoopStop.
        // We can't easily stop the CFRunLoop from another thread without storing
        // the run loop reference, so we rely on Drop of the IOHIDManager to
        // unschedule and stop it. For now, just join if the thread exited.
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for HidInputCapture {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Set up IOHIDManager, register callback, and schedule on current thread's run loop.
///
/// Returns `true` if setup succeeded and `CFRunLoopRun()` should be called.
///
/// # Safety
///
/// Must be called on the dedicated HID thread. `context` must outlive the run loop.
unsafe fn run_hid_loop(context: &Arc<HidCaptureContext>, _running: &Arc<AtomicBool>) -> bool {
    let manager = IOHIDManagerCreate(kCFAllocatorDefault, K_IO_HID_OPTIONS_TYPE_NONE);
    if manager.is_null() {
        log::error!("IOHIDManagerCreate returned null");
        return false;
    }

    // Build matching dictionary for keyboard devices (usage page 0x01, usage 0x06).
    let matching = CFDictionaryCreateMutable(
        kCFAllocatorDefault,
        2,
        &core_foundation_sys::dictionary::kCFTypeDictionaryKeyCallBacks,
        &core_foundation_sys::dictionary::kCFTypeDictionaryValueCallBacks,
    );
    if matching.is_null() {
        CFRelease(manager);
        return false;
    }

    let page_key = cfstr(K_IO_HID_DEVICE_USAGE_PAGE_KEY);
    let usage_key = cfstr(K_IO_HID_DEVICE_USAGE_KEY);
    let page_val = cfnum(K_HID_PAGE_GENERIC_DESKTOP);
    let usage_val = cfnum(K_HID_USAGE_GD_KEYBOARD);

    if page_key.is_null() || usage_key.is_null() || page_val.is_null() || usage_val.is_null() {
        CFRelease(manager);
        CFRelease(matching as *mut _);
        return false;
    }

    core_foundation_sys::dictionary::CFDictionarySetValue(
        matching,
        page_key as *const _,
        page_val as *const _,
    );
    core_foundation_sys::dictionary::CFDictionarySetValue(
        matching,
        usage_key as *const _,
        usage_val as *const _,
    );

    IOHIDManagerSetDeviceMatching(manager, matching as CFDictionaryRef);
    CFRelease(matching as *mut _);
    CFRelease(page_key as *mut _);
    CFRelease(usage_key as *mut _);
    CFRelease(page_val as *mut _);
    CFRelease(usage_val as *mut _);

    // Open the manager to begin device matching.
    let result = IOHIDManagerOpen(manager, K_IO_HID_OPTIONS_TYPE_NONE);
    if result != 0 {
        log::error!("IOHIDManagerOpen failed: {result}");
        CFRelease(manager);
        return false;
    }

    // Register the input value callback. The context pointer is an Arc that
    // lives as long as HidInputCapture, which outlives this thread.
    let ctx_ptr = Arc::as_ptr(context) as *mut std::ffi::c_void;
    IOHIDManagerRegisterInputValueCallback(manager, hid_input_callback, ctx_ptr);

    // Schedule on the current thread's run loop.
    let run_loop = CFRunLoopGetCurrent();
    IOHIDManagerScheduleWithRunLoop(manager, run_loop, kCFRunLoopCommonModes);

    true
}

/// C callback invoked by IOKit for each HID input value.
///
/// # Safety
///
/// `context` must be a valid `*const HidCaptureContext`. `value` must be
/// a valid `IOHIDValueRef`.
extern "C" fn hid_input_callback(
    context: *mut std::ffi::c_void,
    _result: i32,
    _sender: *mut std::ffi::c_void,
    value: *mut std::ffi::c_void,
) {
    if context.is_null() || value.is_null() {
        return;
    }

    unsafe {
        let element = IOHIDValueGetElement(value);
        if element.is_null() {
            return;
        }

        let usage_page = IOHIDElementGetUsagePage(element);
        let usage = IOHIDElementGetUsage(element);

        // Filter: only keyboard/keypad usage page (0x07), standard key range.
        // Usages 0x04..=0xE7 cover letters, digits, punctuation, modifiers.
        if usage_page != K_HID_PAGE_KEYBOARD_OR_KEYPAD {
            return;
        }
        if !(0x04..=0xE7).contains(&usage) {
            return;
        }

        let int_value = IOHIDValueGetIntegerValue(value);
        let ctx = &*(context as *const HidCaptureContext);

        if int_value == 1 {
            ctx.key_down_count.fetch_add(1, Ordering::Relaxed);
        } else if int_value == 0 {
            ctx.key_up_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Create a CFString from a Rust string. Caller must CFRelease.
unsafe fn cfstr(s: &str) -> *mut std::ffi::c_void {
    let c = CString::new(s).unwrap();
    CFStringCreateWithCString(
        kCFAllocatorDefault,
        c.as_ptr(),
        core_foundation_sys::string::kCFStringEncodingUTF8,
    ) as *mut _
}

/// Create a CFNumber from an i32. Caller must CFRelease.
unsafe fn cfnum(v: i32) -> *mut std::ffi::c_void {
    CFNumberCreate(
        kCFAllocatorDefault,
        kCFNumberSInt32Type,
        &v as *const _ as *const _,
    ) as *mut _
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mach_timebase_info() {
        let mut info = MachTimebaseInfo { numer: 0, denom: 0 };
        let ret = unsafe { mach_timebase_info(&mut info) };
        assert_eq!(ret, 0);
        assert!(info.numer > 0);
        assert!(info.denom > 0);
    }

    #[test]
    fn test_mach_absolute_time_monotonic() {
        let t1 = unsafe { mach_absolute_time() };
        let t2 = unsafe { mach_absolute_time() };
        assert!(t2 >= t1);
    }
}
