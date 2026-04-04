

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
use std::sync::{Arc, Mutex};

/
struct HidCaptureContext {
    key_down_count: AtomicU64,
    key_up_count: AtomicU64,
    /
    #[allow(dead_code)]
    timebase_numer: u32,
    /
    #[allow(dead_code)]
    timebase_denom: u32,
}

/
/
struct HidThreadHandles {
    run_loop: *mut std::ffi::c_void,
    manager: *mut std::ffi::c_void,
}



unsafe impl Send for HidThreadHandles {}

/
/
/
/
pub struct HidInputCapture {
    context: Arc<HidCaptureContext>,
    running: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    handles: Arc<Mutex<Option<HidThreadHandles>>>,
}

impl HidInputCapture {
    /
    /
    /
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
        let handles: Arc<Mutex<Option<HidThreadHandles>>> = Arc::new(Mutex::new(None));

        
        
        
        let ctx_addr = Arc::into_raw(Arc::clone(&context)) as usize;

        let running_clone = Arc::clone(&running);
        let handles_clone = Arc::clone(&handles);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();

        let thread = std::thread::Builder::new()
            .name("cpop-hid-capture".into())
            .spawn(move || {
                let ctx_ptr = ctx_addr as *const HidCaptureContext;
                let result = unsafe { run_hid_loop(ctx_ptr) };
                match result {
                    Some((manager, run_loop)) => {
                        *handles_clone.lock().unwrap_or_else(|e| e.into_inner()) =
                            Some(HidThreadHandles { run_loop, manager });
                        running_clone.store(true, Ordering::SeqCst);
                        let _ = ready_tx.send(true);
                        
                        unsafe { CFRunLoopRun() };
                    }
                    None => {
                        let _ = ready_tx.send(false);
                    }
                }
                running_clone.store(false, Ordering::SeqCst);
            })
            .ok()?;

        let ok = ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap_or(false);
        if !ok {
            log::warn!("HID capture thread failed to start");
            
            unsafe { Arc::decrement_strong_count(Arc::as_ptr(&context)) };
            return None;
        }

        Some(Self {
            context,
            running,
            thread: Some(thread),
            handles,
        })
    }

    /
    pub fn key_down_count(&self) -> u64 {
        self.context.key_down_count.load(Ordering::Relaxed)
    }

    /
    pub fn key_up_count(&self) -> u64 {
        self.context.key_up_count.load(Ordering::Relaxed)
    }

    /
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /
    pub fn stop(&mut self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            
            if let Some(handle) = self.thread.take() {
                let _ = handle.join();
            }
            return;
        }

        
        let thread_handles = self
            .handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();

        if let Some(h) = thread_handles {
            unsafe {
                
                IOHIDManagerRegisterInputValueCallback(
                    h.manager,
                    hid_input_callback_noop,
                    std::ptr::null_mut(),
                );
                IOHIDManagerUnscheduleFromRunLoop(h.manager, h.run_loop, kCFRunLoopCommonModes);
                IOHIDManagerClose(h.manager, K_IO_HID_OPTIONS_TYPE_NONE);
                CFRelease(h.manager);

                
                CFRunLoopStop(h.run_loop);
            }
        }

        
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }

        
        
        
        
        
        
        
        
        unsafe {
            Arc::decrement_strong_count(Arc::as_ptr(&self.context));
        }
    }
}

impl Drop for HidInputCapture {
    fn drop(&mut self) {
        self.stop();
    }
}

/
/
extern "C" fn hid_input_callback_noop(
    _context: *mut std::ffi::c_void,
    _result: i32,
    _sender: *mut std::ffi::c_void,
    _value: *mut std::ffi::c_void,
) {
}

/
/
/
/
/
/
/
/
unsafe fn run_hid_loop(
    ctx_raw: *const HidCaptureContext,
) -> Option<(*mut std::ffi::c_void, *mut std::ffi::c_void)> {
    let manager = IOHIDManagerCreate(kCFAllocatorDefault, K_IO_HID_OPTIONS_TYPE_NONE);
    if manager.is_null() {
        log::error!("IOHIDManagerCreate returned null");
        return None;
    }

    
    let matching = CFDictionaryCreateMutable(
        kCFAllocatorDefault,
        2,
        &core_foundation_sys::dictionary::kCFTypeDictionaryKeyCallBacks,
        &core_foundation_sys::dictionary::kCFTypeDictionaryValueCallBacks,
    );
    if matching.is_null() {
        CFRelease(manager);
        return None;
    }

    let page_key = cfstr(K_IO_HID_DEVICE_USAGE_PAGE_KEY);
    let usage_key = cfstr(K_IO_HID_DEVICE_USAGE_KEY);
    let page_val = cfnum(K_HID_PAGE_GENERIC_DESKTOP);
    let usage_val = cfnum(K_HID_USAGE_GD_KEYBOARD);

    if page_key.is_null() || usage_key.is_null() || page_val.is_null() || usage_val.is_null() {
        CFRelease(manager);
        CFRelease(matching as *mut _);
        return None;
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

    let result = IOHIDManagerOpen(manager, K_IO_HID_OPTIONS_TYPE_NONE);
    if result != 0 {
        log::error!("IOHIDManagerOpen failed: {result}");
        CFRelease(manager);
        return None;
    }

    
    
    
    IOHIDManagerRegisterInputValueCallback(
        manager,
        hid_input_callback,
        ctx_raw as *mut std::ffi::c_void,
    );

    let run_loop = CFRunLoopGetCurrent();
    IOHIDManagerScheduleWithRunLoop(manager, run_loop, kCFRunLoopCommonModes);

    Some((manager, run_loop))
}

/
/
/
/
/
/
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

/
unsafe fn cfstr(s: &str) -> *mut std::ffi::c_void {
    let c = CString::new(s).unwrap();
    CFStringCreateWithCString(
        kCFAllocatorDefault,
        c.as_ptr(),
        core_foundation_sys::string::kCFStringEncodingUTF8,
    ) as *mut _
}

/
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
