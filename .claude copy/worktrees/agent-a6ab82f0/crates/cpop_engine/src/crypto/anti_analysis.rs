

//! Anti-analysis and anti-debugging measures.
//!
//! Provides utilities to detect and prevent debugger attachment and
//! binary instrumentation, hardening the process against white-box adversaries.

#[cfg(target_os = "macos")]
use libc::{c_int, c_void};

#[cfg(target_os = "macos")]
const PT_DENY_ATTACH: c_int = 31;

#[cfg(target_os = "macos")]
extern "C" {
    fn ptrace(request: c_int, pid: c_int, addr: *mut c_void, data: c_int) -> c_int;
}

/
pub fn harden_process() {
    #[cfg(target_os = "macos")]
    disable_debugging_macos();
}

/
/
/
/
#[cfg(target_os = "macos")]
fn disable_debugging_macos() {
    unsafe {
        let ret = ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
        if ret != 0 {
            log::warn!(
                "PT_DENY_ATTACH failed (ret={}), debugger hardening unavailable",
                ret
            );
        }
    }
}

/
pub fn is_debugger_present() -> bool {
    #[cfg(target_os = "macos")]
    {
        
        
        
        false
    }

    #[cfg(target_os = "windows")]
    {
        extern "system" {
            fn IsDebuggerPresent() -> i32;
        }
        unsafe { IsDebuggerPresent() != 0 }
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    false
}
