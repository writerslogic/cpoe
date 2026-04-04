

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
        
        
        
        
        
        use libc::{c_int, sysctl, CTL_KERN, KERN_PROC, KERN_PROC_PID};

        const KINFO_PROC_SIZE: usize = 648;
        
        const P_FLAG_OFFSET: usize = 32;
        const P_TRACED: i32 = 0x00000800;

        unsafe {
            let pid = libc::getpid();
            let mut mib: [c_int; 4] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid];
            let mut buf = [0u8; KINFO_PROC_SIZE];
            let mut size = KINFO_PROC_SIZE;
            let ret = sysctl(
                mib.as_mut_ptr(),
                4,
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut size,
                std::ptr::null_mut(),
                0,
            );
            if ret != 0 || size < P_FLAG_OFFSET + 4 {
                return false;
            }
            let p_flag = i32::from_ne_bytes([
                buf[P_FLAG_OFFSET],
                buf[P_FLAG_OFFSET + 1],
                buf[P_FLAG_OFFSET + 2],
                buf[P_FLAG_OFFSET + 3],
            ]);
            (p_flag & P_TRACED) != 0
        }
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
