

//! Memory-hardened wrappers for key material: zeroize-on-drop with
//! optional `mlock` to prevent swap exposure.

use std::ops::Deref;
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
use libc::{mlock, munlock};

/
/
/
/
pub struct ProtectedKey<const N: usize>([u8; N]);

impl<const N: usize> Clone for ProtectedKey<N> {
    fn clone(&self) -> Self {
        
        ProtectedKey::new(self.0)
    }
}

impl<const N: usize> ProtectedKey<N> {
    /
    /
    /
    /
    /
    /
    pub fn new(bytes: [u8; N]) -> Self {
        
        
        let zeroizing = Zeroizing::new(bytes);
        let mut key = Self(*zeroizing);
        key.lock_memory();
        
        key
    }

    /
    /
    pub fn from_zeroizing(bytes: Zeroizing<[u8; N]>) -> Self {
        let mut key = Self(*bytes);
        key.lock_memory();
        
        key
    }

    /
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    fn lock_memory(&mut self) {
        #[cfg(unix)]
        unsafe {
            if mlock(self.0.as_ptr() as *const libc::c_void, N) != 0 {
                log::warn!("mlock failed: {}", std::io::Error::last_os_error());
            }
        }
    }

    fn unlock_memory(&mut self) {
        #[cfg(unix)]
        unsafe {
            let _ = munlock(self.0.as_ptr() as *const libc::c_void, N);
        }
    }
}

impl<const N: usize> From<[u8; N]> for ProtectedKey<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self::new(bytes)
    }
}

impl<const N: usize> From<Zeroizing<[u8; N]>> for ProtectedKey<N> {
    fn from(bytes: Zeroizing<[u8; N]>) -> Self {
        Self::from_zeroizing(bytes)
    }
}

impl<const N: usize> Deref for ProtectedKey<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> Drop for ProtectedKey<N> {
    fn drop(&mut self) {
        self.0.zeroize();
        self.unlock_memory();
    }
}

impl<const N: usize> std::fmt::Debug for ProtectedKey<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProtectedKey<{} bytes>([REDACTED])", N)
    }
}

/
pub struct ProtectedBuf(Vec<u8>);

impl Clone for ProtectedBuf {
    fn clone(&self) -> Self {
        let mut buf = Self(self.0.clone());
        buf.lock_memory();
        buf
    }
}

impl ProtectedBuf {
    /
    pub fn new(mut bytes: Vec<u8>) -> Self {
        
        
        let taken = Zeroizing::new(std::mem::take(&mut bytes));
        
        bytes.zeroize();
        let mut buf = Self((*taken).clone());
        buf.lock_memory();
        
        buf
    }

    /
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn lock_memory(&mut self) {
        #[cfg(unix)]
        if !self.0.is_empty() {
            unsafe {
                if mlock(self.0.as_ptr() as *const libc::c_void, self.0.len()) != 0 {
                    log::warn!(
                        "mlock failed for ProtectedBuf: {}",
                        std::io::Error::last_os_error()
                    );
                }
            }
        }
    }

    fn unlock_memory(&mut self) {
        #[cfg(unix)]
        if !self.0.is_empty() {
            unsafe {
                let _ = munlock(self.0.as_ptr() as *const libc::c_void, self.0.len());
            }
        }
    }
}

impl From<Vec<u8>> for ProtectedBuf {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl Deref for ProtectedBuf {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for ProtectedBuf {
    fn drop(&mut self) {
        self.0.zeroize();
        self.unlock_memory();
    }
}

impl std::fmt::Debug for ProtectedBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProtectedBuf<{} bytes>([REDACTED])", self.0.len())
    }
}
