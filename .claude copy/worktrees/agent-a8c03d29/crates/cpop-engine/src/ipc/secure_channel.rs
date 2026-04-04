

//! Encrypted channel wrapper for inter-component communication

use chacha20poly1305::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvError, SendError, Sender};
use zeroize::{Zeroize, Zeroizing};

/
/
/
/
const NONCE_COUNTER_MAX: u64 = u64::MAX - 1;

/
/
/
const MAX_SECURE_CHANNEL_PAYLOAD: usize = super::messages::MAX_MESSAGE_SIZE;

/
/
fn zeroize_cipher(cipher: &mut ChaCha20Poly1305) {
    
    
    let ptr = cipher as *mut ChaCha20Poly1305 as *mut u8;
    let len = std::mem::size_of::<ChaCha20Poly1305>();
    
    for i in 0..len {
        unsafe { std::ptr::write_volatile(ptr.add(i), 0u8) };
    }
    std::sync::atomic::fence(Ordering::SeqCst);
}

/
pub struct SecureChannel<T> {
    _phantom: std::marker::PhantomData<T>,
}

/
pub struct EncryptedMessage {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl<T: serde::Serialize + serde::de::DeserializeOwned> SecureChannel<T> {
    /
    pub fn new_pair() -> (SecureSender<T>, SecureReceiver<T>) {
        let (tx, rx) = mpsc::channel();

        let mut key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let cipher = ChaCha20Poly1305::new(&key);
        key.as_mut_slice().zeroize();

        
        
        let mut nonce_prefix = [0u8; 4];
        OsRng.fill_bytes(&mut nonce_prefix);

        let sender = SecureSender {
            tx,
            cipher: cipher.clone(),
            nonce_counter: AtomicU64::new(0),
            nonce_prefix,
            _phantom: std::marker::PhantomData,
        };

        let receiver = SecureReceiver {
            rx,
            cipher,
            _phantom: std::marker::PhantomData,
        };

        (sender, receiver)
    }
}

/
pub struct SecureSender<T> {
    tx: Sender<EncryptedMessage>,
    cipher: ChaCha20Poly1305,
    pub(super) nonce_counter: AtomicU64,
    /
    nonce_prefix: [u8; 4],
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Drop for SecureSender<T> {
    fn drop(&mut self) {
        zeroize_cipher(&mut self.cipher);
        self.nonce_prefix.zeroize();
    }
}

impl<T: serde::Serialize> SecureSender<T> {
    /
    pub fn send(&self, value: T) -> Result<(), SendError<EncryptedMessage>> {
        let plaintext = Zeroizing::new(
            bincode::serde::encode_to_vec(&value, bincode::config::standard()).map_err(|_| {
                SendError(EncryptedMessage {
                    nonce: [0; 12],
                    ciphertext: vec![],
                })
            })?,
        );

        
        let counter = loop {
            let current = self.nonce_counter.load(Ordering::SeqCst);
            if current >= NONCE_COUNTER_MAX {
                return Err(SendError(EncryptedMessage {
                    nonce: [0; 12],
                    ciphertext: vec![],
                }));
            }
            match self.nonce_counter.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(val) => break val,
                Err(_) => continue,
            }
        };
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..4].copy_from_slice(&self.nonce_prefix);
        nonce_bytes[4..].copy_from_slice(&counter.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|_| {
                SendError(EncryptedMessage {
                    nonce: [0; 12],
                    ciphertext: vec![],
                })
            })?;

        self.tx.send(EncryptedMessage {
            nonce: nonce_bytes,
            ciphertext,
        })
    }
}

/
pub struct SecureReceiver<T> {
    rx: Receiver<EncryptedMessage>,
    cipher: ChaCha20Poly1305,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Drop for SecureReceiver<T> {
    fn drop(&mut self) {
        zeroize_cipher(&mut self.cipher);
    }
}

impl<T: serde::de::DeserializeOwned> SecureReceiver<T> {
    /
    pub fn recv(&self) -> Result<T, RecvError> {
        let msg = self.rx.recv()?;
        let nonce = Nonce::from_slice(&msg.nonce);

        let mut plaintext = self
            .cipher
            .decrypt(nonce, msg.ciphertext.as_ref())
            .map_err(|_| RecvError)?;

        if plaintext.len() > MAX_SECURE_CHANNEL_PAYLOAD {
            plaintext.zeroize();
            return Err(RecvError);
        }

        let (value, _): (T, usize) = bincode::serde::decode_from_slice(
            &plaintext,
            bincode::config::standard().with_limit::<{ super::messages::MAX_MESSAGE_SIZE }>(),
        )
        .map_err(|_| RecvError)?;

        plaintext.zeroize();

        Ok(value)
    }
}
