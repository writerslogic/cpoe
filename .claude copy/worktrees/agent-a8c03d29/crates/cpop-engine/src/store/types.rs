

/
#[derive(Debug, Clone)]
pub struct SecureEvent {
    pub id: Option<i64>,
    pub device_id: [u8; 16],
    pub machine_id: String,
    pub timestamp_ns: i64,
    pub file_path: String,
    pub content_hash: [u8; 32],
    pub file_size: i64,
    pub size_delta: i32,
    pub previous_hash: [u8; 32],
    pub event_hash: [u8; 32],
    pub context_type: Option<String>,
    pub context_note: Option<String>,
    pub vdf_input: Option<[u8; 32]>,
    pub vdf_output: Option<[u8; 32]>,
    pub vdf_iterations: u64,
    pub forensic_score: f64,
    pub is_paste: bool,
    /
    pub hardware_counter: Option<u64>,
    /
    pub input_method: Option<String>,
    /
    pub lamport_signature: Option<Vec<u8>>,
    /
    pub lamport_pubkey_fingerprint: Option<Vec<u8>>,
}

fn now_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

impl SecureEvent {
    /
    /
    /
    /
    pub fn new(
        file_path: String,
        content_hash: [u8; 32],
        file_size: i64,
        context_note: Option<String>,
    ) -> Self {
        Self {
            id: None,
            device_id: [0u8; 16],
            machine_id: String::new(),
            timestamp_ns: now_ns(),
            file_path,
            content_hash,
            file_size,
            size_delta: 0,
            previous_hash: [0u8; 32],
            event_hash: [0u8; 32],
            context_type: None,
            context_note,
            vdf_input: None,
            vdf_output: None,
            vdf_iterations: 0,
            forensic_score: 0.0,
            is_paste: false,
            hardware_counter: None,
            input_method: None,
            lamport_signature: None,
            lamport_pubkey_fingerprint: None,
        }
    }
}
