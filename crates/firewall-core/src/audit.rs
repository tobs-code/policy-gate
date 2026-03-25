use crate::types::AuditEntry;
use std::sync::OnceLock;

static HMAC_KEY: OnceLock<[u8; 32]> = OnceLock::new();
static LAST_AUDIT_HMAC: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
static CHAIN_SEAL_PATH: &str = "audit_chain.seal";

pub(crate) fn init_audit() {
    let _ = HMAC_KEY.get_or_init(|| {
        if let Ok(key_str) = std::env::var("POLICY_GATE_HMAC_KEY") {
            if let Ok(key_bytes) = hex::decode(&key_str) {
                if key_bytes.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&key_bytes);
                    return key;
                }
            }
        }

        use getrandom::getrandom;
        let mut key = [0u8; 32];
        getrandom(&mut key).expect("cryptographic RNG unavailable");

        if let Err(e) = std::fs::write(CHAIN_SEAL_PATH, hex::encode(key)) {
            eprintln!("Warning: Could not save HMAC key: {}", e);
        }

        key
    });

    if let Ok(seal_content) = std::fs::read_to_string(CHAIN_SEAL_PATH) {
        let trimmed = seal_content.trim();
        if !trimmed.is_empty() && trimmed.len() == 64 {
            *LAST_AUDIT_HMAC.lock().unwrap() = Some(trimmed.to_string());
        }
    }
}

pub(crate) fn attach_chain_hmac(entry: &mut AuditEntry) {
    if let (Some(key), Ok(mut last_hmac_guard)) = (HMAC_KEY.get(), LAST_AUDIT_HMAC.lock()) {
        let prev_hmac = last_hmac_guard.clone();
        let current_hmac = compute_audit_hmac(key, entry, prev_hmac.as_deref());
        entry.chain_hmac = Some(current_hmac.clone());
        *last_hmac_guard = Some(current_hmac.clone());
        if let Err(e) = std::fs::write(CHAIN_SEAL_PATH, &current_hmac) {
            eprintln!("Warning: Could not write chain seal: {}", e);
        }
    }
}

pub(crate) fn compute_audit_hmac(
    key: &[u8; 32],
    entry: &AuditEntry,
    prev_hmac: Option<&str>,
) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key size incorrect");
    mac.update(&entry.sequence.to_le_bytes());
    mac.update(&entry.ingested_at_ns.to_le_bytes());
    mac.update(&entry.decided_at_ns.to_le_bytes());
    mac.update(entry.input_hash.as_bytes());
    if let Some(prev) = prev_hmac {
        mac.update(prev.as_bytes());
    }
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
pub(crate) fn hmac_key() -> Option<&'static [u8; 32]> {
    HMAC_KEY.get()
}

#[cfg(not(feature = "fips"))]
pub(crate) fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(feature = "fips")]
pub(crate) fn sha256_hex(input: &str) -> String {
    use aws_lc_rs::digest;
    let digest = digest::digest(&digest::SHA256, input.as_bytes());
    hex::encode(digest.as_ref())
}
