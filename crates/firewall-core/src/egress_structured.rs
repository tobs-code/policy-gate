// egress_structured.rs — Structured Output Scanning (JSON/XML)
//
// SA-077: Detect PII and secrets in structured outputs (JSON/XML).
// Many LLM applications return structured data, and sensitive information
// can hide in field values that would be missed by plain-text scanning.

use regex::Regex;
use std::sync::OnceLock;

/// Result of structured output scanning.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct StructuredScanResult {
    /// Type of sensitive data found
    pub data_type: &'static str,
    /// Field name where it was found
    pub field_name: String,
    /// Snippet of the value (truncated for safety)
    #[allow(dead_code)]
    pub value_snippet: String,
}

/// Safely compile a regex pattern, logging errors instead of panicking.
/// CVE-FIX: Returns Option instead of panicking on invalid regex.
fn compile_pattern(pattern: &str, name: &'static str) -> Option<Regex> {
    match Regex::new(pattern) {
        Ok(re) => Some(re),
        Err(e) => {
            eprintln!("[WARN] Failed to compile {} regex pattern: {}. This PII pattern will be skipped.", name, e);
            None
        }
    }
}

/// Scan JSON output for PII and secrets.
#[allow(dead_code)]
pub fn scan_json(text: &str) -> Option<StructuredScanResult> {
    // Extract field name — compiled once via OnceLock (outside loop)
    static FIELD_RE: std::sync::OnceLock<Option<Regex>> = std::sync::OnceLock::new();
    let field_re_opt = FIELD_RE.get_or_init(|| {
        compile_pattern(r#""([^"]+)"\s*:"#, "JSON field name")
    });
    
    let field_re = field_re_opt.as_ref()?;

    let patterns = JSON_PII_PATTERNS.get_or_init(|| {
        vec![
            // Medical/Health data
            (
                "MedicalRecordNumber",
                compile_pattern(r#"(?i)"(?:medical_record|mrn|patient_id|health_id)"\s*:\s*"[^"]{5,}""#, "MedicalRecordNumber JSON"),
            ),
            (
                "DiagnosisCode",
                compile_pattern(r#"(?i)"(?:diagnosis|icd_code|icd10)"\s*:\s*"[A-Z]\d{2}(\.\w+)?""#, "DiagnosisCode JSON"),
            ),
            (
                "Prescription",
                compile_pattern(r#"(?i)"(?:prescription|medication|drug_name)"\s*:\s*"[^"]{3,}""#, "Prescription JSON"),
            ),
            // Biometric data
            (
                "Fingerprint",
                compile_pattern(r#"(?i)"(?:fingerprint|fingerprint_template|fp_hash)"\s*:\s*"[^"]{20,}""#, "Fingerprint JSON"),
            ),
            (
                "FaceEmbedding",
                compile_pattern(r#"(?i)"(?:face_embedding|face_vector|facial_features)"\s*:\s*"\[[^\]]{50,}\]""#, "FaceEmbedding JSON"),
            ),
            (
                "IrisData",
                compile_pattern(r#"(?i)"(?:iris_code|iris_template|eye_pattern)"\s*:\s*"[^"]{50,}""#, "IrisData JSON"),
            ),
            (
                "VoicePrint",
                compile_pattern(r#"(?i)"(?:voice_print|voice_embedding|voice_template)"\s*:\s*"[^"]{50,}""#, "VoicePrint JSON"),
            ),
            // Identity documents
            (
                "PassportNumber",
                compile_pattern(r#"(?i)"(?:passport|passport_number|passport_no)"\s*:\s*"[A-Z0-9]{6,12}""#, "PassportNumber JSON"),
            ),
            (
                "DriversLicense",
                compile_pattern(r#"(?i)"(?:drivers_license|driver_license|dl_number|license_no)"\s*:\s*"[A-Z0-9]{5,15}""#, "DriversLicense JSON"),
            ),
            (
                "NationalID",
                compile_pattern(r#"(?i)"(?:national_id|national_identifier|tax_id|sin|nin)"\s*:\s*"[A-Z0-9]{6,15}""#, "NationalID JSON"),
            ),
            // Financial - extended
            (
                "BankAccount",
                compile_pattern(r#"(?i)"(?:bank_account|account_number|iban|bic)"\s*:\s*"[A-Z0-9]{8,34}""#, "BankAccount JSON"),
            ),
            (
                "RoutingNumber",
                compile_pattern(r#"(?i)"(?:routing_number|aba|swift_code)"\s*:\s*"[A-Z0-9]{8,11}""#, "RoutingNumber JSON"),
            ),
            // Secrets in JSON
            (
                "PrivateKey",
                compile_pattern(r#"(?i)"(?:private_key|privatekey|priv_key)"\s*:\s*"[^"]{50,}""#, "PrivateKey JSON"),
            ),
            (
                "DatabaseURL",
                compile_pattern(r#"(?i)"(?:database_url|db_url|db_connection_string)"\s*:\s*"[^"]{20,}""#, "DatabaseURL JSON"),
            ),
        ]
    });

    for (name, pattern_opt) in patterns {
        if let Some(pattern) = pattern_opt {
            if let Some(caps) = pattern.captures(text) {
                let full_match = caps.get(0)?.as_str();
                let field_match = field_re
                    .captures(full_match)?
                    .get(1)?
                    .as_str();
                
                return Some(StructuredScanResult {
                    data_type: name,
                    field_name: field_match.to_string(),
                    value_snippet: truncate_value(full_match, 50),
                });
            }
        }
    }
    None
}

/// Scan XML output for PII and secrets.
#[allow(dead_code)]
pub fn scan_xml(text: &str) -> Option<StructuredScanResult> {
    // Extract tag name — compiled once via OnceLock (outside loop)
    static TAG_RE: std::sync::OnceLock<Option<Regex>> = std::sync::OnceLock::new();
    let tag_re_opt = TAG_RE.get_or_init(|| {
        compile_pattern(r#"<([^\s>]+)"#, "XML tag name")
    });
    
    let tag_re = tag_re_opt.as_ref()?;

    let patterns = XML_PII_PATTERNS.get_or_init(|| {
        vec![
            // Medical/Health data
            (
                "MedicalRecordNumber",
                compile_pattern(r#"(?i)<(?:medical_record|mrn|patient_id|health_id)[^>]*>[^<]{5,}</"#, "MedicalRecordNumber XML"),
            ),
            (
                "DiagnosisCode",
                compile_pattern(r#"(?i)<(?:diagnosis|icd_code|icd10)[^>]*>[A-Z]\d{2}(?:\.\w+)?</"#, "DiagnosisCode XML"),
            ),
            // Biometric data
            (
                "Fingerprint",
                compile_pattern(r#"(?i)<(?:fingerprint|fingerprint_template|fp_hash)[^>]*>[^<]{20,}</"#, "Fingerprint XML"),
            ),
            (
                "FaceEmbedding",
                compile_pattern(r#"(?i)<(?:face_embedding|face_vector|facial_features)[^>]*>[^<]{50,}</"#, "FaceEmbedding XML"),
            ),
            // Identity documents
            (
                "PassportNumber",
                compile_pattern(r#"(?i)<(?:passport|passport_number|passport_no)[^>]*>[A-Z0-9]{6,12}</"#, "PassportNumber XML"),
            ),
            (
                "DriversLicense",
                compile_pattern(r#"(?i)<(?:drivers_license|driver_license|dl_number)[^>]*>[A-Z0-9]{5,15}</"#, "DriversLicense XML"),
            ),
            (
                "NationalID",
                compile_pattern(r#"(?i)<(?:national_id|national_identifier|tax_id|sin|nin)[^>]*>[A-Z0-9]{6,15}</"#, "NationalID XML"),
            ),
            // Secrets in XML
            (
                "PrivateKey",
                compile_pattern(r#"(?i)<(?:private_key|privatekey|priv_key)[^>]*>[^<]{50,}</"#, "PrivateKey XML"),
            ),
            (
                "APIKey",
                compile_pattern(r#"(?i)<(?:api_key|apikey|api_secret)[^>]*>[^<]{16,}</"#, "APIKey XML"),
            ),
        ]
    });

    for (name, pattern_opt) in patterns {
        if let Some(pattern) = pattern_opt {
            if let Some(caps) = pattern.captures(text) {
                let full_match = caps.get(0)?.as_str();
                let tag_match = tag_re
                    .captures(full_match)?
                    .get(1)?
                    .as_str();
                
                return Some(StructuredScanResult {
                    data_type: name,
                    field_name: tag_match.to_string(),
                    value_snippet: truncate_value(full_match, 50),
                });
            }
        }
    }
    None
}

/// Detect if text looks like JSON or XML and scan accordingly.
#[allow(dead_code)]
pub fn scan_structured_output(text: &str) -> Option<StructuredScanResult> {
    let trimmed = text.trim();
    
    // Quick detection - JSON starts with { or [
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return scan_json(text);
    }
    
    // XML detection - starts with < (but not just < alone)
    if trimmed.starts_with('<') && trimmed.len() > 2 {
        // Skip XML declaration if present
        let content = if trimmed.starts_with("<?xml") {
            trimmed.find("?>").map(|i| &trimmed[i + 2..]).unwrap_or(trimmed)
        } else {
            trimmed
        };
        
        // Check if it's actually XML (has a tag)
        if content.trim().starts_with('<') && content.contains('>') {
            return scan_xml(text);
        }
    }
    
    None
}

#[allow(dead_code)]
fn truncate_value(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

#[allow(dead_code)]
static JSON_PII_PATTERNS: OnceLock<Vec<(&'static str, Option<Regex>)>> = OnceLock::new();
#[allow(dead_code)]
static XML_PII_PATTERNS: OnceLock<Vec<(&'static str, Option<Regex>)>> = OnceLock::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_json_medical_record() {
        let json = r#"{"patient_id": "MRN-12345678", "name": "John"}"#;
        let result = scan_json(json);
        assert!(result.is_some());
        assert_eq!(result.unwrap().data_type, "MedicalRecordNumber");
    }

    #[test]
    fn test_scan_json_fingerprint() {
        let json = r#"{"user": "alice", "fingerprint": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"}"#;
        let result = scan_json(json);
        assert!(result.is_some());
        assert_eq!(result.unwrap().data_type, "Fingerprint");
    }

    #[test]
    fn test_scan_xml_passport() {
        let xml = r#"<user><passport_number>AB1234567</passport_number></user>"#;
        let result = scan_xml(xml);
        assert!(result.is_some());
        assert_eq!(result.unwrap().data_type, "PassportNumber");
    }

    #[test]
    fn test_scan_structured_auto_detect_json() {
        let json = r#"{"drivers_license": "D1234567"}"#;
        let result = scan_structured_output(json);
        assert!(result.is_some());
        assert_eq!(result.unwrap().data_type, "DriversLicense");
    }

    #[test]
    fn test_scan_structured_auto_detect_xml() {
        let xml = r#"<?xml version="1.0"?><record><national_id>123456789</national_id></record>"#;
        let result = scan_structured_output(xml);
        assert!(result.is_some());
        assert_eq!(result.unwrap().data_type, "NationalID");
    }

    #[test]
    fn test_scan_structured_plain_text() {
        let text = "This is just plain text with no structure";
        let result = scan_structured_output(text);
        assert!(result.is_none());
    }
}