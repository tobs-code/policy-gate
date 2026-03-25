// lib.rs — firewall-wasm: JS/WASM bindings for policy-gate
//
// Safety Action SA-060: Export high-security firewall to WASM for Edge deployment.

use wasm_bindgen::prelude::*;
use firewall_core::{PromptInput, evaluate, init};

#[wasm_bindgen]
pub fn init_firewall() -> Result<(), String> {
    init().map_err(|e| e.to_string())
}

#[wasm_bindgen]
pub fn evaluate_prompt(text: String, sequence: u64) -> Result<JsValue, String> {
    let input = PromptInput::new(&text)
        .map_err(|e| format!("Normalization failed: {:?}", e))?;
    
    let verdict = evaluate(input, sequence);
    
    serde_wasm_bindgen::to_value(&verdict)
        .map_err(|e| format!("Serialization failed: {}", e))
}
