// crates/firewall-pyo3/src/lib.rs — Python binding for policy-gate
//
// NOT part of the safety function.
// See SAFETY_MANUAL.md §8.1 OC-06: the safety-critical boundary is firewall-core only.
//
// pyo3 requires unsafe internally — #![forbid(unsafe_code)] is not applied here.
// #![deny(clippy::all)] is applied for code quality.
#![deny(clippy::all)]

use firewall_core::{evaluate_messages, evaluate_output, evaluate_raw, init, next_sequence, ChatMessage, PromptInput};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn verdict_to_dict(py: Python<'_>, v: firewall_core::Verdict) -> PyResult<PyObject> {
    let d = PyDict::new_bound(py);
    d.set_item("is_pass", v.is_pass())?;
    d.set_item("verdict_kind", format!("{:?}", v.kind))?;
    d.set_item("sequence", v.audit.sequence)?;
    d.set_item("total_elapsed_us", v.audit.total_elapsed_us)?;
    d.set_item("input_hash", &v.audit.input_hash)?;
    d.set_item("schema_version", v.audit.schema_version)?;

    // block_reason — structured dict or None
    if let Some(br) = &v.audit.block_reason {
        let br_dict = PyDict::new_bound(py);
        match br {
            firewall_core::BlockReason::ForbiddenPattern { pattern_id } => {
                br_dict.set_item("type", "ForbiddenPattern")?;
                br_dict.set_item("pattern_id", pattern_id)?;
            }
            firewall_core::BlockReason::NoIntentMatch => {
                br_dict.set_item("type", "NoIntentMatch")?;
            }
            firewall_core::BlockReason::MalformedInput { detail } => {
                br_dict.set_item("type", "MalformedInput")?;
                br_dict.set_item("detail", detail)?;
            }
            firewall_core::BlockReason::ExceededMaxLength => {
                br_dict.set_item("type", "ExceededMaxLength")?;
            }
            _ => {
                br_dict.set_item("type", format!("{:?}", br))?;
            }
        }
        d.set_item("block_reason", br_dict)?;
    } else {
        d.set_item("block_reason", py.None())?;
    }

    Ok(d.into())
}

// ─── Python module ────────────────────────────────────────────────────────────

/// Initialise the firewall. Must be called before evaluate_raw() or evaluate_messages().
/// Raises RuntimeError if any safety-critical pattern fails to compile.
/// Safe to call multiple times — returns cached result after first call.
fn egress_verdict_to_dict(py: Python<'_>, v: firewall_core::EgressVerdict) -> PyResult<PyObject> {
    let d = PyDict::new_bound(py);
    d.set_item("is_pass", v.is_pass())?;
    d.set_item("verdict_kind", format!("{:?}", v.kind))?;
    if let Some(reason) = &v.egress_reason {
        let reason_dict = PyDict::new_bound(py);
        match reason {
            firewall_core::EgressBlockReason::SystemPromptLeakage { detail } => {
                reason_dict.set_item("type", "SystemPromptLeakage")?;
                reason_dict.set_item("detail", detail)?;
            }
            firewall_core::EgressBlockReason::PiiDetected { pii_type } => {
                reason_dict.set_item("type", "PiiDetected")?;
                reason_dict.set_item("pii_type", pii_type)?;
            }
            firewall_core::EgressBlockReason::HarmfulContent { category } => {
                reason_dict.set_item("type", "HarmfulContent")?;
                reason_dict.set_item("category", category)?;
            }
            firewall_core::EgressBlockReason::Other { detail } => {
                reason_dict.set_item("type", "Other")?;
                reason_dict.set_item("detail", detail)?;
            }
        }
        d.set_item("egress_reason", reason_dict)?;
    } else {
        d.set_item("egress_reason", py.None())?;
    }
    Ok(d.into())
}

#[pyfunction(name = "init")]
fn firewall_init() -> PyResult<()> {
    init().map_err(|e| PyRuntimeError::new_err(format!("firewall init failed: {e}")))
}

/// Evaluate a single raw prompt string through the safety gate.
///
/// Returns a dict with keys:
///   is_pass (bool), verdict_kind (str), sequence (int),
///   total_elapsed_us (int), input_hash (str), block_reason (dict|None),
///   schema_version (int)
///
/// Raises RuntimeError if the firewall was not initialised.
#[pyfunction(name = "evaluate_raw")]
fn firewall_evaluate_raw(py: Python<'_>, text: String) -> PyResult<PyObject> {
    let v = evaluate_raw(text, next_sequence());
    verdict_to_dict(py, v)
}

/// Evaluate a list of message dicts through the safety gate.
///
/// Each message dict must have "role" and "content" string keys.
/// Evaluation is fail-fast: stops at the first blocking message.
///
/// Returns a dict with keys:
///   is_pass (bool), first_block_index (int|-1), verdicts (list[dict])
///
/// Raises RuntimeError if the firewall was not initialised or messages are malformed.
#[pyfunction(name = "evaluate_messages")]
fn firewall_evaluate_messages(py: Python<'_>, messages: &Bound<'_, PyList>) -> PyResult<PyObject> {
    let base_seq = next_sequence();

    let mut chat_messages: Vec<ChatMessage> = Vec::with_capacity(messages.len());
    for (i, item) in messages.iter().enumerate() {
        let d = item.downcast::<PyDict>().map_err(|_| {
            PyRuntimeError::new_err(format!("messages[{i}] must be a dict with 'role' and 'content'"))
        })?;
        let role: String = d.get_item("role")
            .map_err(|_| PyRuntimeError::new_err(format!("messages[{i}] missing 'role'")))?
            .ok_or_else(|| PyRuntimeError::new_err(format!("messages[{i}] missing 'role'")))?
            .extract()?;
        let content: String = d.get_item("content")
            .map_err(|_| PyRuntimeError::new_err(format!("messages[{i}] missing 'content'")))?
            .ok_or_else(|| PyRuntimeError::new_err(format!("messages[{i}] missing 'content'")))?
            .extract()?;
        chat_messages.push(ChatMessage { role, content });
    }

    let cv = evaluate_messages(&chat_messages, base_seq);

    let result = PyDict::new_bound(py);
    result.set_item("is_pass", cv.is_pass)?;
    result.set_item("first_block_index",
        cv.first_block_index.map(|i| i as i64).unwrap_or(-1))?;

    let verdicts_list = PyList::empty_bound(py);
    for v in cv.verdicts {
        verdicts_list.append(verdict_to_dict(py, v)?)?;
    }
    result.set_item("verdicts", verdicts_list)?;

    Ok(result.into())
}

/// Evaluate an LLM response against the original prompt.
///
/// Returns a dict with keys:
///   is_pass (bool), verdict_kind (str), egress_reason (dict|None)
#[pyfunction(name = "evaluate_output")]
fn firewall_evaluate_output(py: Python<'_>, prompt: String, response: String) -> PyResult<PyObject> {
    let prompt = PromptInput::new(prompt)
        .map_err(|e| PyRuntimeError::new_err(format!("invalid prompt for egress evaluation: {:?}", e)))?;
    let v = evaluate_output(&prompt, &response, next_sequence())
        .map_err(|e| PyRuntimeError::new_err(format!("egress evaluation failed: {e}")))?;
    egress_verdict_to_dict(py, v)
}

/// policy-gate Python binding.
///
/// Usage:
///     import policy_gate
///     policy_gate.init()
///     result = policy_gate.evaluate_raw("What is the capital of France?")
///     print(result["is_pass"])  # True
#[pymodule]
fn policy_gate(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(firewall_init, m)?)?;
    m.add_function(wrap_pyfunction!(firewall_evaluate_raw, m)?)?;
    m.add_function(wrap_pyfunction!(firewall_evaluate_messages, m)?)?;
    m.add_function(wrap_pyfunction!(firewall_evaluate_output, m)?)?;
    Ok(())
}
