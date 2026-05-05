// streaming.rs — SA-NEW: Pillar 6 Streaming Egress Handler
//
// Provides safe SSE (Server-Sent Events) streaming from the upstream LLM API
// while applying Aho-Corasick based egress scanning chunk-by-chunk.
//
// Safety invariants:
//   1. Ingress evaluation (full prompt) is always completed BEFORE forwarding
//      to the upstream. Streaming does not bypass the ingress gate.
//   2. Every SSE chunk is scanned against the overlap-buffered pattern set.
//      No chunk is forwarded to the client before being scanned.
//   3. On block: an SSE error event is sent to the client, then the connection
//      is aborted. The partial response already delivered is the accepted risk
//      (same as TCP RST in deep packet inspection systems).
//   4. On [DONE]: a final full-document evaluate_output() is run as a safety
//      net (configurable via streaming_egress_final_check). Divergence is
//      counted via Prometheus but never changes a clean streaming result to
//      a block (we cannot retract already-sent frames).

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use firewall_core::{
    evaluate_output_for_tenant, evaluate_raw_for_tenant, next_sequence, PromptInput,
    StreamEgressDecision, StreamScanner, VerdictKind,
};
use futures_util::StreamExt;
use std::sync::Arc;
use metrics::counter;
use serde_json::Value;
use tracing::{info, warn};

use crate::{AppState, ChatCompletionRequest};

/// Maximum size of the accumulated SSE body for the final-check.
/// Beyond this, the final check is skipped (the body would be too large
/// to hold in memory anyway — the streaming path exists precisely to avoid
/// buffering the full response).
const MAX_FINAL_CHECK_BYTES: usize = 256 * 1024; // 256 KB

pub async fn handle_streaming_chat_completion(
    State(state): State<Arc<AppState>>,
    axum::Json(mut body): axum::Json<ChatCompletionRequest>,
) -> Response {
    // ── Ingress evaluation (full prompt — identical to non-streaming path) ───
    let tenant_id = body.tenant_id.clone();
    let prompt_text = match extract_prompt_text(&body) {
        Some(t) => t,
        None => {
            return (StatusCode::BAD_REQUEST, "No prompt content found").into_response();
        }
    };

    let sequence = next_sequence();
    let ingress_verdict = evaluate_raw_for_tenant(
        prompt_text.clone(),
        sequence,
        tenant_id.clone(),
    );

    if !ingress_verdict.is_pass() {
        counter!("policy_gate_ingress_blocks_total").increment(1);
        info!("Streaming request blocked at ingress: {:?}", ingress_verdict.kind);
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "error": {
                    "type": "policy_gate_block",
                    "message": "Request blocked by policy-gate ingress evaluation",
                    "verdict": format!("{:?}", ingress_verdict.kind),
                }
            })),
        )
            .into_response();
    }

    // ── Resolve tenant config for streaming settings ──────────────────────────
    let config = match firewall_core::config::FirewallConfig::load() {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to load streaming config: {}, using defaults", e);
            counter!("policy_gate_config_load_errors_total").increment(1);
            firewall_core::config::FirewallConfig::default()
        }
    };
    let do_final_check = config.streaming_egress_final_check;

    // ── Forward to upstream with stream: true ─────────────────────────────────
    body.stream = Some(true);
    let upstream_url = format!("{}/v1/chat/completions", state.upstream_url);

    let upstream_response = match state
        .http_client
        .post(&upstream_url)
        .bearer_auth(&state.api_key)
        .json(&body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("Upstream request failed: {}", e);
            return (StatusCode::BAD_GATEWAY, "Upstream request failed").into_response();
        }
    };

    if !upstream_response.status().is_success() {
        let status = upstream_response.status();
        let upstream_body = upstream_response
            .text()
            .await
            .unwrap_or_else(|_| "no body".to_string());
        return (status, upstream_body).into_response();
    }

    // ── Set up scanner and response channel ──────────────────────────────────
    let mut scanner = StreamScanner::new();
    let prompt_input = match PromptInput::new(&prompt_text) {
        Ok(p) => p,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create prompt input")
                .into_response();
        }
    };

    // Use mpsc and unfold to create a response body stream.
    let (sender, receiver) = tokio::sync::mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(16);
    let stream = futures_util::stream::unfold(receiver, |mut r| async {
        r.recv().await.map(|msg| (msg, r))
    });
    let recv_body = axum::body::Body::from_stream(stream);
    let egress_sequence = next_sequence();
    let tenant_id_owned = tenant_id.clone();

    // Spawn the scanning loop as a background task with timeout protection.
    let _join_handle = tokio::spawn(async move {
        let mut byte_stream = upstream_response.bytes_stream();
        let mut accumulated: Vec<u8> = Vec::new();
        let mut blocked = false;
        const STREAM_CHUNK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

        loop {
            let chunk_result = match tokio::time::timeout(STREAM_CHUNK_TIMEOUT, byte_stream.next()).await {
                Ok(Some(result)) => result,
                Ok(None) => break,  // Stream closed normally (EOS)
                Err(_) => {
                    warn!("Streaming chunk timeout (30s exceeded), closing connection");
                    counter!("policy_gate_streaming_timeout_total").increment(1);
                    let _ = sender.send(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "stream chunk timeout",
                    ))).await;
                    break;
                }
            };
            let chunk = match chunk_result {
                Ok(c) => c,
                Err(e) => {
                    warn!("Upstream stream error: {}", e);
                    break;
                }
            };

            // ── Scan chunk ───────────────────────────────────────────────────
            let decision = scanner.feed(&chunk);

            match decision {
                StreamEgressDecision::Block { pattern_id } => {
                    warn!("Streaming block: pattern {} detected. Sending error event...", pattern_id);
                    counter!("policy_gate_streaming_egress_blocks_total").increment(1);
                    // Send SSE error event to client before aborting.
                    let error_event = format!(
                        "event: error\ndata: {{\"error\":\"policy-gate egress block\",\
                         \"pattern\":\"{}\"}}\n\n",
                        pattern_id
                    );
                    let _ = sender.send(Ok(error_event.into())).await;
                    
                    // Tiny delay to ensure the error event is flushed before the connection is aborted.
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

                    // Abort stream by sending an explicit error, causing TCP RST.
                    let _ = sender.send(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "policy egress block",
                    ))).await;
                    blocked = true;
                    break;
                }
                StreamEgressDecision::Forward => {
                    // Accumulate for final check (up to limit).
                    if do_final_check && accumulated.len() < MAX_FINAL_CHECK_BYTES {
                        accumulated.extend_from_slice(&chunk);
                    }
                    counter!("policy_gate_streaming_chunks_total").increment(1);
                    if sender.send(Ok(chunk.clone())).await.is_err() {
                        // Client disconnected.
                        break;
                    }
                }
            }
        }

        // ── Final check at [DONE] ─────────────────────────────────────────────
        if !blocked && do_final_check && !accumulated.is_empty() {
            let response_text = String::from_utf8_lossy(&accumulated).to_string();
            // Extract content from SSE frames for the document check.
            let extracted = extract_sse_content(&response_text);
            if let Ok(egress_verdict) = evaluate_output_for_tenant(
                &prompt_input,
                &extracted,
                egress_sequence,
                tenant_id_owned.as_deref(),
            ) {
                if !matches!(egress_verdict.kind, VerdictKind::Pass | VerdictKind::ShadowPass) {
                    // AC scan passed but doc-level scan blocks — divergence alarm.
                    // We cannot retract already-sent frames, but we log and count.
                    counter!("policy_gate_streaming_egress_divergence_total").increment(1);
                    warn!(
                        "Streaming egress DIVERGENCE: AC scan passed but final check \
                         blocked (tenant={:?}, reason={:?}). \
                         Already-sent frames cannot be retracted.",
                        tenant_id_owned,
                        egress_verdict.egress_reason
                    );
                }
            }
        }
    });

    // ── Build response ────────────────────────────────────────────────────────
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header("X-Accel-Buffering", "no")
        .body(recv_body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Extract the user prompt text from a chat completion request body.
fn extract_prompt_text(body: &ChatCompletionRequest) -> Option<String> {
    body.messages
        .iter()
        .filter(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"))
        .last()
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .map(|s| s.to_string())
}

/// Extract plain-text content from SSE frames for the final document check.
/// Parses `data: {"choices":[{"delta":{"content":"..."}}]}` frames.
fn extract_sse_content(sse_text: &str) -> String {
    let mut out = String::new();
    for line in sse_text.lines() {
        let line = line.trim();
        if let Some(data) = line.strip_prefix("data: ") {
            if data == "[DONE]" {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(data) {
                if let Some(content) = v
                    .pointer("/choices/0/delta/content")
                    .and_then(|c| c.as_str())
                {
                    out.push_str(content);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Router};
    use tokio::net::TcpListener;
    use serde_json::json;

    #[tokio::test]
    async fn test_extract_sse_content() {
        let text = "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\ndata: {\"choices\":[{\"delta\":{\"content\":\" World\"}}]}\ndata: [DONE]\n";
        let out = extract_sse_content(text);
        assert_eq!(out, "Hello World");
    }

    async fn start_mock_server(app: Router) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        port
    }

    async fn start_test_proxy(upstream_port: u16) -> u16 {
        firewall_core::init().ok(); // Ignore if already init
        
        static METRICS: std::sync::OnceLock<metrics_exporter_prometheus::PrometheusHandle> = std::sync::OnceLock::new();
        let handle = METRICS.get_or_init(|| {
            metrics_exporter_prometheus::PrometheusBuilder::new().install_recorder().expect("Failed to install")
        });
        
        let state = Arc::new(crate::AppState {
            http_client: reqwest::Client::new(),
            upstream_url: format!("http://127.0.0.1:{}", upstream_port),
            api_key: "dummy".to_string(),
            metrics_handle: handle.clone(),
        });

        let app = Router::new()
            .route("/v1/chat/completions", post(handle_streaming_chat_completion))
            .with_state(state);

        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => panic!("Failed to bind proxy server: {}", e),
        };
        let port = match listener.local_addr() {
            Ok(addr) => addr.port(),
            Err(e) => panic!("Failed to get proxy port: {}", e),
        };
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                eprintln!("Proxy server error: {}", e);
            }
        });
        port
    }

    #[tokio::test]
    async fn sse_parser_handles_split_frames() {
        // Just tests the extraction logic (already covered by test_extract_sse_content basically,
        // but we can test edge case string split over frames)
        let text = "data: {\"choices\":[{\"delta\":{\"content\":\"spl\"}}]}\ndata: {\"choices\":[{\"delta\":{\"content\":\"it\"}}]}\n";
        assert_eq!(extract_sse_content(text), "split");
    }

    #[tokio::test]
    async fn streaming_handler_blocks_mid_stream() {
        let app = Router::new().route("/v1/chat/completions", post(|| async {
            println!("MOCK UPSTREAM: Received request");
            // Stream chunks: first clean, then PII split across two
            let stream = futures_util::stream::iter(vec![
                Ok::<_, axum::Error>(axum::body::Bytes::from("data: {\"choices\":[{\"delta\":{\"content\":\"Initial safe chunk. \"}}]}\n\n")),
                Ok::<_, axum::Error>(axum::body::Bytes::from("data: {\"choices\":[{\"delta\":{\"content\":\"Matching: sk-pr\"}}]}\n\n")),
                Ok::<_, axum::Error>(axum::body::Bytes::from("oj-12345\"}}]}\n\n")),
                Ok::<_, axum::Error>(axum::body::Bytes::from("data: [DONE]\n\n")),
            ]);
            let body = axum::body::Body::from_stream(stream);
            Response::builder()
                .header("content-type", "text/event-stream")
                .body(body)
                .unwrap()
        }));
        let upstream_port = start_mock_server(app).await;

        let proxy_port = start_test_proxy(upstream_port).await;

        let client = reqwest::Client::new();
        let resp = client.post(format!("http://127.0.0.1:{}/v1/chat/completions", proxy_port))
            .json(&json!({
                "stream": true,
                "messages": [{"role": "user", "content": "hello"}]
            }))
            .send().await.unwrap();

        // Should start successfully
        assert_eq!(resp.status(), 200);
        
        let mut collected = String::new();
        let mut stream = resp.bytes_stream();
        let mut got_error = false;
        
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(c) => {
                    let s = String::from_utf8_lossy(&c);
                    println!("TEST CLIENT: Received chunk: {:?}", s);
                    collected.push_str(&s);
                    if s.contains("policy-gate egress block") {
                        got_error = true;
                    }
                }
                Err(e) => {
                    println!("TEST CLIENT: Stream error (expected): {}", e);
                    break;
                }
            }
        }
        
        assert!(got_error, "Should have received an error event mid-stream. Collected: {}", collected);
        // "sk-" is EGRESS-SF-010 and comes before "sk-proj-" in scanner patterns.
        assert!(collected.contains("EGRESS-SF-010"), "Should contain EGRESS-SF-010. Collected: {}", collected);
    }

    #[tokio::test]
    async fn streaming_handler_pass_clean_response() {
        let app = Router::new().route("/v1/chat/completions", post(|| async {
            let stream = futures_util::stream::iter(vec![
                Ok::<_, axum::Error>(axum::body::Bytes::from("data: {\"choices\":[{\"delta\":{\"content\":\"Hello \"}}]}\n\n")),
                Ok::<_, axum::Error>(axum::body::Bytes::from("data: {\"choices\":[{\"delta\":{\"content\":\"World\"}}]}\n\n")),
                Ok::<_, axum::Error>(axum::body::Bytes::from("data: [DONE]\n\n")),
            ]);
            let body = axum::body::Body::from_stream(stream);
            Response::builder()
                .header("content-type", "text/event-stream")
                .body(body)
                .unwrap()
        }));
        let upstream_port = start_mock_server(app).await;

        let proxy_port = start_test_proxy(upstream_port).await;

        let client = reqwest::Client::new();
        let resp = client.post(format!("http://127.0.0.1:{}/v1/chat/completions", proxy_port))
            .json(&json!({
                "stream": true,
                "messages": [{"role": "user", "content": "hello"}]
            }))
            .send().await.unwrap();

        assert_eq!(resp.status(), 200);
        let mut collected = String::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(chunk) => {
                    collected.push_str(&String::from_utf8_lossy(&chunk));
                }
                Err(e) => {
                    eprintln!("Stream decode error: {}", e);
                    break;
                }
            }
        }
        
        assert!(collected.contains("Hello "));
        assert!(collected.contains("World"));
        assert!(collected.contains("[DONE]"));
        assert!(!collected.contains("error"));
    }
}
