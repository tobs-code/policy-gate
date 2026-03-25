// session.rs — SA-076: Session-Aware-Layer for Multi-Turn Conversation Memory
//
// Addresses the fundamental limitation of stateless design: inability to detect
// multi-turn escalation attacks and payload fragmentation across conversation turns.
//
// This layer maintains a sliding window of recent messages per session and provides
// cross-turn analytics while preserving the core firewall's stateless safety guarantees.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use crate::types::{PromptInput, VerdictKind, BlockReason};

/// Session context for multi-turn conversation memory.
#[derive(Debug, Clone)]
pub struct SessionContext {
    pub session_id: String,
    pub messages: Vec<SessionMessage>,
    pub created_at_ns: u128,
    pub last_activity_ns: u128,
    pub escalation_score: u8,
    pub fragmentation_detected: bool,
}

/// Individual message in session context.
#[derive(Debug, Clone)]
pub struct SessionMessage {
    pub sequence: u64,
    pub timestamp_ns: u128,
    pub input_hash: String,
    pub verdict: VerdictKind,
    pub block_reason: Option<BlockReason>,
    pub escalation_indicators: Vec<EscalationIndicator>,
}

/// Escalation indicators detected in message analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscalationIndicator {
    /// Gradual increase in complexity or specificity
    ComplexityEscalation,
    /// Shift from general to sensitive topics
    TopicDrift,
    /// Attempt to bypass previous restrictions
    PolicyTesting,
    /// Repeated similar prompts with minor variations
    RepetitionWithVariation,
    /// Fragmented payload across multiple turns
    PayloadFragmentation,
}

/// Session manager for multi-turn conversation memory.
pub struct SessionManager {
    /// Session storage: session_id -> SessionContext
    sessions: Arc<Mutex<HashMap<String, SessionContext>>>,
    /// Maximum messages to keep per session (sliding window)
    max_messages: usize,
    /// Session timeout in nanoseconds
    session_timeout_ns: u128,
}

impl SessionManager {
    /// Create new session manager with default configuration.
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            max_messages: 10, // Keep last 10 messages per session
            session_timeout_ns: Duration::from_secs(3600).as_nanos(), // 1 hour
        }
    }

    /// Create session manager with custom configuration.
    pub fn with_config(max_messages: usize, timeout_minutes: u64) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            max_messages,
            session_timeout_ns: Duration::from_secs(timeout_minutes * 60).as_nanos(),
        }
    }

    /// Add message to session context and analyze for escalation patterns.
    pub fn add_message(&self, session_id: &str, input: &PromptInput, verdict: VerdictKind, block_reason: Option<BlockReason>) -> SessionAnalysis {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos();

        let mut sessions = self.sessions.lock().unwrap();
        
        // Get or create session
        let session = sessions.entry(session_id.to_string()).or_insert_with(|| SessionContext {
            session_id: session_id.to_string(),
            messages: Vec::new(),
            created_at_ns: now,
            last_activity_ns: now,
            escalation_score: 0,
            fragmentation_detected: false,
        });

        // Update activity timestamp
        session.last_activity_ns = now;

        // Create session message
        let message = SessionMessage {
            sequence: session.messages.len() as u64 + 1,
            timestamp_ns: now,
            input_hash: crate::sha256_hex(&input.text),
            verdict,
            block_reason,
            escalation_indicators: self.analyze_message_indicators(&input.text, &session.messages),
        };

        // Add to session (maintain sliding window)
        session.messages.push(message.clone());
        if session.messages.len() > self.max_messages {
            session.messages.remove(0);
        }

        // Update escalation metrics
        self.update_session_metrics(session);

        // Generate analysis
        self.generate_analysis(session, &message)
    }

    /// Analyze individual message for escalation indicators.
    fn analyze_message_indicators(&self, text: &str, previous_messages: &[SessionMessage]) -> Vec<EscalationIndicator> {
        let mut indicators = Vec::new();

        // Check for complexity escalation
        if self.is_complexity_escalation(text, previous_messages) {
            indicators.push(EscalationIndicator::ComplexityEscalation);
        }

        // Check for topic drift
        if self.is_topic_drift(text, previous_messages) {
            indicators.push(EscalationIndicator::TopicDrift);
        }

        // Check for policy testing
        if self.is_policy_testing(text, previous_messages) {
            indicators.push(EscalationIndicator::PolicyTesting);
        }

        // Check for repetition with variation
        if self.is_repetition_with_variation(text, previous_messages) {
            indicators.push(EscalationIndicator::RepetitionWithVariation);
        }

        // Check for payload fragmentation
        if self.is_payload_fragmentation(text, previous_messages) {
            indicators.push(EscalationIndicator::PayloadFragmentation);
        }

        indicators
    }

    /// Update session-level escalation metrics.
    fn update_session_metrics(&self, session: &mut SessionContext) {
        // Count escalation indicators in recent messages
        let recent_indicators: usize = session.messages
            .iter()
            .map(|msg| msg.escalation_indicators.len())
            .sum();

        // Calculate escalation score (0-255, capped at 100)
        session.escalation_score = (recent_indicators * 10).min(100) as u8;

        // Detect fragmentation patterns
        session.fragmentation_detected = session.messages
            .iter()
            .any(|msg| msg.escalation_indicators.contains(&EscalationIndicator::PayloadFragmentation));
    }

    /// Generate session analysis with recommendations.
    fn generate_analysis(&self, session: &SessionContext, current_message: &SessionMessage) -> SessionAnalysis {
        let mut flags = Vec::new();

        // High escalation score
        if session.escalation_score >= 70 {
            flags.push(SessionFlag::HighEscalationScore);
        }

        // Fragmentation detected
        if session.fragmentation_detected {
            flags.push(SessionFlag::FragmentationDetected);
        }

        // Rapid escalation (score increased significantly in last 3 messages)
        if self.is_rapid_escalation(session) {
            flags.push(SessionFlag::RapidEscalation);
        }

        // Long session (potential for sophisticated attacks)
        if session.messages.len() >= 8 {
            flags.push(SessionFlag::LongSession);
        }

        // Determine risk level
        let risk_level = match flags.len() {
            0 => SessionRiskLevel::Low,
            1..=2 => SessionRiskLevel::Medium,
            _ => SessionRiskLevel::High,
        };

        SessionAnalysis {
            session_id: session.session_id.clone(),
            message_sequence: current_message.sequence,
            escalation_score: session.escalation_score,
            risk_level: risk_level.clone(),
            message_count: session.messages.len(),
            session_duration_ns: session.last_activity_ns - session.created_at_ns,
            recommendations: self.generate_recommendations(&flags, risk_level.clone()),
            flags,
        }
    }

    /// Clean up expired sessions.
    pub fn cleanup_expired_sessions(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos();

        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, session| {
            now - session.last_activity_ns < self.session_timeout_ns
        });
    }

    /// Get session statistics for monitoring.
    pub fn get_stats(&self) -> SessionStats {
        let sessions = self.sessions.lock().unwrap();
        let total_sessions = sessions.len();
        let active_sessions = sessions.values()
            .filter(|s| s.escalation_score > 0)
            .count();
        let high_risk_sessions = sessions.values()
            .filter(|s| s.escalation_score >= 70)
            .count();

        SessionStats {
            total_sessions,
            active_sessions,
            high_risk_sessions,
        }
    }

    // Private helper methods for escalation detection
    fn is_complexity_escalation(&self, text: &str, previous_messages: &[SessionMessage]) -> bool {
        if previous_messages.is_empty() {
            return false;
        }

        // Simple heuristic: check for increasing sentence length and complexity
        let avg_prev_length: usize = previous_messages
            .iter()
            .take(3) // Last 3 messages
            .map(|msg| {
                // This would need the original text - using hash as proxy
                msg.input_hash.len() // Rough proxy for complexity
            })
            .sum::<usize>() / previous_messages.len().min(3).max(1);

        let current_length = text.len();
        current_length > avg_prev_length * 2 // Double the average length
    }

    fn is_topic_drift(&self, _text: &str, _previous_messages: &[SessionMessage]) -> bool {
        // TODO: Implement topic modeling or keyword analysis
        // For now, placeholder implementation
        false
    }

    fn is_policy_testing(&self, text: &str, previous_messages: &[SessionMessage]) -> bool {
        if previous_messages.is_empty() {
            return false;
        }

        // Check for variations of similar prompts
        let _current_words: Vec<&str> = text.split_whitespace().collect();
        
        for msg in previous_messages.iter().take(3) {
            // Simple similarity check based on hash patterns
            // In production, this would use proper text similarity
            if msg.input_hash.len() > 10 && text.len() > 10 {
                // Heuristic: similar length but different content
                let length_diff = (text.len() as i32 - msg.input_hash.len() as i32).abs();
                if length_diff < 20 && text != msg.input_hash {
                    return true;
                }
            }
        }

        false
    }

    fn is_repetition_with_variation(&self, text: &str, previous_messages: &[SessionMessage]) -> bool {
        if previous_messages.len() < 2 {
            return false;
        }

        // Check if current message is similar to previous ones with small changes
        let current_words: std::collections::HashSet<&str> = text.split_whitespace().collect();
        
        for msg in previous_messages.iter().take(3).skip(1) {
            // Simple overlap check
            let prev_hash_words: std::collections::HashSet<&str> = msg.input_hash.split_whitespace().collect();
            let overlap = current_words.intersection(&prev_hash_words).count();
            
            if overlap > current_words.len() / 2 && overlap < current_words.len() {
                return true; // Significant overlap but not identical
            }
        }

        false
    }

    fn is_payload_fragmentation(&self, text: &str, previous_messages: &[SessionMessage]) -> bool {
        if previous_messages.is_empty() {
            return false;
        }

        // Check for incomplete sentences or fragments that might be combined
        let ends_with_punctuation = text.trim_end().ends_with('.') || 
                                  text.trim_end().ends_with('!') || 
                                  text.trim_end().ends_with('?');

        if !ends_with_punctuation && text.len() < 100 {
            // Short, incomplete sentence might be a fragment
            return true;
        }

        // Check for continuation patterns
        let continuation_indicators = ["and then", "after that", "next", "finally"];
        for indicator in &continuation_indicators {
            if text.to_lowercase().contains(indicator) {
                return true;
            }
        }

        false
    }

    fn is_rapid_escalation(&self, session: &SessionContext) -> bool {
        if session.messages.len() < 3 {
            return false;
        }

        // Check if escalation score increased rapidly in last 3 messages
        let recent_messages: Vec<_> = session.messages.iter().rev().take(3).collect();
        let recent_indicators: usize = recent_messages
            .iter()
            .map(|msg| msg.escalation_indicators.len())
            .sum();

        recent_indicators >= 3 // 3+ indicators in last 3 messages
    }

    fn generate_recommendations(&self, flags: &[SessionFlag], risk_level: SessionRiskLevel) -> Vec<String> {
        let mut recommendations = Vec::new();

        match risk_level {
            SessionRiskLevel::High => {
                recommendations.push("Consider session termination or human review".to_string());
                recommendations.push("Implement rate limiting for this session".to_string());
            }
            SessionRiskLevel::Medium => {
                recommendations.push("Monitor session closely for escalation".to_string());
                recommendations.push("Consider increasing scrutiny of future requests".to_string());
            }
            SessionRiskLevel::Low => {
                recommendations.push("Continue normal monitoring".to_string());
            }
        }

        for flag in flags {
            match flag {
                SessionFlag::FragmentationDetected => {
                    recommendations.push("Potential payload fragmentation detected".to_string());
                }
                SessionFlag::RapidEscalation => {
                    recommendations.push("Rapid escalation pattern detected".to_string());
                }
                SessionFlag::LongSession => {
                    recommendations.push("Long session may indicate sophisticated probing".to_string());
                }
                SessionFlag::HighEscalationScore => {
                    recommendations.push("High escalation score requires attention".to_string());
                }
            }
        }

        recommendations
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Analysis result for a message within session context.
#[derive(Debug, Clone)]
pub struct SessionAnalysis {
    pub session_id: String,
    pub message_sequence: u64,
    pub escalation_score: u8,
    pub risk_level: SessionRiskLevel,
    pub flags: Vec<SessionFlag>,
    pub message_count: usize,
    pub session_duration_ns: u128,
    pub recommendations: Vec<String>,
}

/// Session risk level classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionRiskLevel {
    Low,
    Medium,
    High,
}

/// Session flags indicating specific concerns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionFlag {
    HighEscalationScore,
    FragmentationDetected,
    RapidEscalation,
    LongSession,
}

/// Session statistics for monitoring.
#[derive(Debug, Clone)]
pub struct SessionStats {
    pub total_sessions: usize,
    pub active_sessions: usize,
    pub high_risk_sessions: usize,
}

// Global session manager instance
static SESSION_MANAGER: OnceLock<SessionManager> = OnceLock::new();

/// Initialize the global session manager.
pub fn init_session_manager() {
    let _ = SESSION_MANAGER.get_or_init(|| SessionManager::new());
}

/// Get the global session manager.
pub fn get_session_manager() -> Option<&'static SessionManager> {
    SESSION_MANAGER.get()
}

/// Evaluate message with session context (enhanced version of evaluate_raw).
pub fn evaluate_with_session(
    session_id: &str,
    input: &PromptInput,
    sequence: u64,
) -> crate::types::Verdict {
    // First, get the base firewall verdict
    let base_verdict = crate::evaluate_raw(&input.text, sequence);
    
    // Then, analyze with session context
    if let Some(session_manager) = get_session_manager() {
        let session_analysis = session_manager.add_message(
            session_id,
            input,
            base_verdict.kind.clone(),
            base_verdict.audit.block_reason.clone(),
        );

        // For now, session analysis is advisory only
        // In production, high-risk sessions could trigger additional safeguards
        if session_analysis.risk_level == SessionRiskLevel::High {
            // Log high-risk session for operator review
            eprintln!("Session Risk Alert: {} - Score: {}, Flags: {:?}", 
                     session_analysis.session_id, 
                     session_analysis.escalation_score,
                     session_analysis.flags);
        }
    }

    base_verdict
}