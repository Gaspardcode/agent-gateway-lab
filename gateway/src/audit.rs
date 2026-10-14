//! Une ligne JSON par requête sur stdout, envoyée à CloudWatch Logs par le
//! pilote awslogs de Docker. Les booléens à plat servent aux filtres de
//! métriques CloudWatch (`{ $.exfil IS TRUE }`).

use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::policy::{Category, Finding, Mode};

#[derive(Debug, Serialize)]
pub struct AuditEvent {
    pub event: &'static str,
    pub ts_ms: u128,
    pub request_id: String,
    pub client: Option<String>,
    pub mode: Mode,
    /// allow | block | would_block | redact | deny | error
    pub decision: &'static str,
    pub status: u16,
    pub rules: Vec<&'static str>,
    pub injection: bool,
    pub exfil: bool,
    pub tool_violation: bool,
    pub tainted: bool,
    pub rate_limited: bool,
    pub auth_fail: bool,
    pub tools_called: Vec<String>,
    pub findings: Vec<Finding>,
    pub latency_ms: u128,
    pub upstream_ms: Option<u128>,
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
}

impl AuditEvent {
    pub fn new(request_id: String, client: Option<String>, mode: Mode) -> Self {
        Self {
            event: "chat",
            ts_ms: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0),
            request_id,
            client,
            mode,
            decision: "allow",
            status: 200,
            rules: vec![],
            injection: false,
            exfil: false,
            tool_violation: false,
            tainted: false,
            rate_limited: false,
            auth_fail: false,
            tools_called: vec![],
            findings: vec![],
            latency_ms: 0,
            upstream_ms: None,
            prompt_tokens: None,
            completion_tokens: None,
        }
    }

    pub fn add(&mut self, findings: impl IntoIterator<Item = Finding>) {
        for f in findings {
            match f.category {
                Category::Injection => self.injection = true,
                Category::Exfiltration => self.exfil = true,
                Category::ToolViolation => self.tool_violation = true,
            }
            if !self.rules.contains(&f.rule) {
                self.rules.push(f.rule);
            }
            self.findings.push(f);
        }
    }

    pub fn emit(&self) {
        if let Ok(line) = serde_json::to_string(self) {
            println!("{line}");
        }
    }
}
