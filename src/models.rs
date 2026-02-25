//! Core data structures for Dino-AISS

use serde::{Deserialize, Serialize};

/// OpenClaw-aligned severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn score(&self) -> i32 {
        match self {
            Severity::Critical => -25,
            Severity::High => -15,
            Severity::Medium => -10,
            Severity::Low => -5,
            Severity::Info => -2,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

/// A security finding from a scanner module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub module: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub impact: String,
    pub remediation: String,
    pub config_path: String,
    #[serde(default)]
    pub openclaw_aligned: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cve: Option<String>,
}

impl Finding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: &str,
        module: &str,
        severity: Severity,
        title: &str,
        description: &str,
        impact: &str,
        remediation: &str,
        config_path: &str,
    ) -> Self {
        Self {
            id: id.to_string(),
            module: module.to_string(),
            severity,
            title: title.to_string(),
            description: description.to_string(),
            impact: impact.to_string(),
            remediation: remediation.to_string(),
            config_path: config_path.to_string(),
            openclaw_aligned: true,
            cve: None,
        }
    }

    pub fn with_cve(mut self, cve: &str) -> Self {
        self.cve = Some(cve.to_string());
        self
    }
}

/// Result of a full security scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub health_score: i32,
    pub scan_time_seconds: f64,
}

impl ScanResult {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            health_score: 100,
            scan_time_seconds: 0.0,
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        self.health_score += finding.severity.score();
        self.health_score = self.health_score.clamp(0, 100);
        self.findings.push(finding);
    }

    pub fn critical_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count()
    }

    pub fn high_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count()
    }
}

impl Default for ScanResult {
    fn default() -> Self {
        Self::new()
    }
}
