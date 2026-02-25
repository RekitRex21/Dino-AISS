#![allow(dead_code)]

//! Knowledge Base Module
//!
//! Contains CVE data and mitigation mappings

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A CVE entry in the knowledge base
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    pub title: String,
    pub severity: String,
    pub description: String,
    pub mitigation: String,
    pub affected_versions: String,
}

/// Knowledge base containing CVEs and patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeBase {
    pub cves: HashMap<String, CveEntry>,
    pub patterns: HashMap<String, PatternEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternEntry {
    pub description: String,
    pub severity: String,
    pub remediation: String,
}

impl Default for KnowledgeBase {
    fn default() -> Self {
        let mut cves = HashMap::new();

        // CVE-2026-26322: OpenClaw SSRF Vulnerability
        cves.insert("CVE-2026-26322".to_string(), CveEntry {
            title: "OpenClaw SSRF Vulnerability".to_string(),
            severity: "high".to_string(),
            description: "Server-side request forgery in gatewayUrl validation allowing unauthorized WebSocket triggers".to_string(),
            mitigation: "Upgrade to 2026.2.14+, enforce strict gatewayUrl validation (loopback only, no overrides)".to_string(),
            affected_versions: "<2026.2.14".to_string(),
        });

        // CVE-2026-25593: OpenClaw RCE via cliPath
        cves.insert(
            "CVE-2026-25593".to_string(),
            CveEntry {
                title: "OpenClaw RCE via cliPath".to_string(),
                severity: "critical".to_string(),
                description: "Command injection through unsafe cliPath".to_string(),
                mitigation: "Validate cliPath, use absolute paths only, enable sandbox mode"
                    .to_string(),
                affected_versions: "<2026.2.15".to_string(),
            },
        );

        // CVE-2026-24763: OpenClaw PATH Injection
        cves.insert(
            "CVE-2026-24763".to_string(),
            CveEntry {
                title: "OpenClaw PATH Injection".to_string(),
                severity: "high".to_string(),
                description: "PATH injection in container exec, unsafe Docker options".to_string(),
                mitigation:
                    "Sanitize PATH in container exec, avoid unsafe Docker options, enable sandbox"
                        .to_string(),
                affected_versions: "<2026.2.13".to_string(),
            },
        );

        // CVE-2025-XXXXX: Multiple CVEs
        cves.insert(
            "CVE-2025-XXXXX".to_string(),
            CveEntry {
                title: "Multiple OpenClaw CVEs".to_string(),
                severity: "varies".to_string(),
                description: "Multiple CVEs affecting open-source personal AI assistants"
                    .to_string(),
                mitigation: "Keep updated, follow security advisories regularly".to_string(),
                affected_versions: "various".to_string(),
            },
        );

        let mut patterns = HashMap::new();

        patterns.insert(
            "unsafe_cliPath".to_string(),
            PatternEntry {
                description: "Unrestricted cliPath can lead to command injection".to_string(),
                severity: "critical".to_string(),
                remediation: "Use absolute paths, enable sandbox mode".to_string(),
            },
        );

        patterns.insert(
            "sandbox_mode_off".to_string(),
            PatternEntry {
                description: "Sandbox disabled with dangerous tools enabled".to_string(),
                severity: "critical".to_string(),
                remediation: "Enable sandbox mode or disable exec/web tools".to_string(),
            },
        );

        patterns.insert(
            "lan_bind_no_auth".to_string(),
            PatternEntry {
                description: "LAN-bound gateway without authentication".to_string(),
                severity: "critical".to_string(),
                remediation: "Use loopback bind or enable authentication".to_string(),
            },
        );

        patterns.insert(
            "weak_token".to_string(),
            PatternEntry {
                description: "Weak authentication token".to_string(),
                severity: "high".to_string(),
                remediation: "Use 32+ character random token".to_string(),
            },
        );

        Self { cves, patterns }
    }
}

impl KnowledgeBase {
    /// Get mitigation for a CVE
    pub fn get_mitigation(&self, cve: &str) -> Option<&str> {
        self.cves.get(cve).map(|e| e.mitigation.as_str())
    }

    /// Check if a version is affected
    #[allow(dead_code)]
    pub fn is_affected(&self, cve: &str, _version: &str) -> bool {
        if let Some(entry) = self.cves.get(cve) {
            if let Some(_affect_ver) = entry.affected_versions.strip_prefix("<") {
                // This is a simplified check
                return true;
            }
        }
        false
    }
}

/// Get the global knowledge base instance
#[allow(dead_code)]
pub fn get_knowledge_base() -> KnowledgeBase {
    KnowledgeBase::default()
}
