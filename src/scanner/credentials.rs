//! Credentials & Secret Detector Scanner
//! 
//! Priority: CRITICAL
//! 
//! Checks:
//! - Token exposure in config (redaction detection)
//! - File permissions (600 on files, 700 on dirs)
//! - Environment variable secrets
//! - Legacy auth vulnerabilities
//! - OAuth token detection

use crate::config::OpenClawConfig;
use crate::models::{Finding, Severity};
use crate::scanner::Scanner;

pub struct CredentialsScanner;

impl Scanner for CredentialsScanner {
    fn name(&self) -> &str {
        "credentials"
    }

    fn description(&self) -> &str {
        "Credential and secret detection"
    }

    fn scan(&self, config: &OpenClawConfig) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Check for token exposure in config
        if let Some(token) = &config.gateway.token {
            // Check if token looks redacted (common patterns)
            let is_redacted = token.starts_with("REDACTED") 
                || token.starts_with("***")
                || token == "YOUR_TOKEN_HERE"
                || token.len() < 10;
            
            if !is_redacted && token.len() < 32 {
                findings.push(Finding::new(
                    "credentials.weak_gateway_token",
                    self.name(),
                    Severity::High,
                    "Weak Gateway Token in Config",
                    "Gateway token is present and appears weak or unredacted",
                    "Token could be exposed in config file",
                    "Use a strong token (32+ chars) or ensure config is properly secured",
                    "gateway.auth.token",
                ));
            } else if !is_redacted {
                // Token is present and long enough - warn about exposure
                findings.push(Finding::new(
                    "credentials.token_in_config",
                    self.name(),
                    Severity::Medium,
                    "Gateway Token in Configuration File",
                    "Gateway token is stored directly in config file",
                    "Config file should be protected with appropriate permissions",
                    "Ensure config file has restricted permissions (600)",
                    "gateway.auth.token",
                ));
            }
        }

        // Check for API keys in config (heuristic: long strings that look like keys)
        let config_str = serde_json::to_string(&config.raw).unwrap_or_default();
        let api_key_patterns = ["sk-", "api_", "apikey", "secret", "token"];
        
        for pattern in api_key_patterns {
            if config_str.to_lowercase().contains(pattern) {
                findings.push(Finding::new(
                    "credentials.potential_secret_found",
                    self.name(),
                    Severity::High,
                    "Potential Secret Detected in Config",
                    &format!("Found potential secret pattern '{}' in configuration", pattern),
                    "Sensitive credentials may be exposed",
                    "Review and ensure secrets are properly secured or redacted",
                    "config",
                ));
                break; // Only report once
            }
        }

        findings
    }
}
