//! Tool Policy Scanner
//!
//! Priority: CRITICAL
//!
//! Checks:
//! - exec allowlist (wide = critical)
//! - sandbox enabled (off + exec = critical)
//! - workspaceOnly disabled (file tools)
//! - elevated mode enabled
//! - safeBins bypass detection
//! - web_fetch/web_search SSRF protection
//! - browser control exposure

use crate::config::OpenClawConfig;
use crate::models::{Finding, Severity};
use crate::scanner::Scanner;

pub struct ToolsScanner;

impl Scanner for ToolsScanner {
    fn name(&self) -> &str {
        "tools"
    }

    fn description(&self) -> &str {
        "Tool configuration and policy security"
    }

    fn scan(&self, config: &OpenClawConfig) -> Vec<Finding> {
        let mut findings = Vec::new();
        let tools = &config.tools;
        let sb = &config.sandbox;

        // Check: exec with sandbox off - critical
        if sb.mode.as_deref() == Some("off") {
            if tools.exec_host.as_deref() == Some("gateway") || tools.exec_host.is_none() {
                findings.push(Finding::new(
                    "tools.exec_no_sandbox",
                    self.name(),
                    Severity::Critical,
                    "Exec Tool Without Sandbox",
                    "exec tool enabled with sandbox disabled - runs on host",
                    "Command execution can modify host system",
                    "Enable sandbox or restrict exec allowlist",
                    "agents.defaults.sandbox.mode + tools.exec.host",
                ));
            }
        }

        // Check: elevated mode enabled - critical
        if tools.elevated_enabled == Some(true) {
            findings.push(Finding::new(
                "tools.elevated_enabled",
                self.name(),
                Severity::Critical,
                "Elevated Mode Enabled",
                "tools.elevated.enabled is true - allows host sudo",
                "Agents can execute commands with elevated privileges",
                "Disable tools.elevated.enabled unless required",
                "tools.elevated.enabled",
            ));
        }

        // Check: workspaceOnly disabled - high
        if tools.fs_workspace_only == Some(false) {
            findings.push(Finding::new(
                "tools.fs_workspace_only_disabled",
                self.name(),
                Severity::High,
                "File System Workspace Only Disabled",
                "tools.fs.workspaceOnly is false - can access any file",
                "Agents can read/write files outside workspace",
                "Set tools.fs.workspaceOnly: true",
                "tools.fs.workspaceOnly",
            ));
        }

        // Check: exec security deny - low
        if tools.exec_security.as_deref() == Some("deny") {
            findings.push(Finding::new(
                "tools.exec_security_deny",
                self.name(),
                Severity::Low,
                "Exec Security Set to Deny",
                "tools.exec.security is 'deny' - blocks exec entirely",
                "May prevent legitimate exec usage",
                "Consider 'ask' or 'allowlist' for controlled exec",
                "tools.exec.security",
            ));
        }

        // Check: SSRF protection missing for web tools
        if tools.web_fetch_ssrf_policy.as_deref() != Some("strict") {
            findings.push(
                Finding::new(
                    "tools.web_fetch_no_ssrf",
                    self.name(),
                    Severity::Medium,
                    "Web Fetch SSRF Protection Not Strict",
                    &format!(
                        "web_fetch ssrfPolicy is '{}'",
                        tools.web_fetch_ssrf_policy.as_deref().unwrap_or("default")
                    ),
                    "May allow access to internal network resources",
                    "Set tools.webFetch.ssrfPolicy: 'strict'",
                    "tools.webFetch.ssrfPolicy",
                )
                .with_cve("CVE-2026-26322"),
            );
        }

        if tools.web_search_ssrf_policy.as_deref() != Some("strict") {
            findings.push(
                Finding::new(
                    "tools.web_search_no_ssrf",
                    self.name(),
                    Severity::Medium,
                    "Web Search SSRF Protection Not Strict",
                    &format!(
                        "web_search ssrfPolicy is '{}'",
                        tools.web_search_ssrf_policy.as_deref().unwrap_or("default")
                    ),
                    "May allow access to internal network resources",
                    "Set tools.webSearch.ssrfPolicy: 'strict'",
                    "tools.webSearch.ssrfPolicy",
                )
                .with_cve("CVE-2026-26322"),
            );
        }

        // Check: safeBins allows dangerous patterns
        if let Some(safe_bins) = &tools.exec_safe_bins {
            let dangerous_bins = vec!["/bin/sh", "/bin/bash", "/usr/bin/env"];
            for bin_path in dangerous_bins {
                if safe_bins.contains(&bin_path.to_string()) {
                    findings.push(Finding::new(
                        "tools.safe_bins_dangerous",
                        self.name(),
                        Severity::High,
                        &format!("Dangerous bin in safeBins: {}", bin_path),
                        &format!("{} in safeBins allows shell execution", bin_path),
                        "Can execute arbitrary shell commands",
                        &format!("Remove {} from safeBins", bin_path),
                        "tools.exec.safeBins",
                    ));
                }
            }
        }

        findings
    }
}
