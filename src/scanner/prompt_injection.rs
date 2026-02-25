//! Prompt Injection Chain Detector
//!
//! Priority: MEDIUM
//!
//! Philosophy: Prompt injection alone is NOT a vulnerability. We only flag
//! chains that lead to actual bypass (injection -> tool -> exfil)
//!
//! Checks:
//! - Direct instruction override + tool enablement
//! - Context poisoning via web content + tool access
//! - Multi-turn manipulation + session data access
//! - Memory injection + memory backend exposure

use crate::config::OpenClawConfig;
use crate::models::{Finding, Severity};
use crate::scanner::Scanner;

pub struct PromptInjectionScanner;

impl Scanner for PromptInjectionScanner {
    fn name(&self) -> &str {
        "prompt_injection"
    }

    fn description(&self) -> &str {
        "Prompt injection chain detection"
    }

    fn scan(&self, config: &OpenClawConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        // NOTE: This is a configuration-based scanner. True prompt injection
        // detection would require runtime analysis. Here we detect configurations
        // that make injection more dangerous.

        // Check: Sandbox disabled + web tools enabled = injection more dangerous
        if config.sandbox.mode.as_deref() == Some("off") {
            let has_web_tools = config.tools.web_fetch_ssrf_policy.is_some()
                || config.tools.web_search_ssrf_policy.is_some();

            if has_web_tools {
                findings.push(Finding::new(
                    "injection.sandbox_off_plus_web",
                    self.name(),
                    Severity::Medium,
                    "Sandbox Disabled with Web Tools",
                    "Sandbox is off and web tools are enabled",
                    "Prompt injection could lead to SSRF via web content",
                    "Enable sandbox or disable web tools",
                    "agents.defaults.sandbox.mode + tools.webFetch",
                ));
            }
        }

        // Check: No workspace isolation + exec = file-based injection risk
        if config.sandbox.workspace_access.as_deref() != Some("none")
            && config.tools.exec_host.is_some()
        {
            findings.push(Finding::new(
                "injection.workspace_plus_exec",
                self.name(),
                Severity::Medium,
                "Workspace Access with Exec Enabled",
                "Sandbox has workspace access and exec is enabled",
                "Injected content could be executed",
                "Restrict workspace access or disable exec",
                "agents.defaults.sandbox.workspaceAccess + tools.exec.host",
            ));
        }

        // Check: sessions_spawn not denied + memory access = session hijacking path
        let empty_deny: Vec<String> = Vec::new();
        let deny_list = config.tools.deny.as_deref().unwrap_or(&empty_deny);
        if !deny_list.contains(&"sessions_spawn".to_string()) && config.raw.get("memory").is_some()
        {
            findings.push(Finding::new(
                "injection.sessions_spawn_plus_memory",
                self.name(),
                Severity::Medium,
                "Session Spawn + Memory Access",
                "Can spawn new sessions and has memory access",
                "Could inject persistent instructions into memory",
                "Deny sessions_spawn tool or restrict memory access",
                "tools.deny + memory",
            ));
        }

        // This is informational - we're NOT flagging prompt injection itself
        // as that's expected behavior for AI assistants
        findings.push(Finding::new(
            "injection.info",
            self.name(),
            Severity::Info,
            "Prompt Injection Detection Informational",
            "This scanner detects configuration paths that could amplify injection impact, not injection itself",
            "Prompt injection alone is expected behavior - we only flag chains to bypass",
            "See docs for hardening guidance",
            "N/A",
        ));

        findings
    }
}
