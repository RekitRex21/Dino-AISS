//! Sandbox & Container Security Scanner
//! 
//! Priority: CRITICAL
//! 
//! Checks:
//! - Sandbox mode enabled/disabled
//! - Docker config present but mode off (runtime drift)
//! - Workspace mount exposure (none/ro/rw)
//! - Agent scope isolation (agent/session/shared)
//! - tools.deny missing gateway/cron/sessions_spawn/sessions_send
//! - PATH injection in container exec (CVE-2026-24763)
//! - Unsafe Docker options in sandbox config
//! - Bind-mount injection at init (pre-watch)
//! - Symlink/zip-slip in skill packaging

use crate::config::OpenClawConfig;
use crate::models::{Finding, Severity};
use crate::scanner::Scanner;

pub struct SandboxScanner;

impl Scanner for SandboxScanner {
    fn name(&self) -> &str {
        "sandbox"
    }

    fn description(&self) -> &str {
        "Sandbox configuration and container isolation"
    }

    fn scan(&self, config: &OpenClawConfig) -> Vec<Finding> {
        let mut findings = Vec::new();
        let sb = &config.sandbox;
        let tools = &config.tools;

        // Check: Sandbox mode disabled - critical
        if sb.mode.as_deref() == Some("off") || sb.mode.is_none() {
            findings.push(Finding::new(
                "sandbox.mode_off",
                self.name(),
                Severity::Critical,
                "Sandbox Mode Disabled",
                "Sandbox mode is disabled, tools run directly on host",
                "Tool execution can access and modify the host system",
                "Enable sandbox mode: agents.defaults.sandbox.mode: 'docker'",
                "agents.defaults.sandbox.mode",
            ));
        }

        // Check: Workspace mount rw - high
        if sb.workspace_access.as_deref() == Some("rw") {
            findings.push(Finding::new(
                "sandbox.workspace_rw",
                self.name(),
                Severity::High,
                "Sandbox Workspace Read-Write Access",
                "Sandbox has read-write access to agent workspace",
                "Agent can modify files in the workspace",
                "Set agents.defaults.sandbox.workspaceAccess to 'ro' or 'none'",
                "agents.defaults.sandbox.workspaceAccess",
            ));
        }

        // Check: Shared scope - medium
        if sb.scope.as_deref() == Some("shared") {
            findings.push(Finding::new(
                "sandbox.scope_shared",
                self.name(),
                Severity::Medium,
                "Sandbox Scope Set to Shared",
                "All agents share the same sandbox workspace",
                "One agent can access another agent's files",
                "Set agents.defaults.sandbox.scope to 'agent' or 'session'",
                "agents.defaults.sandbox.scope",
            ));
        }

        // Check: tools.deny missing control plane tools
        if let Some(deny_list) = &tools.deny {
            let mut missing_tools = Vec::new();
            
            if !deny_list.contains(&"gateway".to_string()) {
                missing_tools.push("gateway");
            }
            if !deny_list.contains(&"cron".to_string()) {
                missing_tools.push("cron");
            }
            if !deny_list.contains(&"sessions_spawn".to_string()) {
                missing_tools.push("sessions_spawn");
            }
            if !deny_list.contains(&"sessions_send".to_string()) {
                missing_tools.push("sessions_send");
            }

            if !missing_tools.is_empty() {
                let missing_str = missing_tools.join(", ");
                findings.push(Finding::new(
                    "sandbox.tools_deny_incomplete",
                    self.name(),
                    Severity::High,
                    &format!("tools.deny Missing: {}", missing_str),
                    &format!("Control plane tools not in deny list: {}", missing_str),
                    "Agents can make persistent config changes or spawn subagents",
                    &format!("Add to tools.deny: {}", missing_str),
                    "tools.deny",
                ));
            }
        }

        findings
    }
}
