//! Control Plane Tools Scanner
//! 
//! Priority: HIGH
//! 
//! Checks:
//! - gateway tool accessible
//! - cron tool accessible
//! - sessions_spawn accessible
//! - sessions_send accessible
//!
//! This scanner verifies that dangerous control plane tools are properly restricted

use crate::config::OpenClawConfig;
use crate::models::{Finding, Severity};
use crate::scanner::Scanner;

pub struct ControlPlaneScanner;

impl Scanner for ControlPlaneScanner {
    fn name(&self) -> &str {
        "control_plane"
    }

    fn description(&self) -> &str {
        "Control plane tools access control"
    }

    fn scan(&self, config: &OpenClawConfig) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Check tools.deny for control plane tools
        let empty_deny: Vec<String> = Vec::new();
        let deny_list = config.tools.deny.as_deref().unwrap_or(&empty_deny);
        
        let control_tools = vec![
            ("gateway", "Gateway tool - can modify config, run updates"),
            ("cron", "Cron tool - can schedule jobs"),
            ("sessions_spawn", "Sessions spawn - can create subagents"),
            ("sessions_send", "Sessions send - can send cross-session messages"),
        ];

        for (tool_name, description) in control_tools {
            if !deny_list.contains(&tool_name.to_string()) {
                findings.push(Finding::new(
                    &format!("control_plane.{}_not_denied", tool_name),
                    self.name(),
                    Severity::High,
                    &format!("Tool '{}' Not in Deny List", tool_name),
                    description,
                    "Agent can use this powerful tool",
                    &format!("Add '{}' to tools.deny", tool_name),
                    "tools.deny",
                ));
            }
        }

        // Check if profile allows all tools
        if let Some(profile) = &config.tools.profile {
            if profile == "admin" || profile == "full" || profile == "*" {
                findings.push(Finding::new(
                    "control_plane.unrestricted_profile",
                    self.name(),
                    Severity::Critical,
                    "Unrestricted Tool Profile",
                    &format!("Tools profile is '{}' - allows all tools", profile),
                    "No tool restrictions in place",
                    "Use a restricted profile or explicitly deny dangerous tools",
                    "tools.profile",
                ));
            }
        }

        findings
    }
}
