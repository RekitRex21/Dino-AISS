//! Node Security Scanner
//! 
//! Priority: HIGH
//! 
//! Checks:
//! - Node pairing security
//! - Command allowlist exposure
//! - Sensitive command access (camera/screen/SMS)
//! - System run permissions
//!
//! Note: This scanner checks for node-related configurations in the raw config

use crate::config::OpenClawConfig;
use crate::models::{Finding, Severity};
use crate::scanner::Scanner;

pub struct NodeScanner;

impl Scanner for NodeScanner {
    fn name(&self) -> &str {
        "nodes"
    }

    fn description(&self) -> &str {
        "Paired node and remote execution security"
    }

    fn scan(&self, config: &OpenClawConfig) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Check for nodes configuration in raw config
        if let Some(nodes) = config.raw.get("nodes").and_then(|v| v.as_object()) {
            // Check if any node has sensitive permissions
            for (node_name, node_config) in nodes {
                if let Some(node_obj) = node_config.as_object() {
                    // Check for unrestricted command access
                    if let Some(allow_commands) = node_obj.get("allowCommands") {
                        if allow_commands.is_array() {
                            let commands = allow_commands.as_array().unwrap();
                            // Check for wildcards or dangerous commands
                            for cmd in commands {
                                if let Some(cmd_str) = cmd.as_str() {
                                    if cmd_str == "*" || cmd_str == "all" {
                                        findings.push(Finding::new(
                                            &format!("nodes.{}.unrestricted_commands", node_name),
                                            self.name(),
                                            Severity::Critical,
                                            &format!("Node '{}' Has Unrestricted Commands", node_name),
                                            &format!("Node '{}' allows all commands (*)", node_name),
                                            "Any command can be executed on the node",
                                            "Restrict allowCommands to specific needed commands",
                                            &format!("nodes.{}.allowCommands", node_name),
                                        ));
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    // Check for sensitive capabilities
                    let sensitive_caps = ["camera", "screen", "contacts", "sms", "location"];
                    let mut has_sensitive = Vec::new();
                    
                    if let Some(caps) = node_obj.get("capabilities").and_then(|v| v.as_array()) {
                        for cap in caps {
                            if let Some(cap_str) = cap.as_str() {
                                if sensitive_caps.contains(&cap_str) {
                                    has_sensitive.push(cap_str);
                                }
                            }
                        }
                    }

                    if !has_sensitive.is_empty() {
                        findings.push(Finding::new(
                            &format!("nodes.{}.sensitive_capabilities", node_name),
                            self.name(),
                            Severity::Medium,
                            &format!("Node '{}' Has Sensitive Capabilities", node_name),
                            &format!("Node '{}' has access to: {}", node_name, has_sensitive.join(", ")),
                            "Node can access sensitive device features",
                            "Review if these capabilities are necessary",
                            &format!("nodes.{}.capabilities", node_name),
                        ));
                    }
                }
            }
        }

        // Check for exec on nodes
        if let Some(tools) = config.raw.get("tools").and_then(|v| v.as_object()) {
            if let Some(exec_config) = tools.get("exec").and_then(|v| v.as_object()) {
                if exec_config.get("allowNodeExec") == Some(&serde_json::Value::Bool(true)) {
                    findings.push(Finding::new(
                        "nodes.exec_allowed",
                        self.name(),
                        Severity::High,
                        "Node Execution Enabled",
                        "Tools are allowed to execute commands on paired nodes",
                        "Commands can be run on remote nodes",
                        "Disable allowNodeExec unless strictly needed",
                        "tools.exec.allowNodeExec",
                    ));
                }
            }
        }

        findings
    }
}
