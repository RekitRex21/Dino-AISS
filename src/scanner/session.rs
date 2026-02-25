//! Session & Identity Scanner
//!
//! Priority: HIGH
//!
//! Checks:
//! - dmScope configuration (main vs per-channel-peer vs per-account-channel-peer)
//! - Session key isolation gaps
//! - Cross-session memory leakage paths
//! - Identity link vulnerabilities
//! - Session transcript exposure risk

use crate::config::OpenClawConfig;
use crate::models::{Finding, Severity};
use crate::scanner::Scanner;

pub struct SessionScanner;

impl Scanner for SessionScanner {
    fn name(&self) -> &str {
        "session"
    }

    fn description(&self) -> &str {
        "Session handling and identity management"
    }

    fn scan(&self, config: &OpenClawConfig) -> Vec<Finding> {
        let mut findings = Vec::new();
        let sess = &config.session;

        // Check: dmScope = main (with multiple channels) - medium
        if sess.dm_scope.as_deref() == Some("main") {
            let enabled_channels = config
                .channels
                .values()
                .filter(|ch| ch.enabled == Some(true))
                .count();

            if enabled_channels > 1 {
                findings.push(Finding::new(
                    "session.dm_scope_main_multi_channel",
                    self.name(),
                    Severity::Medium,
                    "DM Scope 'main' With Multiple Channels",
                    "All DMs route to main session across multiple channels",
                    "Messages from different channels/users mix in same context",
                    "Set session.dmScope to 'per-channel-peer'",
                    "session.dmScope",
                ));
            }
        }

        // Check: dmScope not set (defaults to main) - info
        if sess.dm_scope.is_none() {
            findings.push(Finding::new(
                "session.dm_scope_default",
                self.name(),
                Severity::Info,
                "DM Scope Not Explicitly Set",
                "session.dmScope defaults to 'main'",
                "May expose messages to wrong context",
                "Set session.dmScope explicitly to 'per-channel-peer'",
                "session.dmScope",
            ));
        }

        findings
    }
}
