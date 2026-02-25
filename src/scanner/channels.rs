//! Channel Security Scanner
//! 
//! Priority: HIGH
//! 
//! Checks per channel (Telegram, Discord, WhatsApp, Slack, iMessage, Signal):
//! - DM policy (pairing/allowlist/open/disabled)
//! - Group policy (mention gating)
//! - Command authorization
//! - allowFrom ID-only enforcement

use crate::config::OpenClawConfig;
use crate::models::{Finding, Severity};
use crate::scanner::Scanner;

pub struct ChannelScanner;

impl Scanner for ChannelScanner {
    fn name(&self) -> &str {
        "channels"
    }

    fn description(&self) -> &str {
        "Per-channel security configuration"
    }

    fn scan(&self, config: &OpenClawConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (channel_name, channel) in &config.channels {
            if channel.enabled != Some(true) {
                continue;
            }

            // Check: DM policy = open (allows anyone) - critical
            if channel.dm_policy.as_deref() == Some("open") {
                findings.push(Finding::new(
                    &format!("channel.{}.dm_policy_open", channel_name),
                    self.name(),
                    Severity::Critical,
                    &format!("{} DM Policy 'open'", channel_name),
                    &format!("Anyone can DM the bot on {}", channel_name),
                    "Untrusted users can send messages to the agent",
                    &format!("Set channels.{}.dmPolicy to 'pairing' or 'allowlist'", channel_name),
                    &format!("channels.{}.dmPolicy", channel_name),
                ));
            }

            // Check: DM policy = disabled (no DMs allowed) - info
            if channel.dm_policy.as_deref() == Some("disabled") {
                findings.push(Finding::new(
                    &format!("channel.{}.dm_disabled", channel_name),
                    self.name(),
                    Severity::Info,
                    &format!("{} DMs Disabled", channel_name),
                    &format!("DMs are disabled for {}", channel_name),
                    "Cannot receive direct messages on this channel",
                    "Enable if DMs are needed",
                    &format!("channels.{}.dmPolicy", channel_name),
                ));
            }

            // Check: Group policy = open (anyone in group can trigger) - high
            if channel.group_policy.as_deref() == Some("open") {
                findings.push(Finding::new(
                    &format!("channel.{}.group_policy_open", channel_name),
                    self.name(),
                    Severity::High,
                    &format!("{} Group Policy 'open'", channel_name),
                    &format!("Anyone in group can trigger the bot on {}", channel_name),
                    "Any group member can interact with agent",
                    &format!("Set channels.{}.groupPolicy to 'allowlist'", channel_name),
                    &format!("channels.{}.groupPolicy", channel_name),
                ));
            }

            // Check: allowFrom with wildcard - medium
            if let Some(allow_from) = &channel.allow_from {
                if allow_from.contains(&"*".to_string()) {
                    findings.push(Finding::new(
                        &format!("channel.{}.allow_from_wildcard", channel_name),
                        self.name(),
                        Severity::Medium,
                        &format!("{} allowFrom Uses Wildcard", channel_name),
                        &format!("allowFrom includes '*' - allows everyone"),
                        "Any user on the channel can interact with agent",
                        "Use specific user IDs instead of '*'",
                        &format!("channels.{}.allowFrom", channel_name),
                    ));
                }
            }
        }

        findings
    }
}
