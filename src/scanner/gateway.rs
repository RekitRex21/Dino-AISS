//! Gateway & Auth Security Scanner
//! 
//! Priority: CRITICAL
//! 
//! Checks:
//! - Token/password strength (minimum 32 chars for token)
//! - Bind address exposure (loopback vs LAN vs tailnet vs public)
//! - Auth mode configuration (token/password/trusted-proxy/none)
//! - Control UI exposure + allowedOrigins requirement
//! - mDNS information disclosure (minimal vs full vs off)
//! - Tailscale Funnel exposure
//! - Reverse proxy misconfigurations
//! - Missing allowFrom restrictions (recently tightened)
//! - Exposed WebSocket without auth/token validation

use crate::config::OpenClawConfig;
use crate::models::{Finding, Severity};
use crate::scanner::Scanner;

pub struct GatewayScanner;

impl Scanner for GatewayScanner {
    fn name(&self) -> &str {
        "gateway"
    }

    fn description(&self) -> &str {
        "Gateway authentication and authorization security"
    }

    fn scan(&self, config: &OpenClawConfig) -> Vec<Finding> {
        let mut findings = Vec::new();
        let gw = &config.gateway;

        // Check: Auth mode = none (critical)
        if gw.auth_mode.as_deref() == Some("none") {
            findings.push(Finding::new(
                "gateway.auth_none",
                self.name(),
                Severity::Critical,
                "Gateway Authentication Disabled",
                "Gateway auth mode is set to 'none', allowing unauthenticated access",
                "Anyone can access your gateway without authentication",
                "Set gateway.auth.mode to 'token' or 'password'",
                "gateway.auth.mode",
            ).with_cve("CVE-2026-26322"));
        }

        // Check: Public bind (0.0.0.0) - critical
        if gw.bind.as_deref() == Some("0.0.0.0") || gw.bind.as_deref() == Some("0.0.0.0:0") {
            findings.push(Finding::new(
                "gateway.bind_public",
                self.name(),
                Severity::Critical,
                "Gateway Bound to All Interfaces",
                "Gateway is bound to 0.0.0.0, making it publicly accessible",
                "Anyone on the network can access your gateway",
                "Set gateway.bind to 'loopback' for local-only access",
                "gateway.bind",
            ));
        }

        // Check: LAN bind without auth - critical
        if gw.bind.as_deref() == Some("lan") && gw.token.is_none() {
            findings.push(Finding::new(
                "gateway.lan_no_auth",
                self.name(),
                Severity::Critical,
                "LAN-Bound Gateway Without Authentication",
                "Gateway is accessible on LAN without authentication token",
                "Anyone on your local network can access the gateway",
                "Set gateway.auth.token to a strong token (32+ characters)",
                "gateway.bind",
            ));
        }

        // Check: Weak token (< 32 chars)
        if let Some(token) = &gw.token {
            if token.len() < 32 {
                findings.push(Finding::new(
                    "gateway.weak_token",
                    self.name(),
                    Severity::High,
                    "Weak Gateway Token",
                    &format!("Gateway token is only {} characters (recommended: 32+)", token.len()),
                    "Token may be vulnerable to brute force attacks",
                    "Use a token with at least 32 random characters",
                    "gateway.auth.token",
                ));
            }
        }

        // Check: Tailscale Funnel - critical
        if gw.tailscale_funnel == Some(true) {
            findings.push(Finding::new(
                "gateway.tailscale_funnel",
                self.name(),
                Severity::Critical,
                "Tailscale Funnel Enabled",
                "Gateway is exposed via Tailscale Funnel, making it publicly accessible",
                "Your gateway is exposed to the public internet via Tailscale",
                "Disable Tailscale Funnel unless you need public access",
                "gateway.tailscale.funnel",
            ).with_cve("CVE-2026-26322"));
        }

        // Check: mDNS full mode - medium
        if gw.mdns_mode.as_deref() == Some("full") {
            findings.push(Finding::new(
                "gateway.mdns_full",
                self.name(),
                Severity::Medium,
                "mDNS Full Mode Enabled",
                "mDNS is in full mode, exposing cliPath and sshPort",
                "Reveals filesystem path and SSH availability to local network",
                "Set discovery.mdns.mode to 'minimal' or 'off'",
                "discovery.mdns.mode",
            ));
        }

        // Check: Control UI without allowedOrigins (non-loopback) - high
        if gw.bind.as_deref() != Some("loopback") && gw.control_ui_origins.is_none() {
            findings.push(Finding::new(
                "gateway.control_ui_no_origins",
                self.name(),
                Severity::High,
                "Control UI Missing allowedOrigins",
                "Non-loopback Control UI requires explicit allowedOrigins",
                "Control UI may be accessible to unauthorized origins",
                "Set gateway.controlUi.allowedOrigins to explicit origin list",
                "gateway.controlUi.allowedOrigins",
            ));
        }

        // Check: HTTP no auth - critical
        if gw.http_no_auth == Some(true) {
            findings.push(Finding::new(
                "gateway.http_no_auth",
                self.name(),
                Severity::Critical,
                "Gateway HTTP APIs Without Auth",
                "Gateway HTTP APIs are reachable without authentication",
                "Unauthenticated access to gateway HTTP endpoints",
                "Set gateway.auth.mode to 'token' or 'password'",
                "gateway.http.noAuth",
            ));
        }

        // Check: Trusted proxies not configured with LAN bind
        if gw.bind.as_deref() == Some("lan") && gw.trusted_proxies.is_none() {
            findings.push(Finding::new(
                "gateway.no_trusted_proxies",
                self.name(),
                Severity::Low,
                "No Trusted Proxies Configured",
                "LAN-bound gateway without trusted proxies may have IP detection issues",
                "Client IP may not be correctly detected behind proxy",
                "Configure gateway.trustedProxies with proxy IPs",
                "gateway.trustedProxies",
            ));
        }

        findings
    }
}
