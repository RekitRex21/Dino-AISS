//! Browser Control Security Scanner
//!
//! Priority: HIGH
//!
//! Checks:
//! - Profile isolation
//! - Relay port exposure
//! - CDP endpoint security
//! - Download directory exposure
//! - Extension relay security

use crate::config::OpenClawConfig;
use crate::models::{Finding, Severity};
use crate::scanner::Scanner;

pub struct BrowserScanner;

impl Scanner for BrowserScanner {
    fn name(&self) -> &str {
        "browser"
    }

    fn description(&self) -> &str {
        "Browser automation security"
    }

    fn scan(&self, config: &OpenClawConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for browser configuration in raw config
        if let Some(tools) = config.raw.get("tools").and_then(|v| v.as_object()) {
            // Check browser settings
            if let Some(browser) = tools.get("browser").and_then(|v| v.as_object()) {
                // Check relay binding
                if let Some(relay) = browser.get("relay").and_then(|v| v.as_object()) {
                    if let Some(bind) = relay.get("bind").and_then(|v| v.as_str()) {
                        if bind != "loopback" && bind != "127.0.0.1" {
                            findings.push(Finding::new(
                                "browser.relay_public",
                                self.name(),
                                Severity::Critical,
                                "Browser Relay Bound to Non-Localhost",
                                &format!("Browser relay bind is '{}' (not loopback)", bind),
                                "Browser automation could be accessed from network",
                                "Set browser.relay.bind to 'loopback'",
                                "tools.browser.relay.bind",
                            ));
                        }
                    }
                }

                // Check CDP exposure
                if let Some(cdp) = browser.get("cdp").and_then(|v| v.as_object()) {
                    if cdp.get("enabled") == Some(&serde_json::Value::Bool(true)) {
                        if let Some(bind) = cdp.get("bind").and_then(|v| v.as_str()) {
                            if bind != "loopback" && bind != "127.0.0.1" {
                                findings.push(Finding::new(
                                    "browser.cdp_public",
                                    self.name(),
                                    Severity::Critical,
                                    "Chrome DevTools Protocol Enabled and Exposed",
                                    "CDP is enabled and may be accessible from network",
                                    "Remote attackers could control browser",
                                    "Set browser.cdp.bind to 'loopback' or disable CDP",
                                    "tools.browser.cdp",
                                ));
                            }
                        }
                    }
                }

                // Check download directory
                if let Some(download_dir) = browser.get("downloadDir").and_then(|v| v.as_str()) {
                    if download_dir.is_empty() || download_dir == "/" || download_dir == "C:\\" {
                        findings.push(Finding::new(
                            "browser.download_root",
                            self.name(),
                            Severity::High,
                            "Browser Download Directory is Root",
                            &format!("Download directory is '{}'", download_dir),
                            "Downloaded files could overwrite system files",
                            "Set a specific downloads folder",
                            "tools.browser.downloadDir",
                        ));
                    }
                }

                // Check profile isolation
                if let Some(profile) = browser.get("profile").and_then(|v| v.as_str()) {
                    if profile.contains("Default") || profile.contains("default") {
                        findings.push(Finding::new(
                            "browser.default_profile",
                            self.name(),
                            Severity::Medium,
                            "Using Default Browser Profile",
                            "Browser uses the default user profile",
                            "Could access bookmarks, passwords, cookies",
                            "Use a dedicated profile for automation",
                            "tools.browser.profile",
                        ));
                    }
                }
            }
        }

        findings
    }
}
