//! Integration Tests for Dino-AISS
//! Run with: cargo test --test integration

use dino_aiss::{OpenClawConfig, GatewayScanner, SandboxScanner, ToolsScanner, CredentialsScanner, PluginScanner, Scanner};

#[test]
fn test_gateway_auth_none_critical() {
    let config_json = serde_json::json!({
        "gateway": {
            "bind": "loopback",
            "auth": { "mode": "none" }
        }
    });
    let config = OpenClawConfig::from_dict(config_json).unwrap();
    let scanner = GatewayScanner;
    let findings = scanner.scan(&config);
    
    assert!(!findings.is_empty());
}

#[test]
fn test_gateway_bind_public_critical() {
    let config_json = serde_json::json!({
        "gateway": {
            "bind": "0.0.0.0",
            "auth": { "mode": "token", "token": "test_token_12345678901234567890123" }
        }
    });
    let config = OpenClawConfig::from_dict(config_json).unwrap();
    let scanner = GatewayScanner;
    let findings = scanner.scan(&config);
    
    assert!(!findings.is_empty());
}

#[test]
fn test_sandbox_mode_off_critical() {
    let config_json = serde_json::json!({
        "agents": { "defaults": { "sandbox": { "mode": "off" } } }
    });
    let config = OpenClawConfig::from_dict(config_json).unwrap();
    let scanner = SandboxScanner;
    let findings = scanner.scan(&config);
    
    assert!(!findings.is_empty());
}

#[test]
fn test_tools_elevated_enabled() {
    let config_json = serde_json::json!({
        "tools": { "elevated": { "enabled": true } }
    });
    let config = OpenClawConfig::from_dict(config_json).unwrap();
    let scanner = ToolsScanner;
    let findings = scanner.scan(&config);
    
    assert!(!findings.is_empty());
}

#[test]
fn test_credentials_token_in_config() {
    let config_json = serde_json::json!({
        "gateway": { "auth": { "token": "my_secret_token_12345678901234567890" } }
    });
    let config = OpenClawConfig::from_dict(config_json).unwrap();
    let scanner = CredentialsScanner;
    let findings = scanner.scan(&config);
    
    assert!(!findings.is_empty());
}

#[test]
fn test_plugins_allow_unverified() {
    let config_json = serde_json::json!({
        "plugins": { "allowUnverified": true }
    });
    let config = OpenClawConfig::from_dict(config_json).unwrap();
    let scanner = PluginScanner;
    let findings = scanner.scan(&config);
    
    assert!(!findings.is_empty());
}
