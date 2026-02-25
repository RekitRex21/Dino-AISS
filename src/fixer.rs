//! Auto-Remediation Module
//! 
//! Handles automatic fixing of security issues with backup and confirmation

use std::fs;
use std::path::Path;

/// Represents a fix to apply to the config
#[derive(Debug, Clone)]
pub struct ConfigFix {
    pub path: String,
    pub key: String,
    pub value: serde_json::Value,
    pub description: String,
}

/// Generate fixes for findings
pub fn generate_fixes(findings: &[crate::models::Finding]) -> Vec<ConfigFix> {
    let mut fixes = Vec::new();
    
    for finding in findings {
        let fix = match finding.id.as_str() {
            // Sandbox fixes
            "sandbox.mode_off" => Some(ConfigFix {
                path: "agents.defaults.sandbox".to_string(),
                key: "mode".to_string(),
                value: serde_json::Value::String("docker".to_string()),
                description: "Enable sandbox mode".to_string(),
            }),
            "sandbox.workspace_rw" => Some(ConfigFix {
                path: "agents.defaults.sandbox".to_string(),
                key: "workspaceAccess".to_string(),
                value: serde_json::Value::String("none".to_string()),
                description: "Remove workspace write access".to_string(),
            }),
            "sandbox.scope_shared" => Some(ConfigFix {
                path: "agents.defaults.sandbox".to_string(),
                key: "scope".to_string(),
                value: serde_json::Value::String("agent".to_string()),
                description: "Set sandbox scope to agent isolation".to_string(),
            }),
            
            // Tools fixes
            "tools.fs_workspace_only_disabled" => Some(ConfigFix {
                path: "tools.fs".to_string(),
                key: "workspaceOnly".to_string(),
                value: serde_json::Value::Bool(true),
                description: "Enable file system workspace isolation".to_string(),
            }),
            "tools.web_fetch_no_ssrf" => Some(ConfigFix {
                path: "tools.webFetch".to_string(),
                key: "ssrfPolicy".to_string(),
                value: serde_json::Value::String("strict".to_string()),
                description: "Enable strict SSRF protection for web fetch".to_string(),
            }),
            "tools.web_search_no_ssrf" => Some(ConfigFix {
                path: "tools.webSearch".to_string(),
                key: "ssrfPolicy".to_string(),
                value: serde_json::Value::String("strict".to_string()),
                description: "Enable strict SSRF protection for web search".to_string(),
            }),
            "tools.elevated_enabled" => Some(ConfigFix {
                path: "tools.elevated".to_string(),
                key: "enabled".to_string(),
                value: serde_json::Value::Bool(false),
                description: "Disable elevated mode".to_string(),
            }),
            
            // Gateway fixes
            "gateway.auth_none" => Some(ConfigFix {
                path: "gateway.auth".to_string(),
                key: "mode".to_string(),
                value: serde_json::Value::String("token".to_string()),
                description: "Enable token authentication".to_string(),
            }),
            "gateway.bind_public" => Some(ConfigFix {
                path: "gateway".to_string(),
                key: "bind".to_string(),
                value: serde_json::Value::String("loopback".to_string()),
                description: "Bind to loopback only".to_string(),
            }),
            "gateway.tailscale_funnel" => Some(ConfigFix {
                path: "gateway.tailscale".to_string(),
                key: "funnel".to_string(),
                value: serde_json::Value::Bool(false),
                description: "Disable Tailscale Funnel".to_string(),
            }),
            
            // Session fixes
            "session.dm_scope_main_multi_channel" | "session.dm_scope_default" => Some(ConfigFix {
                path: "session".to_string(),
                key: "dmScope".to_string(),
                value: serde_json::Value::String("per-channel-peer".to_string()),
                description: "Set DM scope to per-channel-peer".to_string(),
            }),
            
            _ => None,
        };
        
        if let Some(f) = fix {
            fixes.push(f);
        }
    }
    
    fixes
}

/// Apply fixes to a config file with backup
pub fn apply_fixes(config_path: &str, fixes: &[ConfigFix], dry_run: bool) -> Result<String, String> {
    let path = Path::new(config_path);
    
    if !path.exists() {
        return Err(format!("Config file not found: {}", config_path));
    }
    
    // Read original config
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config: {}", e))?;
    
    // Parse JSON
    let mut config: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse config: {}", e))?;
    
    // Create backup
    let backup_path = format!("{}.bak", config_path);
    if !dry_run {
        fs::write(&backup_path, &content)
            .map_err(|e| format!("Failed to create backup: {}", e))?;
    }
    
    // Apply fixes
    for fix in fixes {
        apply_fix_to_value(&mut config, &fix.path, &fix.key, fix.value.clone());
    }
    
    // Output
    let result = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    
    if dry_run {
        return Ok(format!("DRY RUN - Would apply fixes:\n{}", result));
    }
    
    // Write fixed config
    fs::write(path, &result)
        .map_err(|e| format!("Failed to write config: {}", e))?;
    
    Ok(format!("Applied fixes. Backup saved to: {}", backup_path))
}

fn apply_fix_to_value(config: &mut serde_json::Value, path: &str, key: &str, value: serde_json::Value) {
    let parts: Vec<&str> = path.split('.').collect();
    
    // Navigate to the right location using index-based access
    let mut target_idx = parts.len();
    
    // Create nested objects if needed
    for (i, part) in parts.iter().enumerate() {
        if i + 1 < parts.len() {
            // Ensure the path exists
            if config.get(*part).is_none() {
                if let Some(obj) = config.as_object_mut() {
                    obj.insert(part.to_string(), serde_json::Value::Object(serde_json::Map::new()));
                }
            }
        } else {
            target_idx = i;
        }
    }
    
    // Apply the final fix
    if let Some(obj) = config.as_object_mut() {
        obj.insert(key.to_string(), value);
    }
}

/// Preview what fixes would do without applying
pub fn preview_fixes(findings: &[crate::models::Finding]) -> String {
    let fixes = generate_fixes(findings);
    
    if fixes.is_empty() {
        return "No automatic fixes available for these findings.".to_string();
    }
    
    let mut preview = String::from("Automatic fixes available:\n\n");
    
    for (i, fix) in fixes.iter().enumerate() {
        let value_str = serde_json::to_string(&fix.value).unwrap_or_default();
        preview.push_str(&format!(
            "{}. {}: Set {} to {}\n   {}\n\n",
            i + 1,
            fix.path,
            fix.key,
            value_str,
            fix.description
        ));
    }
    
    preview
}
