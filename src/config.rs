//! OpenClaw Configuration Parser

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Gateway configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GatewayConfig {
    pub mode: Option<String>,
    pub bind: Option<String>,
    pub port: Option<u16>,
    pub auth_mode: Option<String>,
    pub token: Option<String>,
    pub tailscale_funnel: Option<bool>,
    pub mdns_mode: Option<String>,
    pub control_ui_origins: Option<Vec<String>>,
    pub trusted_proxies: Option<Vec<String>>,
    pub http_no_auth: Option<bool>,
}

/// Tools configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolsConfig {
    pub profile: Option<String>,
    pub deny: Option<Vec<String>>,
    pub exec_host: Option<String>,
    pub exec_security: Option<String>,
    pub exec_ask: Option<String>,
    pub exec_safe_bins: Option<Vec<String>>,
    pub elevated_enabled: Option<bool>,
    pub fs_workspace_only: Option<bool>,
    pub web_fetch_ssrf_policy: Option<String>,
    pub web_search_ssrf_policy: Option<String>,
}

/// Sandbox configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub mode: Option<String>,
    pub workspace_access: Option<String>,
    pub scope: Option<String>,
}

/// Session configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionConfig {
    pub dm_scope: Option<String>,
}

/// Channel configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChannelConfig {
    pub enabled: Option<bool>,
    pub dm_policy: Option<String>,
    pub group_policy: Option<String>,
    pub allow_from: Option<Vec<String>>,
    pub groups: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Parsed OpenClaw configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OpenClawConfig {
    #[serde(default)]
    pub gateway: GatewayConfig,
    #[serde(default)]
    pub tools: ToolsConfig,
    #[serde(default)]
    pub sandbox: SandboxConfig,
    #[serde(default)]
    pub session: SessionConfig,
    #[serde(default)]
    pub channels: HashMap<String, ChannelConfig>,
    #[serde(default, skip)]
    pub raw: serde_json::Value,
}

impl OpenClawConfig {
    /// Load config from file (JSON or YAML)
    pub fn from_file(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Err(format!("Config file not found: {}", path.display()));
        }

        let content =
            fs::read_to_string(path).map_err(|e| format!("Failed to read config: {}", e))?;

        // Try JSON first, then YAML
        let data: serde_json::Value = serde_json::from_str(&content)
            .or_else(|_| serde_yaml::from_str(&content))
            .map_err(|e| format!("Failed to parse config: {}", e))?;

        Self::from_dict(data)
    }

    /// Parse config from dictionary
    pub fn from_dict(data: serde_json::Value) -> Result<Self, String> {
        let mut config = OpenClawConfig::default();
        config.raw = data.clone();

        // Parse gateway
        if let Some(gw) = data.get("gateway").and_then(|v| v.as_object()) {
            config.gateway = GatewayConfig {
                mode: gw.get("mode").and_then(|v| v.as_str()).map(String::from),
                bind: gw.get("bind").and_then(|v| v.as_str()).map(String::from),
                port: gw.get("port").and_then(|v| v.as_u64()).map(|p| p as u16),
                auth_mode: gw
                    .get("auth")
                    .and_then(|v| v.get("mode"))
                    .and_then(|v| v.as_str())
                    .map(String::from),
                token: gw
                    .get("auth")
                    .and_then(|v| v.get("token"))
                    .and_then(|v| v.as_str())
                    .map(String::from),
                tailscale_funnel: gw
                    .get("tailscale")
                    .and_then(|v| v.get("funnel"))
                    .and_then(|v| v.as_bool()),
                mdns_mode: gw
                    .get("discovery")
                    .and_then(|v| v.get("mdns"))
                    .and_then(|v| v.get("mode"))
                    .and_then(|v| v.as_str())
                    .map(String::from),
                control_ui_origins: gw
                    .get("controlUi")
                    .and_then(|v| v.get("allowedOrigins"))
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    }),
                trusted_proxies: gw
                    .get("trustedProxies")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    }),
                http_no_auth: gw
                    .get("http")
                    .and_then(|v| v.get("noAuth"))
                    .and_then(|v| v.as_bool()),
            };
        }

        // Parse tools
        if let Some(tl) = data.get("tools").and_then(|v| v.as_object()) {
            config.tools = ToolsConfig {
                profile: tl.get("profile").and_then(|v| v.as_str()).map(String::from),
                deny: tl.get("deny").and_then(|v| v.as_array()).map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                }),
                exec_host: tl
                    .get("exec")
                    .and_then(|v| v.get("host"))
                    .and_then(|v| v.as_str())
                    .map(String::from),
                exec_security: tl
                    .get("exec")
                    .and_then(|v| v.get("security"))
                    .and_then(|v| v.as_str())
                    .map(String::from),
                exec_ask: tl
                    .get("exec")
                    .and_then(|v| v.get("ask"))
                    .and_then(|v| v.as_str())
                    .map(String::from),
                exec_safe_bins: tl
                    .get("exec")
                    .and_then(|v| v.get("safeBins"))
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    }),
                elevated_enabled: tl
                    .get("elevated")
                    .and_then(|v| v.get("enabled"))
                    .and_then(|v| v.as_bool()),
                fs_workspace_only: tl
                    .get("fs")
                    .and_then(|v| v.get("workspaceOnly"))
                    .and_then(|v| v.as_bool()),
                web_fetch_ssrf_policy: tl
                    .get("webFetch")
                    .and_then(|v| v.get("ssrfPolicy"))
                    .and_then(|v| v.as_str())
                    .map(String::from),
                web_search_ssrf_policy: tl
                    .get("webSearch")
                    .and_then(|v| v.get("ssrfPolicy"))
                    .and_then(|v| v.as_str())
                    .map(String::from),
            };
        }

        // Parse sandbox (agents.defaults.sandbox)
        if let Some(agents) = data.get("agents").and_then(|v| v.as_object()) {
            if let Some(defaults) = agents.get("defaults").and_then(|v| v.as_object()) {
                if let Some(sb) = defaults.get("sandbox").and_then(|v| v.as_object()) {
                    config.sandbox = SandboxConfig {
                        mode: sb.get("mode").and_then(|v| v.as_str()).map(String::from),
                        workspace_access: sb
                            .get("workspaceAccess")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        scope: sb.get("scope").and_then(|v| v.as_str()).map(String::from),
                    };
                }
            }
        }

        // Parse session
        if let Some(sess) = data.get("session").and_then(|v| v.as_object()) {
            config.session = SessionConfig {
                dm_scope: sess
                    .get("dmScope")
                    .and_then(|v| v.as_str())
                    .map(String::from),
            };
        }

        // Parse channels
        let channel_names = [
            "telegram", "discord", "whatsapp", "slack", "imessage", "signal",
        ];
        for name in channel_names {
            if let Some(ch) = data
                .get("channels")
                .and_then(|v| v.get(name))
                .and_then(|v| v.as_object())
            {
                config.channels.insert(
                    name.to_string(),
                    ChannelConfig {
                        enabled: ch.get("enabled").and_then(|v| v.as_bool()),
                        dm_policy: ch
                            .get("dmPolicy")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        group_policy: ch
                            .get("groupPolicy")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        allow_from: ch.get("allowFrom").and_then(|v| v.as_array()).map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        }),
                        groups: ch.get("groups").and_then(|v| v.as_object()).cloned(),
                    },
                );
            }
        }

        Ok(config)
    }
}
