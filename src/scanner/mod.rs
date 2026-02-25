#![allow(dead_code)]

//! Scanner Base Trait

use crate::config::OpenClawConfig;
use crate::models::Finding;

pub mod gateway;
pub mod sandbox;
pub mod tools;
pub mod session;
pub mod channels;
pub mod credentials;
pub mod nodes;
pub mod browser;
pub mod control_plane;
pub mod memory;
pub mod prompt_injection;
pub mod plugins;

pub use gateway::GatewayScanner;
pub use sandbox::SandboxScanner;
pub use tools::ToolsScanner;
pub use session::SessionScanner;
pub use channels::ChannelScanner;
pub use credentials::CredentialsScanner;
pub use nodes::NodeScanner;
pub use browser::BrowserScanner;
pub use control_plane::ControlPlaneScanner;
pub use memory::MemoryScanner;
pub use prompt_injection::PromptInjectionScanner;
pub use plugins::PluginScanner;

/// Get all available scanners
pub fn get_all_scanners() -> Vec<Box<dyn Scanner>> {
    vec![
        Box::new(GatewayScanner),
        Box::new(SandboxScanner),
        Box::new(ToolsScanner),
        Box::new(SessionScanner),
        Box::new(ChannelScanner),
        Box::new(CredentialsScanner),
        Box::new(NodeScanner),
        Box::new(BrowserScanner),
        Box::new(ControlPlaneScanner),
        Box::new(MemoryScanner),
        Box::new(PromptInjectionScanner),
        Box::new(PluginScanner),
    ]
}

/// Base trait for all scanner modules
pub trait Scanner {
    /// Scanner module name
    fn name(&self) -> &str;

    /// Scanner description
    fn description(&self) -> &str;

    /// Scan the configuration and return findings
    fn scan(&self, config: &OpenClawConfig) -> Vec<Finding>;
}
