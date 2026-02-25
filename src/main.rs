//! Dino-AISS - AI Assistant Security Scanner
//! 
//! A security scanner designed specifically for AI assistants following
//! the OpenClaw personal assistant security model.

mod models;
mod config;
mod scanner;
mod knowledge;
mod fixer;

use std::path::Path;
use std::time::Instant;
use clap::{Parser, ValueEnum};
use colored::*;

use crate::config::OpenClawConfig;
use crate::models::{ScanResult, Severity};
use crate::scanner::get_all_scanners;
use crate::fixer::{generate_fixes, apply_fixes, preview_fixes};

#[derive(Parser, Debug)]
#[command(name = "dino-aiss")]
#[command(version = "0.1.0")]
#[command(about = "Dino-AISS - AI Assistant Security Scanner", long_about = None)]
struct Args {
    /// Path to OpenClaw configuration file
    #[arg(short, long, required = true)]
    config: String,

    /// Filter findings by severity
    #[arg(long, value_enum, default_value = "all")]
    severity: SeverityFilter,

    /// Output format
    #[arg(short, long, value_enum, default_value = "console")]
    format: OutputFormat,

    /// Output file (default: stdout)
    #[arg(short, long)]
    output: Option<String>,

    /// Show detailed output
    #[arg(short, long)]
    verbose: bool,
    
    /// Auto-fix mode (preview changes)
    #[arg(long)]
    fix: bool,
    
    /// Force fix without confirmation
    #[arg(long)]
    force: bool,
    
    /// Check OpenClaw version against CVE patches (e.g., --check-version 2026.2.10)
    #[arg(long, requires = "config")]
    check_version: Option<String>,
    
    /// Generate mailto: link for sharing report
    #[arg(long)]
    email: Option<String>,
    
    /// Generate upgrade guide
    #[arg(long)]
    upgrade_guide: bool,
}

#[derive(Debug, Clone, ValueEnum)]
enum SeverityFilter {
    CriticalOnly,
    HighOnly,
    All,
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Console,
    Json,
    Markdown,
    Html,
}

fn run_scan(args: &Args) -> Result<ScanResult, String> {
    // Load config
    let config_path = Path::new(&args.config);
    let openclaw_config = OpenClawConfig::from_file(config_path)?;

    // Run scanners
    let scanners = get_all_scanners();
    let mut result = ScanResult::new();

    for scanner in scanners {
        let findings = scanner.scan(&openclaw_config);
        for finding in findings {
            match args.severity {
                SeverityFilter::CriticalOnly => {
                    if finding.severity == Severity::Critical {
                        result.add_finding(finding);
                    }
                }
                SeverityFilter::HighOnly => {
                    if finding.severity == Severity::Critical || finding.severity == Severity::High {
                        result.add_finding(finding);
                    }
                }
                SeverityFilter::All => {
                    result.add_finding(finding);
                }
            }
        }
    }

    Ok(result)
}

fn display_console(result: &ScanResult, verbose: bool) {
    let score_str = if result.health_score >= 80 { 
        format!("{}/100", result.health_score).green().to_string() 
    } else if result.health_score >= 60 { 
        format!("{}/100", result.health_score).yellow().to_string() 
    } else { 
        format!("{}/100", result.health_score).red().to_string() 
    };

    println!("\n[ Scan Results ]");
    println!("Health Score: {}", score_str);
    println!("Critical: {} | High: {} | Total: {}", 
        result.critical_count(), result.high_count(), result.findings.len());
    println!();

    if result.findings.is_empty() {
        println!("{}", "No security issues found!".green());
        return;
    }

    println!("[ Security Findings ]");
    println!("{:<11} | {:<12} | {:<32} | {:<12}", 
        "Severity", "Module", "Title", "CVE");
    println!("{}-+-{}-+-{}-+-{}", "-".repeat(11), "-".repeat(12), "-".repeat(32), "-".repeat(12));

    // Sort by severity
    let mut sorted = result.findings.clone();
    sorted.sort_by(|a, b| {
        let order = |s: &Severity| match s {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        };
        order(&a.severity).cmp(&order(&b.severity))
    });

    for finding in &sorted {
        let sev_str = match finding.severity {
            Severity::Critical => finding.severity.as_str().red().bold().to_string(),
            Severity::High => finding.severity.as_str().yellow().bold().to_string(),
            Severity::Medium => finding.severity.as_str().cyan().to_string(),
            Severity::Low => finding.severity.as_str().blue().to_string(),
            Severity::Info => finding.severity.as_str().to_string(),
        };
        
        let title = if finding.title.len() > 30 {
            format!("{}...", &finding.title[..27])
        } else {
            finding.title.clone()
        };
        
        let cve = finding.cve.clone().unwrap_or_else(|| "-".to_string());
        
        println!("{:<11} | {:<12} | {:<32} | {:<12}", 
            sev_str, finding.module, title, cve);
    }
    println!();

    if verbose {
        println!("[ Finding Details ]");
        for (i, finding) in sorted.iter().enumerate() {
            println!("\n{}. {} ({})", i + 1, finding.title, finding.severity.as_str());
            println!("   ID: {}", finding.id);
            println!("   Path: {}", finding.config_path);
            println!("   Description: {}", finding.description);
            println!("   Remediation: {}", finding.remediation);
        }
    }
}

fn display_json(result: &ScanResult, output: &Option<String>) {
    let json = serde_json::to_string_pretty(&result).unwrap();
    if let Some(path) = output {
        std::fs::write(path, &json).unwrap();
        println!("OK Results written to: {}", path);
    } else {
        println!("{}", json);
    }
}

fn display_html(result: &ScanResult, output: &Option<String>) {
    let severity_color = |sev: &str| -> &str {
        match sev {
            "critical" => "#dc2626",
            "high" => "#d97706", 
            "medium" => "#0891b2",
            "low" => "#2563eb",
            _ => "#6b7280",
        }
    };
    
    let html = format!(r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Dino-AISS Security Scan</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f9fafb; }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        h1 {{ color: #059669; }}
        .score {{ font-size: 64px; font-weight: bold; }}
        .score-high {{ color: #059669; }}
        .score-medium {{ color: #d97706; }}
        .score-low {{ color: #dc2626; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat {{ background: white; padding: 15px 25px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .critical {{ color: #dc2626; font-weight: bold; }}
        .high {{ color: #d97706; font-weight: bold; }}
        .finding {{ margin: 15px 0; padding: 20px; background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-left: 4px solid #e5e7eb; }}
        .finding.critical {{ border-left-color: #dc2626; }}
        .finding.high {{ border-left-color: #d97706; }}
        .finding.medium {{ border-left-color: #0891b2; }}
        .finding.low {{ border-left-color: #2563eb; }}
        .cve {{ background: #fee2e2; color: #991b1b; padding: 2px 8px; border-radius: 4px; font-size: 12px; }}
        code {{ background: #f3f4f6; padding: 2px 6px; border-radius: 4px; }}
        .footer {{ margin-top: 40px; color: #6b7280; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Dino-AISS Security Scan</h1>
        <p class="score {}">{}</p>
        <div class="summary">
            <div class="stat"><span class="critical">{}</span> Critical</div>
            <div class="stat"><span class="high">{}</span> High</div>
            <div class="stat">{} Total Findings</div>
        </div>
        
        <h2>Findings</h2>
"#,
        if result.health_score >= 80 { "score-high" } else if result.health_score >= 60 { "score-medium" } else { "score-low" },
        result.health_score,
        result.critical_count(),
        result.high_count(),
        result.findings.len()
    );
    
    let mut html = html;
    
    // Add findings
    let mut sorted = result.findings.clone();
    sorted.sort_by(|a, b| {
        let order = |s: &Severity| match s {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        };
        order(&a.severity).cmp(&order(&b.severity))
    });
    
    for finding in sorted {
        let cve_tag = finding.cve.as_ref()
            .map(|c| format!("<span class='cve'>{}</span>", c))
            .unwrap_or_default();
        
        html.push_str(&format!(r#"
        <div class="finding {}">
            <h3>{} {}</h3>
            <p><strong>Module:</strong> {}</p>
            <p><strong>Config Path:</strong> <code>{}</code></p>
            <p><strong>Description:</strong> {}</p>
            <p><strong>Remediation:</strong> {}</p>
        </div>"#,
            finding.severity.as_str(),
            finding.title,
            cve_tag,
            finding.module,
            finding.config_path,
            finding.description,
            finding.remediation
        ));
    }
    
    html.push_str(&format!(r#"
        <div class="footer">
            <p>Scanned by Dino-AISS v0.1.0 - AI Assistant Security Scanner</p>
            <p>Philosophy: "We scan for real exploit chains, not theoretical configs."</p>
        </div>
    </div>
</body>
</html>"#));
    
    if let Some(path) = output {
        std::fs::write(path, &html).unwrap();
        println!("OK Results written to: {}", path);
    } else {
        println!("{}", html);
    }
}

fn display_markdown(result: &ScanResult, output: &Option<String>) {
    let mut md = format!(r#"# Dino-AISS Security Scan Results

**Health Score:** {}/100
**Critical:** {} | **High:** {} | **Total:** {}

---

## Findings

"#, 
        result.health_score,
        result.critical_count(),
        result.high_count(),
        result.findings.len()
    );
    
    // Sort by severity
    let mut sorted = result.findings.clone();
    sorted.sort_by(|a, b| {
        let order = |s: &Severity| match s {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        };
        order(&a.severity).cmp(&order(&b.severity))
    });
    
    for finding in sorted {
        let cve_line = finding.cve.as_ref()
            .map(|c| format!("\n**CVE:** {}", c))
            .unwrap_or_default();
        
        md.push_str(&format!(r#"### {}

- **Severity:** {}
- **Module:** {}
- **Path:** `{}`{}
- **Description:** {}
- **Remediation:** {}

---
"#, 
            finding.title,
            finding.severity.as_str(),
            finding.module,
            finding.config_path,
            cve_line,
            finding.description,
            finding.remediation
        ));
    }
    
    if let Some(path) = output {
        std::fs::write(path, &md).unwrap();
        println!("OK Results written to: {}", path);
    } else {
        println!("{}", md);
    }
}

fn generate_fix_suggestions(result: &ScanResult) -> Vec<String> {
    let mut suggestions = Vec::new();
    
    for finding in &result.findings {
        let suggestion = match finding.id.as_str() {
            "sandbox.mode_off" => "Set agents.defaults.sandbox.mode to 'docker'".to_string(),
            "sandbox.workspace_rw" => "Set agents.defaults.sandbox.workspaceAccess to 'none' or 'ro'".to_string(),
            "sandbox.scope_shared" => "Set agents.defaults.sandbox.scope to 'agent'".to_string(),
            "sandbox.tools_deny_incomplete" => "Add control plane tools to tools.deny: gateway, cron, sessions_spawn, sessions_send".to_string(),
            "tools.exec_no_sandbox" => "Enable sandbox mode or restrict exec allowlist".to_string(),
            "tools.elevated_enabled" => "Set tools.elevated.enabled to false".to_string(),
            "tools.fs_workspace_only_disabled" => "Set tools.fs.workspaceOnly to true".to_string(),
            "tools.web_fetch_no_ssrf" => "Set tools.webFetch.ssrfPolicy to 'strict'".to_string(),
            "tools.web_search_no_ssrf" => "Set tools.webSearch.ssrfPolicy to 'strict'".to_string(),
            "gateway.auth_none" => "Set gateway.auth.mode to 'token' or 'password'".to_string(),
            "gateway.bind_public" => "Set gateway.bind to 'loopback'".to_string(),
            "gateway.weak_token" => "Use a token with at least 32 random characters".to_string(),
            "gateway.tailscale_funnel" => "Set gateway.tailscale.funnel to false".to_string(),
            "session.dm_scope_main_multi_channel" => "Set session.dmScope to 'per-channel-peer'".to_string(),
            "channel.telegram.dm_policy_open" => "Set channels.telegram.dmPolicy to 'pairing' or 'allowlist'".to_string(),
            "channel.discord.group_policy_open" => "Set channels.discord.groupPolicy to 'allowlist'".to_string(),
            "control_plane.gateway_not_denied" => "Add 'gateway' to tools.deny".to_string(),
            "control_plane.cron_not_denied" => "Add 'cron' to tools.deny".to_string(),
            "control_plane.sessions_spawn_not_denied" => "Add 'sessions_spawn' to tools.deny".to_string(),
            "control_plane.sessions_send_not_denied" => "Add 'sessions_send' to tools.deny".to_string(),
            _ => format!("Review and fix: {}", finding.config_path),
        };
        
        suggestions.push(format!("[{}] {}: {}", 
            finding.severity.as_str().to_uppercase(),
            finding.title,
            suggestion
        ));
    }
    
    suggestions
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("\nDino-AISS v{}", "0.1.0".cyan());
    println!("AI Assistant Security Scanner\n");

    // Version check mode
    if let Some(version) = &args.check_version {
        println!("[ Version Check ]");
        println!("Checking version: {}\n", version);
        
        // CVE version requirements
        let cve_requirements = vec![
            ("CVE-2026-26322", "2026.2.14"),
            ("CVE-2026-25593", "2026.2.15"),
            ("CVE-2026-24763", "2026.2.13"),
        ];
        
        for (cve, min_version) in cve_requirements {
            println!("{}: requires >= {}", cve, min_version);
            // Simple version comparison (would need proper semver in production)
            let version_str = version.as_str();
            if version_str < min_version {
                println!("  [{}] UPGRADE NEEDED!", "FAIL".red());
            } else {
                println!("  [{}]", "OK".green());
            }
        }
        
        return Ok(());
    }

    print!("Loading config from: {} ... ", args.config);
    let start = Instant::now();
    
    let result = match run_scan(&args) {
        Ok(r) => r,
        Err(e) => {
            println!("{}", "FAIL".red());
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    
    println!("{} ({:.2}s)", "OK".green(), start.elapsed().as_secs_f32());

    // Handle --fix mode
    if args.fix {
        println!("\n[ Auto-Fix Suggestions ]");
        let suggestions = generate_fix_suggestions(&result);
        
        if suggestions.is_empty() {
            println!("No fixes needed!");
        } else {
            for (i, suggestion) in suggestions.iter().enumerate() {
                println!("{}. {}", i + 1, suggestion);
            }
            
            if !args.force {
                println!("\nRun with --force to skip confirmation");
            }
        }
    }
    
    // Handle --email mode (generate mailto link)
    if let Some(email) = &args.email {
        println!("\n[ Email Report ]");
        
        // Generate mailto: link
        let subject = format!("Dino-AISS Security Scan - {} findings", result.findings.len());
        let body = format!(
            "Dino-AISS Security Scan Results\n\
            ==============================\n\n\
            Health Score: {}/100\n\
            Critical: {}\n\
            High: {}\n\
            Total Findings: {}\n\n\
            Run with --format html --output report.html for full details.\n\n\
            --\n\
            Dino-AISS v0.1.0\n\
            Philosophy: \"We scan for real exploit chains, not theoretical configs.\"",
            result.health_score,
            result.critical_count(),
            result.high_count(),
            result.findings.len()
        );
        
        let mailto = format!(
            "mailto:{}?subject={}&body={}",
            email,
            urlencoding::encode(&subject),
            urlencoding::encode(&body)
        );
        
        println!("To share via email, open:");
        println!("\n{}\n", mailto);
    }

    // Display results
    match args.format {
        OutputFormat::Console => display_console(&result, args.verbose),
        OutputFormat::Json => display_json(&result, &args.output),
        OutputFormat::Markdown => display_markdown(&result, &args.output),
        OutputFormat::Html => display_html(&result, &args.output),
    }

    // Exit code based on severity
    if result.critical_count() > 0 {
        std::process::exit(2);
    } else if result.high_count() > 0 {
        std::process::exit(1);
    }
    
    // Handle upgrade guide
    if args.upgrade_guide {
        println!("\n[ Upgrade Guide ]\n");
        
        let version = openclaw_version_from_config(&args.config);
        
        println!("Current version: {}\n", version);
        println!("Recommended upgrades based on security fixes:");
        
        let upgrades = vec![
            ("2026.2.14", "SSRF vulnerability fixes, strict gatewayUrl validation"),
            ("2026.2.15", "RCE via cliPath fix, command validation"),
            ("2026.2.20", "Sandbox Docker improvements, PATH sanitization"),
            ("2026.2.23", "Security hardening batch, safe bins updates"),
        ];
        
        for (ver, desc) in upgrades {
            let status = "[upgrade]".yellow();
            println!("  {} v{} - {}", status, ver, desc);
        }
        
        println!("\nTo upgrade: npm update -g openclaw");
        
        return Ok(());
    }

    Ok(())
}

fn openclaw_version_from_config(_config_path: &str) -> String {
    "unknown".to_string()
}
