# Changelog

All notable changes to Dino-AISS will be documented in this file.

## [0.0.1] - 2026-02-24

### Added
- **12 Scanner Modules**: Gateway, Sandbox, Tools, Credentials, Session, Channels, Nodes, Browser, Control Plane, Memory, Prompt Injection, Plugins
- **Multi-format Reports**: JSON, HTML, Markdown output support
- **Auto-Fix Suggestions**: --fix flag to generate remediation suggestions
- **Safe Fix Application**: Creates .fixed file for review before applying
- **Knowledge Base Integration**: CVE database with mitigations
  - CVE-2026-26322 (SSRF)
  - CVE-2026-25593 (RCE via cliPath)
  - CVE-2026-24763 (PATH injection)
- **Version Check**: --check-version flag to compare against CVE patches
- **Upgrade Guide**: --upgrade-guide flag for recommended upgrades
- **Email/Share**: --email flag to generate mailto: links
- **GitHub Actions CI**: Automated test, clippy, fmt, build
- **Project Infrastructure**:
  - MIT License
  - Rust .gitignore template
  - rustfmt.toml configuration
  - rust-toolchain.toml for stable toolchain
  - Cargo.lock committed for reproducibility

### Philosophy
- Focus on real exploit chains, not theoretical vulnerabilities
- Localhost bindings are by design, not vulnerabilities
- Prompt injection alone is not a finding (needs bypass chain)
- Personal agent model - single user per gateway
