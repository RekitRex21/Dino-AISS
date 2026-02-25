# Dino-AISS - OpenClaw Config Security Scanner

![Rust](https://img.shields.io/badge/Rust-1.75+-orange)
![License](https://img.shields.io/badge/License-MIT-green)
![CI](https://github.com/RekitRex21/Dino-AISS/actions/workflows/ci.yml/badge.svg)

> "We scan for real exploit chains, not theoretical configs. Localhost is by design."

Dino-AISS is a Rust-based security scanner designed specifically for AI assistants following the OpenClaw personal assistant security model.

## Philosophy

- **Personal Agent Focus**: Built for single-user deployments, not multi-tenant systems
- **Real Exploit Chains**: We flag actual bypasses, not theoretical vulnerabilities  
- **Localhost by Design**: Loopback bindings are expected, not vulnerabilities
- **Prompt Injection**: Not a finding unless there's a bypass chain to tool execution

## Installation

```bash
# From source
cargo install --git https://github.com/RekitRex21/Dino-AISS.git

# Or build locally
git clone https://github.com/RekitRex21/Dino-AISS.git
cd Dino-AISS
cargo build --release
```

## Usage

### Basic Scan
```bash
dino-aiss --config ~/.openclaw/openclaw.json
```

### Critical Only
```bash
dino-aiss --config ~/.openclaw/openclaw.json --severity critical-only
```

### Auto-Fix Suggestions
```bash
dino-aiss --config ~/.openclaw/openclaw.json --fix
```

### HTML Report
```bash
dino-aiss --config ~/.openclaw/openclaw.json --format html --output report.html
```

### Version Check
```bash
dino-aiss --config ~/.openclaw/openclaw.json --check-version 2026.2.10
```

### Upgrade Guide
```bash
dino-aiss --config ~/.openclaw/openclaw.json --upgrade-guide
```

### Share via Email
```bash
dino-aiss --config ~/.openclaw/openclaw.json --email security@example.com
```

## Features

### 12 Security Scanner Modules
- Gateway & Auth Security
- Sandbox & Container Security
- Tool Policy Scanner
- Credentials & Secrets Detection
- Session & Identity Isolation
- Channel Security (Telegram, Discord, WhatsApp, Slack, iMessage, Signal)
- Node Security
- Browser Control Security
- Control Plane Tools
- Memory & Context Security
- Prompt Injection Chains
- Plugin & Extension Security

### CVE Knowledge Base
- CVE-2026-26322 (SSRF)
- CVE-2026-25593 (RCE via cliPath)
- CVE-2026-24763 (PATH injection)

### Output Formats
- Console (color-coded)
- JSON (machine-readable)
- Markdown (documentation)
- HTML (shareable reports)

## Configuration

Dino-AISS reads your OpenClaw configuration file and analyzes it for security issues.

**Note**: Cargo.lock is committed for reproducible builds.

## License

MIT License - See [LICENSE](LICENSE)

## Credits

Built by [RekitRex21](https://github.com/RekitRex21)
