# Dino-AISS – OpenClaw Configuration Security Scanner

**A lightweight, local Rust tool that helps you audit your personal OpenClaw setup for common misconfigurations and known issues.**

Dino-AISS scans your OpenClaw config file (usually `~/.openclaw/openclaw.json` or similar) and reports potential security weaknesses — focusing on practical risks that could affect single-user, localhost deployments.

> **Important:** This is **not** an official OpenClaw tool.
> It is an independent, open-source project built by a community member to help secure personal setups.
> **Everything runs locally on your machine — no data is sent anywhere unless you explicitly use the --email flag.**

---

## Why This Tool Exists

OpenClaw is an exciting, fast-moving personal AI agent project — but like many powerful tools, it comes with real security trade-offs if configs are too permissive (e.g., exposed tools, weak auth, unsafe PATH handling).

Recent disclosures (Jan–Feb 2026) have highlighted several CVEs affecting OpenClaw components, including SSRF, command injection, and sandbox escapes. Dino-AISS helps catch these patterns early so you can harden your setup before they become problems.

## Key Principles

- **Designed for single-user, localhost-first deployments** — the most common way people run OpenClaw at home.
- **Prioritizes exploitable chains** over purely theoretical concerns (e.g., prompt injection is only flagged if a clear path to unauthorized tool execution exists).
- **Localhost/loopback bindings are intentional** for personal agents — we don't flag them unless they're combined with other risky exposures.
- **Transparency first** — all scan logic is in plain Rust code; you're encouraged to review it.

---

## Installation

```bash
# Quick install from source (recommended)
cargo install --git https://github.com/RekitRex21/Dino-AISS.git

# Or clone and build manually
git clone https://github.com/RekitRex21/Dino-AISS.git
cd Dino-AISS
cargo build --release

# Then use ./target/release/dino-aiss
```

---

## Basic Usage Examples

```bash
# Standard scan (recommended starting point)
dino-aiss --config ~/.openclaw/openclaw.json

# Only show high/critical issues
dino-aiss --config ~/.openclaw/openclaw.json --severity critical-only

# Generate a nice HTML report (great for review)
dino-aiss --config ~/.openclaw/openclaw.json --format html --output my-scan-report.html

# Preview suggested fixes without applying them (dry-run mode coming soon)
dino-aiss --config ~/.openclaw/openclaw.json --fix --dry-run
```

---

## ⚠️ Important Security & Privacy Notes

- **No network calls by default** — scans are 100% local. No telemetry, no phoning home.
- **`--email` flag** — Only use this if you trust the recipient. It sends the full scan report (including config snippets and any detected secrets) via plain SMTP. **No encryption is applied.**
  → Safer alternative: Use `--format json` or `--format html` and share manually/securely.
- **`--fix` flag** — Suggests and can apply config changes (e.g., tightening tool allow-lists, removing risky paths). **Always review changes first!**
  → We strongly recommend running with `--dry-run` (or manually diffing) before applying. Back up your config file first.
- **Detected secrets** — If Dino-AISS finds API keys, tokens, etc., in your config, it will warn you — but it never logs or exfils them automatically.

---

## Scanners Included (12 modules)

- Gateway & Auth Checks
- Sandbox/Container Hardening
- Tool Policy & Allow-List Review
- Credential/Secret Leak Detection
- Session & Isolation Checks
- Messaging Channel Security (Discord, Telegram, etc.)
- Node/Browser Control Exposure
- Memory/Context Leak Risks
- Prompt Injection Chains (with execution path validation)
- Plugin/Extension Vetting
- And more...

---

## Known CVE References (as of Feb 2026)

These are publicly disclosed issues in OpenClaw or related components that Dino-AISS checks patterns for:

- **CVE-2026-26322** — SSRF in Gateway tool via outbound WebSocket (high severity)
- **CVE-2026-25593** — Potential RCE patterns via unsafe `cliPath` handling
- **CVE-2026-24763** — PATH injection / Docker sandbox escape via environment variables

These are real vulnerabilities reported in security blogs and NVD — Dino-AISS helps detect similar misconfigs that could expose you to them.

---

## Output Formats

- Color console (default)
- JSON (for scripting/automation)
- Markdown
- HTML (human-readable reports)

---

## License

MIT — free to use, modify, fork. See [LICENSE](LICENSE) for details.

---

## Questions or Concerns?

Feel free to open an issue or PR. This is a community helper tool — feedback welcome!

If you're worried about anything in the code, clone it and `cargo audit` / review the Rust source — it's all there.

---

Built with ❤️ for the OpenClaw community by [@RekitRex21](https://github.com/RekitRex21) 🦖
