# Dino-AISS Security Scan Results

**Health Score:** 73/100
**Critical:** 0 | **High:** 1 | **Total:** 3

---

## Findings

### Potential Secret Detected in Config

- **Severity:** high
- **Module:** credentials
- **Path:** `config`
- **Description:** Found potential secret pattern 'token' in configuration
- **Remediation:** Review and ensure secrets are properly secured or redacted

---
### Gateway Token in Configuration File

- **Severity:** medium
- **Module:** credentials
- **Path:** `gateway.auth.token`
- **Description:** Gateway token is stored directly in config file
- **Remediation:** Ensure config file has restricted permissions (600)

---
### Prompt Injection Detection Informational

- **Severity:** info
- **Module:** prompt_injection
- **Path:** `N/A`
- **Description:** This scanner detects configuration paths that could amplify injection impact, not injection itself
- **Remediation:** See docs for hardening guidance

---
