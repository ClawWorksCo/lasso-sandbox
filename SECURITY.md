# Security Policy

LASSO is a security-focused project. We take vulnerability reports seriously and aim to resolve confirmed issues quickly.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.4.x   | Yes       |
| < 1.4   | No        |

Only the latest 1.4.x release receives security patches. Older versions are not supported. Please upgrade before reporting issues.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, use one of the following channels:

1. **GitHub Security Advisories** (preferred): File a private advisory at [ClawWorksCo/lasso-sandbox Security Advisories](https://github.com/ClawWorksCo/lasso-sandbox/security/advisories/new).

### What to Include

- A clear description of the vulnerability and its potential impact.
- Steps to reproduce, including any relevant configuration or environment details.
- The affected version(s).
- Any suggested fix or mitigation, if you have one.

## Response Timeline

- **Acknowledgement**: Within 48 hours of receiving the report.
- **Triage**: We will confirm whether the issue is valid and assess severity within 7 days.
- **Fix**: Critical vulnerabilities will be patched within 30 days. Lower-severity issues will be addressed in the next scheduled release.

## Disclosure Policy

We follow a **coordinated disclosure** model:

1. The reporter notifies us privately.
2. We develop and test a fix.
3. We release the fix and publish a security advisory.
4. The reporter is free to disclose details after the fix is released.

We will credit reporters in the advisory unless they prefer to remain anonymous.

## Scope

The following areas are in scope for security reports:

- **Command gate bypasses** -- circumventing the allowed/denied command list in `lasso/core/commands.py`.
- **Container escapes** -- breaking out of the sandboxed execution environment.
- **Audit log tampering** -- forging, deleting, or modifying signed audit records in `lasso/core/audit.py`.
- **Authentication/authorization bypasses** -- gaining unauthorized access to protected methods.
- **Network policy evasion** -- circumventing iptables rules or network isolation configured in `lasso/core/network.py`.

Issues outside of these areas (e.g., denial of service against local CLI, cosmetic UI bugs in the dashboard) are welcome as regular GitHub issues but are not treated as security vulnerabilities.
