# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in mcp-firewall, please report it responsibly:

**Email:** rr@canus.ch
**Subject:** [mcp-firewall] Security Vulnerability

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

I will acknowledge receipt within 48 hours and provide an estimated timeline for a fix.

## Scope

- mcp-firewall proxy, pipeline, policy engine, audit trail
- CLI and dashboard
- Dependencies (if vulnerability is introduced through mcp-firewall's usage)

## Out of Scope

- Vulnerabilities in MCP servers being proxied (that's what mcp-firewall protects against)
- Social engineering
- Denial of service via resource exhaustion (known limitation of any proxy)

## Disclosure

- Security fixes are released as patch versions
- CVEs are requested for critical/high vulnerabilities
- Fixes are credited to the reporter (unless anonymity is requested)
