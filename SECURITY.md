# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Nexus Gate, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email the maintainer directly or use GitHub's private vulnerability reporting feature on this repository.

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to release a fix within 7 days for critical issues.

## Scope

Security issues in the following are in scope:

- **Classifier bypass** — A command that should be blocked is allowed
- **Self-protection bypass** — The AI agent can modify nexus files
- **Taint tracking evasion** — Multi-step exfiltration that evades detection
- **Dashboard auth bypass** — Unauthenticated access to admin APIs
- **Token/credential exposure** — Agent tokens or admin passwords leaked

## Out of Scope

- Variable obfuscation (`a="curl"; $a evil.com`) — blocked by default as unknown binary, documented as a known limitation
- Attacks requiring physical access to the machine
- Social engineering the human operator (not the AI agent)

## Security Design

Nexus Gate's security model is documented in the README. Key principles:

- **Default-deny** for unknown binaries
- **Structural analysis** over name-based guessing
- **User overrides cannot downgrade critical risk**
- **Self-protection is permanent and non-overridable**
- **Audit logs hash sensitive values** — never store raw secrets
- **Dashboard uses PBKDF2** with 100,000 iterations for password hashing
- **Session tokens** are cryptographically random and SHA-256 hashed
