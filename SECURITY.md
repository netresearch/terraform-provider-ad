# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| < latest | :x:               |

## Reporting a Vulnerability

1. **Do NOT open a public GitHub issue** for security vulnerabilities
2. Report via [GitHub Security Advisories](https://github.com/netresearch/terraform-provider-ad/security/advisories/new)

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Initial response**: Within 48 hours
- **Status update**: Within 7 days
- **Resolution target**: Within 30 days

## Security Measures

This project implements:

- **CodeQL** static analysis
- **Dependency scanning** via Dependabot
- **Signed releases** using GPG

## Branch Protection

The `main` branch requires:

- Pull request with 1+ approvals
- Passing CI status checks
- Up-to-date with base branch
- No force pushes
