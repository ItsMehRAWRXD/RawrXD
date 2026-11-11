# Security Policy

**RAWRXD Compiler Driver**

---

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

---

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please follow these steps:

### 1. Do Not Open a Public Issue

Security vulnerabilities should **NOT** be reported through public GitHub issues.

### 2. Email the Maintainers

Send an email to: **security@rawrxd.dev**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### 3. Response Timeline

- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 7 days
- **Fix/Update**: Within 30 days (critical issues sooner)

### 4. Disclosure

Once fixed, we will:
- Release a patched version
- Credit the reporter (if desired)
- Publish a security advisory

---

## Security Considerations

### Compiler Security

The RAWRXD Compiler Driver:
- Does not execute user code
- Only invokes trusted compilers
- Validates all file paths
- Sanitizes command-line arguments

### Best Practices

When using RAWRXD Compiler Driver:

1. **Keep Updated**: Always use the latest version
2. **Verify Downloads**: Check checksums when downloading
3. **Use Trusted Compilers**: Only use compilers from trusted sources
4. **Sandbox When Possible**: Run in isolated environments for untrusted code

---

## Known Security Features

- ✅ Input validation
- ✅ Path sanitization
- ✅ Command injection prevention
- ✅ Buffer overflow protection
- ✅ No network communication
- ✅ No data collection

---

## Security History

| Date       | Issue | Severity | Status |
|------------|-------|----------|--------|
| 2026-07-19 | None reported | - | - |

---

*Last updated: 2026-07-19*
