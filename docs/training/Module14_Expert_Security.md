# Sovereign IDE — Training Module 14
## Expert Path: Security

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Difficulty:** Expert  
**Duration:** 6 hours

---

## 1. Module Overview

This module covers security best practices for the Sovereign IDE. By the end of this module, you will be able to:

- Understand IDE security model
- Secure extension development
- Configure secure settings
- Audit extensions and code
- Implement secure workflows

---

## 2. Security Model

### 2.1 Extension Security

**Extension Isolation:**
- Extensions run in separate processes
- Limited access to system resources
- Permission-based API access
- Sandboxed execution

**Trust Model:**
```
Untrusted → Workspace Trust → Full Access
    ↓              ↓              ↓
 Limited      Restricted      Complete
```

### 2.2 Workspace Trust

**Trust Levels:**

| Level | Description | Capabilities |
|-------|-------------|--------------|
| Untrusted | Unknown source | Read-only |
| Restricted | Basic trust | Limited execution |
| Trusted | Verified source | Full access |

**Configure Trust:**
1. File → Preferences → Security → Workspace Trust
2. Add trusted folders
3. Set default trust level

---

## 3. Secure Extension Development

### 3.1 Input Validation

```javascript
// Validate file paths
function isValidPath(filePath) {
    // Prevent path traversal
    const resolved = path.resolve(filePath);
    const workspaceRoot = path.resolve(workspaceFolder);
    return resolved.startsWith(workspaceRoot);
}

// Validate user input
function sanitizeInput(input) {
    // Remove potentially dangerous characters
    return input.replace(/[<>\"']/g, '');
}

// Validate URLs
function isValidUrl(url) {
    try {
        const parsed = new URL(url);
        return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
        return false;
    }
}
```

### 3.2 Secure Storage

```javascript
// Use SecretStorage for sensitive data
const secrets = context.secrets;

// Store API key
await secrets.store('apiKey', 'secret123');

// Retrieve API key
const apiKey = await secrets.get('apiKey');

// Delete when no longer needed
await secrets.delete('apiKey');
```

### 3.3 Command Injection Prevention

```javascript
// Bad - vulnerable to injection
const { exec } = require('child_process');
exec(`gcc ${userInput}`); // Dangerous!

// Good - use parameterized commands
const { spawn } = require('child_process');
const proc = spawn('gcc', [userInput]); // Safe

// Validate before execution
const allowedFiles = ['main.c', 'utils.c'];
if (!allowedFiles.includes(userInput)) {
    throw new Error('Invalid file');
}
```

---

## 4. Secure Configuration

### 4.1 Settings Security

```json
{
    "security.workspace.trust.enabled": true,
    "security.workspace.trust.startupPrompt": "always",
    "security.restrictedMode.enabled": true,
    "security.allowedUNCHosts": [],
    "security.disableExecution": false
}
```

### 4.2 Extension Permissions

**Declare Permissions:**
```json
{
    "capabilities": {
        "untrustedWorkspaces": {
            "supported": "limited"
        }
    },
    "contributes": {
        "commands": [],
        "menus": []
    }
}
```

### 4.3 Network Security

```javascript
// Validate certificates
const https = require('https');
const options = {
    hostname: 'api.example.com',
    port: 443,
    path: '/data',
    method: 'GET',
    rejectUnauthorized: true // Verify SSL
};

// Use proxy settings
const proxyUrl = vscode.workspace.getConfiguration('http').get('proxy');
```

---

## 5. Code Auditing

### 5.1 Static Analysis

**Enable Security Linting:**
```json
{
    "eslint.security.enable": true,
    "eslint.security.rules": {
        "no-eval": "error",
        "no-implied-eval": "error",
        "no-new-func": "error"
    }
}
```

### 5.2 Dependency Scanning

**Check Dependencies:**
```bash
# Audit npm packages
npm audit

# Fix vulnerabilities
npm audit fix

# Check for outdated packages
npm outdated
```

### 5.3 Extension Audit

**Audit Checklist:**
- [ ] No hardcoded secrets
- [ ] Input validation
- [ ] Secure API usage
- [ ] Proper error handling
- [ ] No eval() or new Function()
- [ ] Sanitized HTML output
- [ ] Validated file paths

---

## 6. Secure Workflows

### 6.1 Git Security

**Configure Git:**
```bash
# Verify commits
git config --global commit.gpgsign true

# Check for secrets
git config --global core.hooksPath .githooks

# Use SSH for remotes
git remote set-url origin git@github.com:user/repo.git
```

### 6.2 CI/CD Security

**Secure Pipeline:**
```yaml
# .github/workflows/secure.yml
name: Secure Build
on: [push]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run security scan
        run: |
          npm audit --audit-level=high
          
      - name: Check for secrets
        run: |
          git-secrets --scan
```

### 6.3 Secret Management

**Environment Variables:**
```javascript
// Use environment variables
const apiKey = process.env.API_KEY;
if (!apiKey) {
    throw new Error('API_KEY not set');
}
```

**Configuration Files:**
```json
{
    "apiKey": "${env:API_KEY}",
    "secret": "${env:SECRET}"
}
```

---

## 7. Practical Exercises

### Exercise 1: Security Audit

**Objective:** Audit extension for vulnerabilities

**Tasks:**
1. Review extension code
2. Check for injection vulnerabilities
3. Verify input validation
4. Document findings

**Expected Time:** 45 minutes

### Exercise 2: Implement Secure Storage

**Objective:** Use SecretStorage API

**Tasks:**
1. Store sensitive data
2. Retrieve data securely
3. Implement proper cleanup
4. Test security

**Expected Time:** 30 minutes

### Exercise 3: Configure Workspace Trust

**Objective:** Set up workspace security

**Tasks:**
1. Configure trust settings
2. Test restricted mode
3. Verify permissions
4. Document configuration

**Expected Time:** 25 minutes

### Exercise 4: Secure CI/CD Pipeline

**Objective:** Create secure build pipeline

**Tasks:**
1. Add security scanning
2. Configure secret detection
3. Set up dependency checks
4. Test pipeline

**Expected Time:** 40 minutes

---

## 8. Module Assessment

### Knowledge Check

1. What is the purpose of workspace trust?
2. How do you prevent command injection?
3. What is the SecretStorage API used for?
4. How do you validate file paths?
5. What should be included in a security audit?

### Practical Assessment

Secure an extension:
1. Audit for vulnerabilities
2. Implement secure storage
3. Add input validation
4. Configure security settings

**Pass Criteria:** Successfully complete all exercises

---

## 9. Next Steps

Upon completing this module:

1. Proceed to **Module 15: Expert Path - Final Project**
2. Apply security practices
3. Regular security audits
4. Stay updated on security advisories

---

## Summary

This module covered:

- ✅ Security model
- ✅ Secure extension development
- ✅ Secure configuration
- ✅ Code auditing
- ✅ Secure workflows

**Status:** Complete

---

*End of Module 14: Expert Path - Security*
