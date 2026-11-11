# Sovereign IDE — Training Module 8
## Developer Path: Extensions

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Difficulty:** Intermediate  
**Duration:** 5 hours

---

## 1. Module Overview

This module covers extension management and usage in the Sovereign IDE. By the end of this module, you will be able to:

- Browse and install extensions
- Configure extension settings
- Manage extension updates
- Troubleshoot extension issues
- Use key extensions effectively

---

## 2. Extension Marketplace

### 2.1 Browsing Extensions

**Open Extensions View:** `Ctrl+Shift+X`

**Search Options:**
- By name: "C++"
- By category: "@category:debuggers"
- By tag: "@tag:python"
- Installed: "@installed"
- Recommended: "@recommended"

**Extension Information:**
- Name and publisher
- Version and rating
- Download count
- Description
- Categories and tags

### 2.2 Installing Extensions

**Install Methods:**
1. Click "Install" on extension page
2. Command Palette → Extensions: Install Extensions
3. Install from VSIX: `...` menu → Install from VSIX

**Extension Types:**
- **UI Extensions:** Run in IDE process
- **Workspace Extensions:** Run in workspace
- **Remote Extensions:** Run on remote host

### 2.3 Managing Extensions

**Extension Actions:**
- **Disable:** Temporarily disable
- **Uninstall:** Remove extension
- **Enable:** Re-enable disabled
- **Update:** Update to latest
- **Configure:** Open settings

**Bulk Operations:**
```bash
# Update all extensions
Extensions: Update All Extensions

# Disable all extensions
Extensions: Disable All Extensions
```

---

## 3. Essential Extensions

### 3.1 Language Support

| Extension | Purpose | Category |
|-----------|---------|----------|
| C/C++ | IntelliSense, debugging | Language |
| Python | IntelliSense, linting | Language |
| JavaScript/TypeScript | Language support | Language |
| Rust | Language server | Language |
| Go | Language support | Language |

### 3.2 Development Tools

| Extension | Purpose | Category |
|-----------|---------|----------|
| GitLens | Enhanced Git | SCM |
| Docker | Container management | DevOps |
| REST Client | API testing | Testing |
| Markdown All in One | Markdown support | Documentation |
| Code Spell Checker | Spell checking | Quality |

### 3.3 Sovereign IDE Extensions

| Extension | Purpose | Features |
|-----------|---------|----------|
| Sovereign AI | AI integration | Code completion, analysis |
| Sovereign Binary | Binary analysis | Disassembly, CFG |
| Sovereign MoE | Model management | Expert pruning |
| Sovereign SEG | Distributed computing | Task scheduling |

---

## 4. Extension Configuration

### 4.1 Extension Settings

**Access Settings:**
1. Extensions → Right-click → Extension Settings
2. Or: File → Preferences → Settings → Extensions

**Settings Structure:**
```json
{
    "extension.name.setting": value,
    "python.pythonPath": "/usr/bin/python3",
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": true
}
```

### 4.2 Workspace vs User Settings

**User Settings:** (`~/.config/Sovereign/settings.json`)
- Apply globally
- Personal preferences

**Workspace Settings:** (`.sovereign/settings.json`)
- Project-specific
- Shared with team

**Example:**
```json
// User settings
{
    "editor.fontSize": 14,
    "editor.theme": "Sovereign Dark"
}

// Workspace settings
{
    "python.pythonPath": "./venv/bin/python",
    "python.testing.pytestEnabled": true
}
```

### 4.3 Extension Keybindings

**Configure Keybindings:**
1. File → Preferences → Keyboard Shortcuts
2. Search for extension commands
3. Assign custom shortcuts

**Example:**
```json
[
    {
        "key": "ctrl+shift+t",
        "command": "python.runtests",
        "when": "editorTextFocus"
    }
]
```

---

## 5. Extension Development

### 5.1 Extension Structure

```
my-extension/
├── package.json          # Extension manifest
├── extension.js          # Main entry point
├── README.md             # Documentation
├── CHANGELOG.md          # Version history
└── resources/
    └── icon.png          # Extension icon
```

### 5.2 package.json

```json
{
    "name": "my-extension",
    "displayName": "My Extension",
    "description": "Does something useful",
    "version": "1.0.0",
    "publisher": "myname",
    "engines": {
        "sovereign": "^1.0.0"
    },
    "categories": ["Other"],
    "activationEvents": [
        "onCommand:myExtension.hello"
    ],
    "main": "./extension.js",
    "contributes": {
        "commands": [
            {
                "command": "myExtension.hello",
                "title": "Hello World"
            }
        ],
        "configuration": {
            "title": "My Extension",
            "properties": {
                "myExtension.enabled": {
                    "type": "boolean",
                    "default": true,
                    "description": "Enable extension"
                }
            }
        }
    }
}
```

### 5.3 Extension API

```javascript
// extension.js
const sovereign = require('sovereign');

function activate(context) {
    console.log('Extension activated');
    
    let disposable = sovereign.commands.registerCommand(
        'myExtension.hello',
        () => {
            sovereign.window.showInformationMessage('Hello World!');
        }
    );
    
    context.subscriptions.push(disposable);
}

function deactivate() {
    console.log('Extension deactivated');
}

module.exports = { activate, deactivate };
```

---

## 6. Extension Troubleshooting

### 6.1 Common Issues

| Issue | Solution |
|-------|----------|
| Extension not loading | Check activation events |
| Commands not found | Reload window |
| Settings not applying | Check scope (user/workspace) |
| Performance issues | Disable unused extensions |
| Conflicts | Check extension compatibility |

### 6.2 Debugging Extensions

**Enable Extension Debugging:**
1. Open Extension Development Host
2. Set breakpoints in extension code
3. Run extension

**Extension Logs:**
```bash
# View extension host logs
Help → Toggle Developer Tools → Console

# Extension-specific logs
Extensions → Extension → View Logs
```

### 6.3 Safe Mode

**Start in Safe Mode:**
```bash
# Disable all extensions
sovereign --disable-extensions

# Or via command palette
Developer: Reload Window With Extensions Disabled
```

---

## 7. Recommended Extension Sets

### 7.1 C++ Development

```json
{
    "recommendations": [
        "sovereign.cpptools",
        "sovereign.cmake-tools",
        "sovereign.clang-format",
        "sovereign.code-spell-checker"
    ]
}
```

### 7.2 Python Development

```json
{
    "recommendations": [
        "sovereign.python",
        "sovereign.pylint",
        "sovereign.black-formatter",
        "sovereign.jupyter"
    ]
}
```

### 7.3 Web Development

```json
{
    "recommendations": [
        "sovereign.eslint",
        "sovereign.prettier",
        "sovereign.html-css-support",
        "sovereign.live-server"
    ]
}
```

---

## 8. Practical Exercises

### Exercise 1: Install and Configure Extensions

**Objective:** Set up development environment

**Tasks:**
1. Install C/C++ extension
2. Configure include paths
3. Install code formatter
4. Configure formatting on save

**Expected Time:** 20 minutes

### Exercise 2: Extension Settings

**Objective:** Configure extension settings

**Tasks:**
1. Open extension settings
2. Modify Python interpreter path
3. Enable linting
4. Test configuration

**Expected Time:** 15 minutes

### Exercise 3: Create Simple Extension

**Objective:** Create a basic extension

**Tasks:**
1. Generate extension template
2. Implement hello world command
3. Test in development host
4. Package extension

**Expected Time:** 45 minutes

### Exercise 4: Troubleshoot Extension

**Objective:** Fix extension issues

**Tasks:**
1. Identify conflicting extensions
2. Check extension logs
3. Disable problematic extension
4. Verify fix

**Expected Time:** 20 minutes

---

## 9. Module Assessment

### Knowledge Check

1. How do you install an extension from a VSIX file?
2. What is the difference between user and workspace settings?
3. How do you configure extension keybindings?
4. What is the purpose of activationEvents in package.json?
5. How do you start Sovereign IDE in safe mode?

### Practical Assessment

Complete extension workflow:
1. Install 3 extensions
2. Configure extension settings
3. Create a simple extension
4. Troubleshoot an issue

**Pass Criteria:** Successfully complete all exercises

---

## 10. Next Steps

Upon completing this module:

1. Proceed to **Module 9: Advanced Path - Binary Analysis**
2. Explore more extensions
3. Consider creating custom extensions
4. Join extension developer community

---

## Summary

This module covered:

- ✅ Extension marketplace
- ✅ Essential extensions
- ✅ Extension configuration
- ✅ Extension development basics
- ✅ Troubleshooting
- ✅ Recommended extension sets

**Status:** Complete

---

*End of Module 8: Developer Path - Extensions*
