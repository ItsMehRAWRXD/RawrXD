# Sovereign IDE — Training Module 11
## Expert Path: Extension Development

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Difficulty:** Expert  
**Duration:** 8 hours

---

## 1. Module Overview

This module covers expert-level extension development for the Sovereign IDE. By the end of this module, you will be able to:

- Create complex extensions with multiple features
- Integrate with IDE APIs and services
- Implement custom views and editors
- Handle extension lifecycle and state
- Package and publish extensions

---

## 2. Extension Architecture

### 2.1 Extension Structure

```
my-extension/
├── package.json              # Extension manifest
├── extension.js              # Main entry point
├── src/
│   ├── commands.js           # Command implementations
│   ├── providers.js          # Language providers
│   ├── views.js              # Custom views
│   └── utils.js              # Utility functions
├── resources/
│   ├── icons/                # Extension icons
│   └── templates/            # File templates
├── test/
│   └── extension.test.js     # Unit tests
├── README.md
├── CHANGELOG.md
└── LICENSE
```

### 2.2 Extension Lifecycle

```javascript
// Activation
function activate(context) {
    // Register commands
    // Register providers
    // Initialize state
    // Setup event listeners
}

// Deactivation
function deactivate() {
    // Cleanup resources
    // Save state
    // Dispose subscriptions
}
```

### 2.3 Context Subscriptions

```javascript
function activate(context) {
    // Commands
    context.subscriptions.push(
        sovereign.commands.registerCommand('ext.hello', () => {
            sovereign.window.showInformationMessage('Hello!');
        })
    );
    
    // Event listeners
    context.subscriptions.push(
        sovereign.workspace.onDidChangeTextDocument(event => {
            console.log('Document changed:', event.document.fileName);
        })
    );
    
    // Disposables
    const statusBarItem = sovereign.window.createStatusBarItem();
    context.subscriptions.push(statusBarItem);
}
```

---

## 3. Commands and Menus

### 3.1 Command Registration

```javascript
// Simple command
sovereign.commands.registerCommand('ext.sayHello', () => {
    sovereign.window.showInformationMessage('Hello World!');
});

// Command with arguments
sovereign.commands.registerCommand('ext.openFile', (filePath) => {
    sovereign.workspace.openTextDocument(filePath)
        .then(doc => sovereign.window.showTextDocument(doc));
});

// Async command
sovereign.commands.registerCommand('ext.fetchData', async () => {
    const result = await fetchData();
    sovereign.window.showInformationMessage(`Fetched: ${result}`);
});
```

### 3.2 Menu Contributions

```json
{
    "contributes": {
        "commands": [
            {
                "command": "ext.sayHello",
                "title": "Say Hello",
                "category": "My Extension"
            }
        ],
        "menus": {
            "commandPalette": [
                {
                    "command": "ext.sayHello",
                    "when": "editorIsOpen"
                }
            ],
            "editor/context": [
                {
                    "command": "ext.sayHello",
                    "group": "myGroup@1"
                }
            ],
            "explorer/context": [
                {
                    "command": "ext.openFile",
                    "when": "explorerResourceIsFile"
                }
            ]
        }
    }
}
```

---

## 4. Language Providers

### 4.1 Completion Provider

```javascript
const sovereign = require('sovereign');

class MyCompletionProvider {
    provideCompletionItems(document, position, token, context) {
        const linePrefix = document.lineAt(position).text.substr(0, position.character);
        
        if (linePrefix.endsWith('my.')) {
            return [
                new sovereign.CompletionItem('function', sovereign.CompletionItemKind.Function),
                new sovereign.CompletionItem('variable', sovereign.CompletionItemKind.Variable),
                new sovereign.CompletionItem('class', sovereign.CompletionItemKind.Class)
            ];
        }
        
        return [];
    }
}

sovereign.languages.registerCompletionItemProvider(
    'javascript',
    new MyCompletionProvider(),
    '.'
);
```

### 4.2 Hover Provider

```javascript
class MyHoverProvider {
    provideHover(document, position, token) {
        const wordRange = document.getWordRangeAtPosition(position);
        const word = document.getText(wordRange);
        
        if (word === 'myFunction') {
            return new sovereign.Hover(
                new sovereign.MarkdownString('**myFunction** - Does something useful')
            );
        }
        
        return null;
    }
}

sovereign.languages.registerHoverProvider('javascript', new MyHoverProvider());
```

### 4.3 Definition Provider

```javascript
class MyDefinitionProvider {
    provideDefinition(document, position, token) {
        const wordRange = document.getWordRangeAtPosition(position);
        const word = document.getText(wordRange);
        
        // Find definition location
        const definitionLocation = findDefinition(word);
        
        if (definitionLocation) {
            return new sovereign.Location(
                sovereign.Uri.file(definitionLocation.file),
                new sovereign.Position(definitionLocation.line, 0)
            );
        }
        
        return null;
    }
}

sovereign.languages.registerDefinitionProvider('javascript', new MyDefinitionProvider());
```

---

## 5. Custom Views

### 5.1 Tree View

```javascript
class MyTreeDataProvider {
    constructor() {
        this._onDidChangeTreeData = new sovereign.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
    }
    
    refresh() {
        this._onDidChangeTreeData.fire();
    }
    
    getTreeItem(element) {
        return element;
    }
    
    getChildren(element) {
        if (!element) {
            // Return root items
            return Promise.resolve([
                new sovereign.TreeItem('Item 1'),
                new sovereign.TreeItem('Item 2'),
                new sovereign.TreeItem('Item 3')
            ]);
        }
        
        // Return children of element
        return Promise.resolve([]);
    }
}

const treeDataProvider = new MyTreeDataProvider();
sovereign.window.registerTreeDataProvider('myView', treeDataProvider);
```

### 5.2 Webview Panel

```javascript
function createWebviewPanel() {
    const panel = sovereign.window.createWebviewPanel(
        'myWebview',
        'My Webview',
        sovereign.ViewColumn.One,
        {
            enableScripts: true,
            retainContextWhenHidden: true
        }
    );
    
    panel.webview.html = `
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: sans-serif; padding: 20px; }
            </style>
        </head>
        <body>
            <h1>My Extension Webview</h1>
            <button id="button">Click Me</button>
            <script>
                const button = document.getElementById('button');
                button.addEventListener('click', () => {
                    // Send message to extension
                    vscode.postMessage({ command: 'buttonClicked' });
                });
            </script>
        </body>
        </html>
    `;
    
    // Handle messages from webview
    panel.webview.onDidReceiveMessage(
        message => {
            switch (message.command) {
                case 'buttonClicked':
                    sovereign.window.showInformationMessage('Button clicked!');
                    return;
            }
        },
        undefined,
        context.subscriptions
    );
}
```

---

## 6. Configuration and State

### 6.1 Configuration API

```javascript
// Read configuration
const config = sovereign.workspace.getConfiguration('myExtension');
const setting = config.get('mySetting', 'default');
const numberSetting = config.get('numberSetting', 42);

// Update configuration
await config.update('mySetting', 'newValue', true);  // Global
await config.update('mySetting', 'newValue', false); // Workspace

// Listen for changes
sovereign.workspace.onDidChangeConfiguration(event => {
    if (event.affectsConfiguration('myExtension.mySetting')) {
        console.log('Setting changed!');
    }
});
```

### 6.2 State Management

```javascript
// Global state (persists across sessions)
const globalState = context.globalState;
globalState.update('key', 'value');
const value = globalState.get('key');

// Workspace state (per workspace)
const workspaceState = context.workspaceState;
workspaceState.update('key', 'value');

// Secrets (encrypted storage)
const secrets = context.secrets;
await secrets.store('apiKey', 'secret123');
const apiKey = await secrets.get('apiKey');
await secrets.delete('apiKey');
```

---

## 7. Testing Extensions

### 7.1 Test Setup

```javascript
// test/extension.test.js
const assert = require('assert');
const sovereign = require('sovereign');

describe('Extension Test Suite', () => {
    before(async () => {
        // Activate extension
        const ext = sovereign.extensions.getExtension('publisher.myExtension');
        await ext.activate();
    });
    
    it('Command should be registered', async () => {
        const commands = await sovereign.commands.getCommands();
        assert.ok(commands.includes('ext.sayHello'));
    });
    
    it('Should provide completions', async () => {
        const doc = await sovereign.workspace.openTextDocument({
            language: 'javascript',
            content: 'my.'
        });
        
        const completions = await sovereign.commands.executeCommand(
            'sovereign.executeCompletionProvider',
            doc.uri,
            new sovereign.Position(0, 3)
        );
        
        assert.ok(completions.items.length > 0);
    });
});
```

### 7.2 Running Tests

```bash
# Install test dependencies
npm install --save-dev @types/sovereign

# Run tests
npm test

# Debug tests
npm run test:debug
```

---

## 8. Packaging and Publishing

### 8.1 Packaging

```bash
# Install vsce (Sovereign Extension CLI)
npm install -g @sovereign/vsce

# Package extension
vsce package

# Output: my-extension-1.0.0.vsix
```

### 8.2 Publishing

```bash
# Login to marketplace
vsce login

# Publish extension
vsce publish

# Publish specific version
vsce publish 1.1.0
```

### 8.3 Pre-publish Checklist

- [ ] Update version in package.json
- [ ] Update CHANGELOG.md
- [ ] Run all tests
- [ ] Update README.md
- [ ] Add icon (128x128)
- [ ] Verify license
- [ ] Test in clean environment

---

## 9. Practical Exercises

### Exercise 1: Command Extension

**Objective:** Create command-based extension

**Tasks:**
1. Generate extension template
2. Register 3 commands
3. Add menu contributions
4. Test commands

**Expected Time:** 45 minutes

### Exercise 2: Language Provider

**Objective:** Implement completion provider

**Tasks:**
1. Create completion provider
2. Register for language
3. Implement logic
4. Test completions

**Expected Time:** 60 minutes

### Exercise 3: Custom View

**Objective:** Create tree view

**Tasks:**
1. Implement TreeDataProvider
2. Register view
3. Add commands
4. Handle events

**Expected Time:** 75 minutes

### Exercise 4: Webview Extension

**Objective:** Create webview panel

**Tasks:**
1. Create webview
2. Add HTML/CSS/JS
3. Handle messages
4. Manage lifecycle

**Expected Time:** 60 minutes

### Exercise 5: Complete Extension

**Objective:** Build production-ready extension

**Tasks:**
1. Combine all features
2. Add configuration
3. Write tests
4. Package and test

**Expected Time:** 90 minutes

---

## 10. Module Assessment

### Knowledge Check

1. What is the purpose of context.subscriptions?
2. How do you register a completion provider?
3. What is the difference between globalState and workspaceState?
4. How do you handle messages from a webview?
5. What is the vsce tool used for?

### Practical Assessment

Build complete extension:
1. Create extension with 3+ features
2. Implement language provider
3. Add custom view
4. Write tests
5. Package extension

**Pass Criteria:** Successfully complete all exercises

---

## 11. Next Steps

Upon completing this module:

1. Proceed to **Module 12: Expert Path - SDK Integration**
2. Publish extension to marketplace
3. Join extension developer community
4. Contribute to open source extensions

---

## Summary

This module covered:

- ✅ Extension architecture
- ✅ Commands and menus
- ✅ Language providers
- ✅ Custom views
- ✅ Configuration and state
- ✅ Testing
- ✅ Packaging and publishing

**Status:** Complete

---

*End of Module 11: Expert Path - Extension Development*
