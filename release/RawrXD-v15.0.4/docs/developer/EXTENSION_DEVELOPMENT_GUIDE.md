# RawrXD Extension Development Guide

## Phase Y.5/5: Developer Experience & Ecosystem Expansion

---

## Overview

This guide covers developing VS Code-compatible extensions for RawrXD. Extensions provide UI enhancements, language support, debugging capabilities, and integration with external tools.

---

## Getting Started

### Prerequisites

- Node.js 18+ (for TypeScript extensions)
- RawrXD Extension Host installed
- VS Code (optional, for development)

### Quick Start

```bash
# Create a new extension project
rawrxd-cli extension create MyExtension --template=typescript

# Install dependencies
cd MyExtension
npm install

# Build the extension
npm run build

# Package the extension
rawrxd-cli extension package

# Install the extension
rawrxd-cli extension install MyExtension-1.0.0.vsix
```

---

## Extension Structure

### Minimum Extension

```typescript
// src/extension.ts
import * as rawrxd from 'rawrxd';

export function activate(context: rawrxd.ExtensionContext) {
    console.log('MyExtension is now active');
    
    // Register a command
    const disposable = rawrxd.commands.registerCommand('myextension.hello', () => {
        rawrxd.window.showInformationMessage('Hello from MyExtension!');
    });
    
    context.subscriptions.push(disposable);
}

export function deactivate() {
    console.log('MyExtension is now deactivated');
}
```

### package.json

```json
{
    "name": "myextension",
    "displayName": "My Extension",
    "description": "A sample extension",
    "version": "1.0.0",
    "publisher": "your-name",
    "engines": {
        "rawrxd": "^1.0.0",
        "vscode": "^1.70.0"
    },
    "categories": ["Other"],
    "keywords": ["sample", "extension"],
    "activationEvents": [
        "onCommand:myextension.hello"
    ],
    "main": "./out/extension.js",
    "contributes": {
        "commands": [
            {
                "command": "myextension.hello",
                "title": "Hello World",
                "category": "MyExtension"
            }
        ]
    },
    "scripts": {
        "build": "tsc",
        "watch": "tsc -watch",
        "package": "rawrxd-cli extension package"
    },
    "devDependencies": {
        "@types/node": "^18.0.0",
        "rawrxd-types": "^1.0.0",
        "typescript": "^5.0.0"
    }
}
```

---

## Extension API

### Commands

```typescript
// Register a command
const command = rawrxd.commands.registerCommand('myextension.doSomething', async () => {
    // Show input box
    const input = await rawrxd.window.showInputBox({
        prompt: 'Enter something'
    });
    
    if (input) {
        // Show message
        rawrxd.window.showInformationMessage(`You entered: ${input}`);
    }
});

// Execute a command
await rawrxd.commands.executeCommand('myextension.doSomething');

// Dispose when done
command.dispose();
```

### Workspace

```typescript
// Get workspace folders
const folders = rawrxd.workspace.workspaceFolders;
if (folders && folders.length > 0) {
    const rootPath = folders[0].uri.fsPath;
}

// Open a file
const document = await rawrxd.workspace.openTextDocument('/path/to/file.txt');
const editor = await rawrxd.window.showTextDocument(document);

// Edit a file
const edit = new rawrxd.WorkspaceEdit();
edit.insert(document.uri, new rawrxd.Position(0, 0), 'Hello World');
await rawrxd.workspace.applyEdit(edit);

// Watch files
const watcher = rawrxd.workspace.createFileSystemWatcher('**/*.txt');
watcher.onDidCreate(uri => console.log(`Created: ${uri}`));
watcher.onDidChange(uri => console.log(`Changed: ${uri}`));
watcher.onDidDelete(uri => console.log(`Deleted: ${uri}`));
```

### Window

```typescript
// Show messages
rawrxd.window.showInformationMessage('Info message');
rawrxd.window.showWarningMessage('Warning message');
rawrxd.window.showErrorMessage('Error message');

// Show input box
const result = await rawrxd.window.showInputBox({
    prompt: 'Enter your name',
    placeHolder: 'John Doe'
});

// Show quick pick
const choice = await rawrxd.window.showQuickPick(['Option 1', 'Option 2', 'Option 3'], {
    placeHolder: 'Select an option'
});

// Show file dialog
const files = await rawrxd.window.showOpenDialog({
    canSelectFiles: true,
    canSelectFolders: false,
    canSelectMany: false
});

// Create status bar item
const statusBarItem = rawrxd.window.createStatusBarItem(
    rawrxd.StatusBarAlignment.Left,
    100
);
statusBarItem.text = "$(sync~spin) Loading...";
statusBarItem.show();

// Create output channel
const outputChannel = rawrxd.window.createOutputChannel('MyExtension');
outputChannel.appendLine('Extension activated');
outputChannel.show();
```

### Terminal

```typescript
// Create terminal
const terminal = rawrxd.window.createTerminal('My Terminal');
terminal.sendText('echo "Hello from extension"');
terminal.show();

// Handle terminal close
rawrxd.window.onDidCloseTerminal(terminal => {
    console.log(`Terminal closed: ${terminal.name}`);
});
```

### Language Features

```typescript
// Register completion provider
const provider = rawrxd.languages.registerCompletionItemProvider(
    'javascript',
    {
        provideCompletionItems(document, position) {
            const completion = new rawrxd.CompletionItem('console');
            completion.kind = rawrxd.CompletionItemKind.Variable;
            completion.documentation = 'Console object';
            return [completion];
        }
    },
    '.' // Trigger character
);

// Register hover provider
rawrxd.languages.registerHoverProvider('javascript', {
    provideHover(document, position) {
        const word = document.getText(document.getWordRangeAtPosition(position));
        if (word === 'console') {
            return new rawrxd.Hover('The console object provides access to the browser\'s debugging console.');
        }
    }
});

// Register definition provider
rawrxd.languages.registerDefinitionProvider('javascript', {
    provideDefinition(document, position) {
        // Return definition location
        return new rawrxd.Location(
            document.uri,
            new rawrxd.Position(10, 0)
        );
    }
});

// Register diagnostics
const collection = rawrxd.languages.createDiagnosticCollection('myextension');
const diagnostics: rawrxd.Diagnostic[] = [];
diagnostics.push(new rawrxd.Diagnostic(
    new rawrxd.Range(0, 0, 0, 10),
    'This is an error',
    rawrxd.DiagnosticSeverity.Error
));
collection.set(document.uri, diagnostics);
```

### Configuration

```typescript
// Get configuration
const config = rawrxd.workspace.getConfiguration('myextension');
const setting = config.get<string>('mySetting', 'default');

// Update configuration
await config.update('mySetting', 'new value', true);

// Watch configuration changes
rawrxd.workspace.onDidChangeConfiguration(event => {
    if (event.affectsConfiguration('myextension.mySetting')) {
        console.log('Setting changed');
    }
});
```

### Progress

```typescript
// Show progress
await rawrxd.window.withProgress({
    location: rawrxd.ProgressLocation.Notification,
    title: 'Doing work',
    cancellable: true
}, async (progress, token) => {
    token.onCancellationRequested(() => {
        console.log('User cancelled');
    });
    
    progress.report({ increment: 0 });
    
    for (let i = 0; i < 10; i++) {
        if (token.isCancellationRequested) {
            break;
        }
        
        await new Promise(resolve => setTimeout(resolve, 1000));
        progress.report({ increment: 10, message: `Step ${i + 1}/10` });
    }
});
```

---

## Extension Manifest

### Activation Events

```json
{
    "activationEvents": [
        "onCommand:myextension.hello",
        "onLanguage:javascript",
        "onView:myextension.myView",
        "onDebug",
        "workspaceContains:**/*.myext",
        "*"
    ]
}
```

### Contributions

```json
{
    "contributes": {
        "commands": [
            {
                "command": "myextension.hello",
                "title": "Hello World",
                "icon": "$(hello)"
            }
        ],
        "menus": {
            "commandPalette": [
                {
                    "command": "myextension.hello",
                    "when": "editorLangId == javascript"
                }
            ],
            "editor/context": [
                {
                    "command": "myextension.hello",
                    "group": "mygroup@1"
                }
            ]
        },
        "keybindings": [
            {
                "command": "myextension.hello",
                "key": "ctrl+shift+h",
                "mac": "cmd+shift+h"
            }
        ],
        "configuration": {
            "title": "My Extension",
            "properties": {
                "myextension.enabled": {
                    "type": "boolean",
                    "default": true,
                    "description": "Enable My Extension"
                },
                "myextension.timeout": {
                    "type": "number",
                    "default": 30,
                    "description": "Timeout in seconds"
                }
            }
        },
        "views": {
            "explorer": [
                {
                    "id": "myextension.myView",
                    "name": "My View"
                }
            ]
        },
        "themes": [
            {
                "label": "My Theme",
                "uiTheme": "vs-dark",
                "path": "./themes/my-theme.json"
            }
        ],
        "grammars": [
            {
                "language": "mylang",
                "scopeName": "source.mylang",
                "path": "./syntaxes/mylang.tmLanguage.json"
            }
        ]
    }
}
```

---

## Building Extensions

### TypeScript Configuration

```json
// tsconfig.json
{
    "compilerOptions": {
        "module": "commonjs",
        "target": "ES2020",
        "lib": ["ES2020"],
        "outDir": "out",
        "rootDir": "src",
        "strict": true,
        "esModuleInterop": true,
        "skipLibCheck": true,
        "forceConsistentCasingInFileNames": true
    },
    "exclude": ["node_modules", ".rawrxd"]
}
```

### Build Commands

```bash
# Compile TypeScript
npm run build

# Watch for changes
npm run watch

# Run tests
npm test

# Package extension
rawrxd-cli extension package

# Publish extension
rawrxd-cli extension publish
```

---

## Testing Extensions

### Unit Tests

```typescript
// src/test/suite/extension.test.ts
import * as assert from 'assert';
import * as rawrxd from 'rawrxd';
import * as myExtension from '../../extension';

suite('Extension Test Suite', () => {
    rawrxd.window.showInformationMessage('Start all tests.');
    
    test('Sample test', () => {
        assert.strictEqual(-1, [1, 2, 3].indexOf(5));
        assert.strictEqual(-1, [1, 2, 3].indexOf(0));
    });
});
```

### Integration Tests

```typescript
// src/test/runTest.ts
import * as path from 'path';
import { runTests } from 'rawrxd-test';

async function main() {
    try {
        const extensionDevelopmentPath = path.resolve(__dirname, '../../');
        const extensionTestsPath = path.resolve(__dirname, './suite/index');
        
        await runTests({
            extensionDevelopmentPath,
            extensionTestsPath
        });
    } catch (err) {
        console.error('Failed to run tests');
        process.exit(1);
    }
}

main();
```

---

## Publishing Extensions

### Package Structure

```
MyExtension-1.0.0.vsix
├── extension/
│   ├── package.json
│   ├── README.md
│   ├── LICENSE
│   ├── CHANGELOG.md
│   ├── out/
│   │   └── extension.js
│   └── resources/
│       └── icon.png
└── [Content_Types].xml
```

### Publishing Commands

```bash
# Package extension
rawrxd-cli extension package

# Validate extension
rawrxd-cli extension validate MyExtension-1.0.0.vsix

# Publish to marketplace
rawrxd-cli extension publish MyExtension-1.0.0.vsix

# Publish to private registry
rawrxd-cli extension publish MyExtension-1.0.0.vsix \
    --registry=https://extensions.mycompany.com
```

---

## Debugging Extensions

### Launch Configuration

```json
// .rawrxd/launch.json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Run Extension",
            "type": "extensionHost",
            "request": "launch",
            "args": [
                "--extensionDevelopmentPath=${workspaceFolder}"
            ],
            "outFiles": [
                "${workspaceFolder}/out/**/*.js"
            ],
            "preLaunchTask": "${defaultBuildTask}"
        }
    ]
}
```

### Debug Commands

```bash
# Start extension host in debug mode
rawrxd --extensionDevelopmentPath=./MyExtension

# Attach debugger
rawrxd-cli debug attach --extension=MyExtension

# View extension logs
rawrxd-cli extension logs MyExtension --follow
```

---

## Best Practices

### Performance

```typescript
// Lazy load heavy modules
let heavyModule: typeof import('heavy-module') | undefined;

async function doSomethingHeavy() {
    if (!heavyModule) {
        heavyModule = await import('heavy-module');
    }
    return heavyModule.doSomething();
}

// Dispose resources properly
class MyExtension {
    private disposables: rawrxd.Disposable[] = [];
    
    activate(context: rawrxd.ExtensionContext) {
        this.disposables.push(
            rawrxd.commands.registerCommand('myextension.cmd', () => {})
        );
        
        context.subscriptions.push(...this.disposables);
    }
    
    deactivate() {
        this.disposables.forEach(d => d.dispose());
    }
}
```

### Error Handling

```typescript
async function safeOperation() {
    try {
        await riskyOperation();
    } catch (error) {
        rawrxd.window.showErrorMessage(`Operation failed: ${error}`);
        console.error(error);
    }
}
```

### User Experience

```typescript
// Show progress for long operations
await rawrxd.window.withProgress({
    location: rawrxd.ProgressLocation.Notification,
    title: 'Processing...',
    cancellable: true
}, async (progress, token) => {
    // Operation with progress updates
});

// Provide feedback
rawrxd.window.showInformationMessage(
    'Operation completed successfully',
    'Open Results'
).then(selection => {
    if (selection === 'Open Results') {
        // Open results
    }
});
```

---

## Troubleshooting

### Common Issues

#### Extension Not Activating

- Check activationEvents in package.json
- Verify main entry point exists
- Check extension host logs

#### Commands Not Working

- Verify command is registered
- Check contributes.commands in package.json
- Ensure no command name conflicts

#### Language Features Not Showing

- Verify language ID matches
- Check provider registration
- Ensure document selector is correct

### Debug Commands

```bash
# List installed extensions
rawrxd-cli extension list

# Get extension info
rawrxd-cli extension info MyExtension

# Check extension health
rawrxd-cli extension health MyExtension

# Reload extension
rawrxd-cli extension reload MyExtension

# Enable/disable extension
rawrxd-cli extension enable MyExtension
rawrxd-cli extension disable MyExtension
```

---

## Examples

### Example 1: File Explorer Enhancement

```typescript
// Add custom tree view to explorer
export function activate(context: rawrxd.ExtensionContext) {
    const treeDataProvider = new MyTreeDataProvider();
    
    rawrxd.window.registerTreeDataProvider('myextension.myView', treeDataProvider);
    
    rawrxd.commands.registerCommand('myextension.refresh', () => {
        treeDataProvider.refresh();
    });
}

class MyTreeDataProvider implements rawrxd.TreeDataProvider<MyTreeItem> {
    private _onDidChangeTreeData = new rawrxd.EventEmitter<MyTreeItem | undefined>();
    readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
    
    refresh(): void {
        this._onDidChangeTreeData.fire(undefined);
    }
    
    getTreeItem(element: MyTreeItem): rawrxd.TreeItem {
        return element;
    }
    
    getChildren(element?: MyTreeItem): Thenable<MyTreeItem[]> {
        if (!element) {
            return Promise.resolve([
                new MyTreeItem('Item 1', rawrxd.TreeItemCollapsibleState.None),
                new MyTreeItem('Item 2', rawrxd.TreeItemCollapsibleState.Collapsed)
            ]);
        }
        return Promise.resolve([]);
    }
}

class MyTreeItem extends rawrxd.TreeItem {
    constructor(
        public readonly label: string,
        public readonly collapsibleState: rawrxd.TreeItemCollapsibleState
    ) {
        super(label, collapsibleState);
        this.tooltip = label;
        this.iconPath = new rawrxd.ThemeIcon('file');
    }
}
```

### Example 2: Custom Language Support

```typescript
// Register language support
export function activate(context: rawrxd.ExtensionContext) {
    // Document symbol provider
    context.subscriptions.push(
        rawrxd.languages.registerDocumentSymbolProvider('mylang', {
            provideDocumentSymbols(document) {
                const symbols: rawrxd.DocumentSymbol[] = [];
                // Parse document and extract symbols
                return symbols;
            }
        })
    );
    
    // Formatting provider
    context.subscriptions.push(
        rawrxd.languages.registerDocumentFormattingEditProvider('mylang', {
            provideDocumentFormattingEdits(document) {
                const edits: rawrxd.TextEdit[] = [];
                // Format document
                return edits;
            }
        })
    );
}
```

---

## API Reference

See `rawrxd-types` package for complete TypeScript API definitions.

---

*Guide Version: 1.0.0*  
*Last Updated: 2026-07-13*
