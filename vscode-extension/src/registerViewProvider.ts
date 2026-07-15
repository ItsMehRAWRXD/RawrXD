// ============================================================================
// registerViewProvider.ts - Register View Provider
// ============================================================================
// Webview view provider for live register inspection during debugging
// Shows r0-r15 with NaN-boxed value display
//
// Copyright (c) 2026 RawrXD Project
// ============================================================================

import * as vscode from 'vscode';

export class RegisterViewProvider implements vscode.WebviewViewProvider {
    private _view?: vscode.WebviewView;
    private _registers: Map<string, { value: number; type: string; display: string }> = new Map();

    constructor(private readonly _extensionUri: vscode.Uri) {
        // Initialize with empty registers
        for (let i = 0; i < 16; i++) {
            this._registers.set(`r${i}`, { value: 0, type: 'null', display: 'null' });
        }
    }

    resolveWebviewView(
        webviewView: vscode.WebviewView,
        context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken
    ): void {
        this._view = webviewView;

        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [this._extensionUri]
        };

        webviewView.webview.html = this._getHtmlForWebview();

        // Handle messages from the webview
        webviewView.webview.onDidReceiveMessage(async (message) => {
            switch (message.command) {
                case 'refresh':
                    await this.refreshRegisters();
                    break;
                case 'copy':
                    await vscode.env.clipboard.writeText(message.value);
                    vscode.window.showInformationMessage('Register value copied to clipboard');
                    break;
            }
        });

        // Listen for debug events
        vscode.debug.onDidChangeActiveDebugSession((session) => {
            if (session?.type === 'rawrxd-script') {
                this.refreshRegisters();
            }
        });

        vscode.debug.onDidReceiveDebugSessionCustomEvent((event) => {
            if (event.session.type === 'rawrxd-script' && event.event === 'registerUpdate') {
                this.updateRegisters(event.body);
            }
        });
    }

    private async refreshRegisters() {
        // Request register values from debug session
        const session = vscode.debug.activeDebugSession;
        if (session && session.type === 'rawrxd-script') {
            try {
                const response = await session.customRequest('getRegisters');
                this.updateRegisters(response);
            } catch (e) {
                // Session might not be paused
            }
        }
    }

    private updateRegisters(data: any) {
        if (data && data.registers) {
            for (const [name, info] of Object.entries(data.registers)) {
                this._registers.set(name, info as any);
            }
            this._updateWebview();
        }
    }

    private _updateWebview() {
        if (this._view) {
            const registers = Array.from(this._registers.entries()).map(([name, info]) => ({
                name,
                ...info
            }));
            this._view.webview.postMessage({ command: 'update', registers });
        }
    }

    private _getHtmlForWebview(): string {
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RawrXD Registers</title>
    <style>
        body {
            font-family: var(--vscode-font-family);
            font-size: var(--vscode-font-size);
            color: var(--vscode-foreground);
            background: var(--vscode-editor-background);
            padding: 10px;
            margin: 0;
        }
        .register-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 8px;
        }
        .register {
            display: flex;
            align-items: center;
            padding: 6px 10px;
            background: var(--vscode-input-background);
            border: 1px solid var(--vscode-input-border);
            border-radius: 4px;
            cursor: pointer;
            transition: background 0.2s;
        }
        .register:hover {
            background: var(--vscode-list-hoverBackground);
        }
        .register-name {
            font-weight: bold;
            color: var(--vscode-symbolIcon-variableForeground);
            min-width: 30px;
        }
        .register-value {
            font-family: var(--vscode-editor-font-family);
            margin-left: 10px;
            flex: 1;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .register-type {
            font-size: 0.8em;
            color: var(--vscode-descriptionForeground);
            margin-left: 8px;
        }
        .type-number { color: #4FC1FF; }
        .type-string { color: #CE9178; }
        .type-boolean { color: #569CD6; }
        .type-object { color: #9CDCFE; }
        .type-null { color: #808080; }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .title {
            font-weight: bold;
            font-size: 1.1em;
        }
        .refresh-btn {
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none;
            padding: 4px 12px;
            border-radius: 3px;
            cursor: pointer;
        }
        .refresh-btn:hover {
            background: var(--vscode-button-hoverBackground);
        }
        .empty-state {
            text-align: center;
            color: var(--vscode-descriptionForeground);
            padding: 40px 20px;
        }
    </style>
</head>
<body>
    <div class="header">
        <span class="title">Registers (r0-r15)</span>
        <button class="refresh-btn" onclick="refresh()">Refresh</button>
    </div>
    <div id="content">
        <div class="empty-state">No active debug session</div>
    </div>
    <script>
        const vscode = acquireVsCodeApi();
        
        function refresh() {
            vscode.postMessage({ command: 'refresh' });
        }
        
        function copyValue(name, value) {
            vscode.postMessage({ command: 'copy', value: \`\${name}: \${value}\` });
        }
        
        window.addEventListener('message', event => {
            const message = event.data;
            if (message.command === 'update') {
                updateRegisters(message.registers);
            }
        });
        
        function updateRegisters(registers) {
            const content = document.getElementById('content');
            if (!registers || registers.length === 0) {
                content.innerHTML = '<div class="empty-state">No register data available</div>';
                return;
            }
            
            const grid = document.createElement('div');
            grid.className = 'register-grid';
            
            registers.forEach(reg => {
                const div = document.createElement('div');
                div.className = 'register';
                div.onclick = () => copyValue(reg.name, reg.display);
                div.innerHTML = \`
                    <span class="register-name">\${reg.name}</span>
                    <span class="register-value">\${reg.display}</span>
                    <span class="register-type type-\${reg.type}">\${reg.type}</span>
                \`;
                grid.appendChild(div);
            });
            
            content.innerHTML = '';
            content.appendChild(grid);
        }
    </script>
</body>
</html>`;
    }
}
