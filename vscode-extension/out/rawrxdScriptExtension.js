"use strict";
// ============================================================================
// rawrxdScriptExtension.ts - RawrXD-Script Extension Activation
// ============================================================================
// Main entry point for VS Code extension
// Handles LSP client and DAP debugger registration
//
// Copyright (c) 2026 RawrXD Project
// ============================================================================
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const path = __importStar(require("path"));
const vscode_languageclient_1 = require("vscode-languageclient");
const debugAdapterFactory_1 = require("./debugAdapterFactory");
const registerViewProvider_1 = require("./registerViewProvider");
let client;
let outputChannel;
function activate(context) {
    outputChannel = vscode.window.createOutputChannel('RawrXD-Script');
    outputChannel.appendLine('RawrXD-Script extension activating...');
    // Get configuration
    const config = vscode.workspace.getConfiguration('rawrxd-script');
    // ============================================================================
    // Start Language Server (LSP)
    // ============================================================================
    if (config.get('lsp.enabled', true)) {
        startLanguageServer(context);
    }
    // ============================================================================
    // Register Debug Adapter (DAP)
    // ============================================================================
    const debugAdapterFactory = new debugAdapterFactory_1.RawrXDScriptDebugAdapterFactory(outputChannel, context.extensionPath);
    context.subscriptions.push(vscode.debug.registerDebugAdapterDescriptorFactory('rawrxd-script', debugAdapterFactory));
    // ============================================================================
    // Register Register View Provider
    // ============================================================================
    const registerProvider = new registerViewProvider_1.RegisterViewProvider(context.extensionUri);
    context.subscriptions.push(vscode.window.registerWebviewViewProvider('rawrxd-script.registers', registerProvider));
    // ============================================================================
    // Register Commands
    // ============================================================================
    registerCommands(context);
    // ============================================================================
    // Register Event Handlers
    // ============================================================================
    registerEventHandlers(context);
    outputChannel.appendLine('RawrXD-Script extension activated successfully!');
}
function startLanguageServer(context) {
    // Get configuration
    const config = vscode.workspace.getConfiguration('rawrxd-script');
    let serverPath = config.get('lsp.serverPath', '');
    // If no custom path set, resolve relative to extension
    if (!serverPath) {
        // Try multiple possible locations (dev vs packaged extension)
        const possiblePaths = [
            // Packaged extension: binaries in 'bin' folder
            path.join(context.extensionPath, 'bin', 'RawrXD_LSPServer.exe'),
            // Development: rawrxd repo build output
            path.join(context.extensionPath, '..', '..', 'build', 'RawrXD_LSPServer.exe'),
            // Alternative: direct from source
            path.join(context.extensionPath, '..', '..', 'src', 'lsp', 'RawrXD_LSPServer.exe'),
        ];
        const fs = require('fs');
        for (const p of possiblePaths) {
            if (fs.existsSync(p)) {
                serverPath = p;
                outputChannel.appendLine(`Found LSP server at: ${p}`);
                break;
            }
        }
        if (!serverPath) {
            vscode.window.showErrorMessage('RawrXD-Script: LSP server not found. Please set rawrxd-script.lsp.serverPath in settings.');
            return;
        }
    }
    // Server options
    const serverOptions = {
        command: serverPath,
        args: [],
        transport: vscode_languageclient_1.TransportKind.stdio
    };
    // Client options
    const clientOptions = {
        documentSelector: [
            { scheme: 'file', language: 'rawrxd-script' }
        ],
        synchronize: {
            fileEvents: vscode.workspace.createFileSystemWatcher('**/*.rxs')
        },
        outputChannel: vscode.window.createOutputChannel('RawrXD-Script LSP')
    };
    // Create and start client
    client = new vscode_languageclient_1.LanguageClient('rawrxd-script', 'RawrXD-Script Language Server', serverOptions, clientOptions);
    client.start();
    outputChannel.appendLine('Language Server started');
}
function registerCommands(context) {
    // Run command
    context.subscriptions.push(vscode.commands.registerCommand('rawrxd-script.run', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor || editor.document.languageId !== 'rawrxd-script') {
            vscode.window.showWarningMessage('No RawrXD-Script file active');
            return;
        }
        const filePath = editor.document.fileName;
        const terminal = vscode.window.createTerminal('RawrXD-Script');
        terminal.sendText(`RawrXD_Script.exe "${filePath}"`);
        terminal.show();
    }));
    // Debug command
    context.subscriptions.push(vscode.commands.registerCommand('rawrxd-script.debug', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor || editor.document.languageId !== 'rawrxd-script') {
            vscode.window.showWarningMessage('No RawrXD-Script file active');
            return;
        }
        // Start debugging
        vscode.debug.startDebugging(undefined, {
            type: 'rawrxd-script',
            request: 'launch',
            name: 'Debug RawrXD-Script',
            program: editor.document.fileName,
            stopOnEntry: true
        });
    }));
    // Run with Golden Master
    context.subscriptions.push(vscode.commands.registerCommand('rawrxd-script.runWithGoldenMaster', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor || editor.document.languageId !== 'rawrxd-script') {
            vscode.window.showWarningMessage('No RawrXD-Script file active');
            return;
        }
        vscode.debug.startDebugging(undefined, {
            type: 'rawrxd-script',
            request: 'launch',
            name: 'Debug with Golden Master',
            program: editor.document.fileName,
            stopOnEntry: true,
            goldenMaster: true
        });
    }));
    // Open Trace Visualizer
    context.subscriptions.push(vscode.commands.registerCommand('rawrxd-script.openTraceVisualizer', () => {
        const panel = vscode.window.createWebviewPanel('rawrxdTraceVisualizer', 'RawrXD Trace Visualizer', vscode.ViewColumn.Two, {
            enableScripts: true,
            localResourceRoots: [
                vscode.Uri.file(context.extensionPath)
            ]
        });
        // Try multiple possible locations for the visualizer
        const possiblePaths = [
            path.join(context.extensionPath, 'visualizer', 'trace_visualizer.html'),
            path.join(context.extensionPath, '..', '..', 'src', 'script', 'visualizer', 'trace_visualizer.html'),
        ];
        const fs = require('fs');
        let htmlContent = '<h1>Trace Visualizer not found</h1><p>Please ensure trace_visualizer.html is in the extension folder.</p>';
        for (const htmlPath of possiblePaths) {
            if (fs.existsSync(htmlPath)) {
                htmlContent = fs.readFileSync(htmlPath, 'utf8');
                break;
            }
        }
        panel.webview.html = htmlContent;
    }));
    // Show Register View
    context.subscriptions.push(vscode.commands.registerCommand('rawrxd-script.showRegisterView', () => {
        vscode.commands.executeCommand('workbench.view.debug');
        vscode.commands.executeCommand('rawrxd-script.registers.focus');
    }));
    // Restart LSP
    context.subscriptions.push(vscode.commands.registerCommand('rawrxd-script.restartLSP', async () => {
        if (client) {
            await client.stop();
            client.start();
            vscode.window.showInformationMessage('RawrXD-Script Language Server restarted');
        }
    }));
}
function registerEventHandlers(context) {
    // Listen for debug session starts
    context.subscriptions.push(vscode.debug.onDidStartDebugSession((session) => {
        if (session.type === 'rawrxd-script') {
            outputChannel.appendLine(`Debug session started: ${session.name}`);
        }
    }));
    // Listen for debug session ends
    context.subscriptions.push(vscode.debug.onDidTerminateDebugSession((session) => {
        if (session.type === 'rawrxd-script') {
            outputChannel.appendLine(`Debug session ended: ${session.name}`);
        }
    }));
}
function deactivate() {
    if (client) {
        return client.stop();
    }
    return undefined;
}
//# sourceMappingURL=rawrxdScriptExtension.js.map