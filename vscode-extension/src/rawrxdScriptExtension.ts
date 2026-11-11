// ============================================================================
// rawrxdScriptExtension.ts - RawrXD-Script Extension Activation
// ============================================================================
// Main entry point for VS Code extension
// Handles LSP client and DAP debugger registration
//
// Copyright (c) 2026 RawrXD Project
// ============================================================================

import * as vscode from 'vscode';
import * as path from 'path';
import { LanguageClient, LanguageClientOptions, ServerOptions, TransportKind } from 'vscode-languageclient';
import { RawrXDScriptDebugAdapterFactory } from './debugAdapterFactory';
import { RegisterViewProvider } from './registerViewProvider';

let client: LanguageClient | undefined;
let outputChannel: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext) {
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
    const debugAdapterFactory = new RawrXDScriptDebugAdapterFactory(outputChannel, context.extensionPath);
    context.subscriptions.push(
        vscode.debug.registerDebugAdapterDescriptorFactory('rawrxd-script', debugAdapterFactory)
    );

    // ============================================================================
    // Register Register View Provider
    // ============================================================================
    const registerProvider = new RegisterViewProvider(context.extensionUri);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider('rawrxd-script.registers', registerProvider)
    );

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

function startLanguageServer(context: vscode.ExtensionContext) {
    // Get configuration
    const config = vscode.workspace.getConfiguration('rawrxd-script');
    let serverPath = config.get<string>('lsp.serverPath', '');
    
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
            vscode.window.showErrorMessage(
                'RawrXD-Script: LSP server not found. Please set rawrxd-script.lsp.serverPath in settings.'
            );
            return;
        }
    }
    
    // Server options
    const serverOptions: ServerOptions = {
        command: serverPath,
        args: [],
        transport: TransportKind.stdio
    };

    // Client options
    const clientOptions: LanguageClientOptions = {
        documentSelector: [
            { scheme: 'file', language: 'rawrxd-script' }
        ],
        synchronize: {
            fileEvents: vscode.workspace.createFileSystemWatcher('**/*.rxs')
        },
        outputChannel: vscode.window.createOutputChannel('RawrXD-Script LSP')
    };

    // Create and start client
    client = new LanguageClient(
        'rawrxd-script',
        'RawrXD-Script Language Server',
        serverOptions,
        clientOptions
    );

    client.start();
    outputChannel.appendLine('Language Server started');
}

function registerCommands(context: vscode.ExtensionContext) {
    // Run command
    context.subscriptions.push(
        vscode.commands.registerCommand('rawrxd-script.run', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor || editor.document.languageId !== 'rawrxd-script') {
                vscode.window.showWarningMessage('No RawrXD-Script file active');
                return;
            }

            const filePath = editor.document.fileName;
            const terminal = vscode.window.createTerminal('RawrXD-Script');
            terminal.sendText(`RawrXD_Script.exe "${filePath}"`);
            terminal.show();
        })
    );

    // Debug command
    context.subscriptions.push(
        vscode.commands.registerCommand('rawrxd-script.debug', async () => {
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
        })
    );

    // Run with Golden Master
    context.subscriptions.push(
        vscode.commands.registerCommand('rawrxd-script.runWithGoldenMaster', async () => {
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
        })
    );

    // Open Trace Visualizer
    context.subscriptions.push(
        vscode.commands.registerCommand('rawrxd-script.openTraceVisualizer', () => {
            const panel = vscode.window.createWebviewPanel(
                'rawrxdTraceVisualizer',
                'RawrXD Trace Visualizer',
                vscode.ViewColumn.Two,
                {
                    enableScripts: true,
                    localResourceRoots: [
                        vscode.Uri.file(context.extensionPath)
                    ]
                }
            );

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
        })
    );

    // Show Register View
    context.subscriptions.push(
        vscode.commands.registerCommand('rawrxd-script.showRegisterView', () => {
            vscode.commands.executeCommand('workbench.view.debug');
            vscode.commands.executeCommand('rawrxd-script.registers.focus');
        })
    );

    // Restart LSP
    context.subscriptions.push(
        vscode.commands.registerCommand('rawrxd-script.restartLSP', async () => {
            if (client) {
                await client.stop();
                client.start();
                vscode.window.showInformationMessage('RawrXD-Script Language Server restarted');
            }
        })
    );
}

function registerEventHandlers(context: vscode.ExtensionContext) {
    // Listen for debug session starts
    context.subscriptions.push(
        vscode.debug.onDidStartDebugSession((session) => {
            if (session.type === 'rawrxd-script') {
                outputChannel.appendLine(`Debug session started: ${session.name}`);
            }
        })
    );

    // Listen for debug session ends
    context.subscriptions.push(
        vscode.debug.onDidTerminateDebugSession((session) => {
            if (session.type === 'rawrxd-script') {
                outputChannel.appendLine(`Debug session ended: ${session.name}`);
            }
        })
    );
}

export function deactivate(): Thenable<void> | undefined {
    if (client) {
        return client.stop();
    }
    return undefined;
}
