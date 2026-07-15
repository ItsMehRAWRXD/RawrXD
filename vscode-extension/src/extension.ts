import * as vscode from 'vscode';
import { RawrXDCompletionProvider } from './completionProvider';
import { RawrXDClusterClient } from './clusterClient';
import { ChatPanel, WebSocketServer } from './chat';
import { InlineChatController } from './inlineChat';
import { SmartActionsProvider, SmartActionsController } from './smartActions';
import { AgentMode } from './agent';
import { TerminalIntegration } from './terminal';
import { SidecarClient } from './sidecar';
import { debugAdapter } from './debugAdapter';
import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';

let lspProcess: ChildProcess | undefined;
let completionProvider: RawrXDCompletionProvider | undefined;
let clusterClient: RawrXDClusterClient | undefined;
let wsServer: WebSocketServer | undefined;
let inlineChatController: InlineChatController | undefined;
let smartActionsController: SmartActionsController | undefined;
let agentMode: AgentMode | undefined;
let terminalIntegration: TerminalIntegration | undefined;
let sidecarClient: SidecarClient | undefined;

export async function activate(context: vscode.ExtensionContext) {
    const config = vscode.workspace.getConfiguration('rawrxd');
    
    if (!config.get('enabled', true)) {
        console.log('RawrXD: Extension disabled in settings');
        return;
    }

    // Spawn the RawrXD LSP server
    // Use the built binary from the cmake output directory
    const lspPath = 'd:\\rawrxd-ci-bootstrap\\build\\cmake-preset-ninja-release\\bin\\RawrXD_LSPServer.exe';
    
    try {
        lspProcess = spawn(lspPath, [], {
            stdio: ['pipe', 'pipe', 'pipe'],
            windowsHide: true
        });

        lspProcess.on('error', (err) => {
            vscode.window.showErrorMessage(`RawrXD LSP spawn failed: ${err.message}`);
        });

        lspProcess.stderr?.on('data', (data) => {
            console.error('RawrXD LSP stderr:', data.toString());
        });

        // Initialize cluster client
        const endpoint = config.get<string>('clusterEndpoint', 'http://localhost:8080');
        clusterClient = new RawrXDClusterClient(endpoint);

        // Register completion provider for supported languages
        const languages = ['python', 'javascript', 'typescript', 'cpp', 'c', 'asm', 'rawrxd-script'];
        
        for (const lang of languages) {
            const provider = vscode.languages.registerCompletionItemProvider(
                { scheme: 'file', language: lang },
                new RawrXDCompletionProvider(clusterClient, lspProcess),
                '.', // Trigger on dot
                '>', // Trigger on arrow
                '('  // Trigger on paren
            );
            context.subscriptions.push(provider);
        }

        // Register commands
        context.subscriptions.push(
            vscode.commands.registerCommand('rawrxd.enable', () => {
                config.update('enabled', true, true);
                vscode.window.showInformationMessage('RawrXD completion enabled');
            }),
            vscode.commands.registerCommand('rawrxd.disable', () => {
                config.update('enabled', false, true);
                vscode.window.showInformationMessage('RawrXD completion disabled');
            }),
            vscode.commands.registerCommand('rawrxd.status', async () => {
                const status = await clusterClient?.getStatus();
                vscode.window.showInformationMessage(
                    `RawrXD Cluster: ${status?.nodes || 0} nodes, ${status?.tps || 0} TPS`
                );
            }),
            vscode.commands.registerCommand('rawrxd.openChat', () => {
                ChatPanel.createOrShow(context.extensionUri);
            })
        );

        // Start WebSocket server for chat
        wsServer = new WebSocketServer(8081);
        wsServer.start();

        // Initialize inline chat controller
        inlineChatController = new InlineChatController(clusterClient);
        context.subscriptions.push(inlineChatController);

        // Register inline chat command
        context.subscriptions.push(
            vscode.commands.registerCommand('rawrxd.inlineChat', () => {
                const editor = vscode.window.activeTextEditor;
                if (editor) {
                    inlineChatController?.show(editor);
                } else {
                    vscode.window.showWarningMessage('Open a file to use RawrXD inline chat');
                }
            })
        );

        // Initialize smart actions controller
        smartActionsController = new SmartActionsController(clusterClient);

        // Register smart actions code action provider
        const smartActionsProvider = new SmartActionsProvider(clusterClient);
        context.subscriptions.push(
            vscode.languages.registerCodeActionsProvider(
                [{ scheme: 'file' }],
                smartActionsProvider,
                { providedCodeActionKinds: SmartActionsProvider.providedCodeActionKinds }
            )
        );

        // Register smart action commands
        context.subscriptions.push(
            vscode.commands.registerCommand('rawrxd.smartGenerate', (document, range) => {
                smartActionsController?.handleGenerate(document, range);
            }),
            vscode.commands.registerCommand('rawrxd.smartExplain', (document, range) => {
                smartActionsController?.handleExplain(document, range);
            }),
            vscode.commands.registerCommand('rawrxd.smartFix', (document, range, diagnostics) => {
                smartActionsController?.handleFix(document, range, diagnostics);
            }),
            vscode.commands.registerCommand('rawrxd.smartTest', (document, range) => {
                smartActionsController?.handleTest(document, range);
            }),
            vscode.commands.registerCommand('rawrxd.smartDocument', (document, range) => {
                smartActionsController?.handleDocument(document, range);
            })
        );

        // Initialize Native Sidecar
        sidecarClient = new SidecarClient();
        
        try {
            await sidecarClient.start();
            console.log('[RawrXD] Native sidecar initialized');
            
            // Listen for sidecar events
            sidecarClient.on('event', (event) => {
                console.log('[RawrXD Sidecar Event]:', event);
            });
            
            sidecarClient.on('error', (error) => {
                console.error('[RawrXD Sidecar Error]:', error);
            });
            
        } catch (error) {
            console.warn('[RawrXD] Failed to start native sidecar:', error);
            vscode.window.showWarningMessage('RawrXD native sidecar unavailable - falling back to TypeScript agent');
        }
        
        context.subscriptions.push(sidecarClient);

        // Initialize Agent Mode (using sidecar if available)
        agentMode = new AgentMode();
        context.subscriptions.push(agentMode);

        // Register Agent Mode commands - route through sidecar when available
        context.subscriptions.push(
            vscode.commands.registerCommand('rawrxd.agentMode', async () => {
                const goal = await vscode.window.showInputBox({
                    prompt: 'What should the agent do?',
                    placeHolder: 'e.g., Fix all build errors, Refactor auth module, Add tests for utils',
                    title: 'RawrXD Agent Mode'
                });
                
                if (!goal) return;
                
                // Route through native sidecar if available
                if (sidecarClient?.isConnected()) {
                    try {
                        const response = await sidecarClient.sendRequest({
                            action: 'plan',
                            goal,
                            taskId: `task-${Date.now()}`
                        });
                        
                        console.log('[RawrXD] Sidecar plan response:', response);
                        
                        // Start execution
                        await sidecarClient.sendRequest({
                            action: 'execute',
                            goal,
                            taskId: response.taskId || `task-${Date.now()}`
                        });
                        
                        vscode.window.showInformationMessage(`RawrXD Agent: Started "${goal}"`);
                    } catch (error) {
                        vscode.window.showErrorMessage(`Agent failed: ${error}`);
                    }
                } else {
                    // Fallback to TypeScript agent
                    agentMode?.startAgentSession(goal);
                }
            }),
            vscode.commands.registerCommand('rawrxd.agentStop', () => {
                if (sidecarClient?.isConnected()) {
                    sidecarClient.sendRequest({ action: 'stop', taskId: 'active' });
                }
                agentMode?.stop();
            })
        );

        // Initialize Terminal Integration
        terminalIntegration = new TerminalIntegration();
        context.subscriptions.push(terminalIntegration);

        // Register terminal commands
        context.subscriptions.push(
            vscode.commands.registerCommand('rawrxd.terminalBuild', async () => {
                const result = await terminalIntegration?.build();
                vscode.window.showInformationMessage(`Build ${result?.exitCode === 0 ? 'succeeded' : 'failed'}`);
            }),
            vscode.commands.registerCommand('rawrxd.terminalTest', async () => {
                const result = await terminalIntegration?.test();
                vscode.window.showInformationMessage(`Tests ${result?.exitCode === 0 ? 'passed' : 'failed'}`);
            })
        );

        // =============================================================================
        // RAWRXD NATIVE TOOLCHAIN COMMANDS (from extension_actual.ts)
        // =============================================================================
        
        const outputChannel = vscode.window.createOutputChannel('RawrXD Build');
        outputChannel.show();
        
        // Build command
        context.subscriptions.push(
            vscode.commands.registerCommand('rawrxd.build', async () => {
                const editor = vscode.window.activeTextEditor;
                if (!editor) {
                    vscode.window.showErrorMessage('❌ No active editor');
                    return;
                }
                
                const sourceFile = editor.document.fileName;
                outputChannel.clear();
                outputChannel.appendLine(`🔨 Building ${path.basename(sourceFile)}...`);
                
                // Use native toolchain
                const { exec } = require('child_process');
                const cmd = `d:\\rawrxd\\native_toolchain\\universal_compiler.exe "${sourceFile}"`;
                
                exec(cmd, (error: any, stdout: string, stderr: string) => {
                    if (error) {
                        outputChannel.appendLine(`❌ Build failed: ${error.message}`);
                        vscode.window.showErrorMessage('❌ Build failed');
                    } else {
                        outputChannel.appendLine('✅ Build successful!');
                        if (stdout) outputChannel.appendLine(stdout);
                        vscode.window.showInformationMessage('✅ Build successful!');
                    }
                });
            })
        );
        
        // Run command
        context.subscriptions.push(
            vscode.commands.registerCommand('rawrxd.run', async () => {
                const editor = vscode.window.activeTextEditor;
                if (!editor) {
                    vscode.window.showErrorMessage('❌ No active editor');
                    return;
                }
                
                const sourceFile = editor.document.fileName;
                const exeFile = sourceFile.replace(/\.[^.]+$/, '.exe');
                
                const fs = require('fs');
                if (!fs.existsSync(exeFile)) {
                    vscode.window.showErrorMessage('❌ Executable not found. Build first.');
                    return;
                }
                
                outputChannel.appendLine(`🏃 Running ${path.basename(exeFile)}...`);
                
                const { exec } = require('child_process');
                exec(`"${exeFile}"`, (error: any, stdout: string, stderr: string) => {
                    if (stdout) outputChannel.appendLine(stdout);
                    if (stderr) outputChannel.appendLine(stderr);
                    outputChannel.appendLine(`✅ Program completed`);
                });
            })
        );
        
        // Debug command - WIRED to DebugIntegration.cpp DAP server
        context.subscriptions.push(
            vscode.commands.registerCommand('rawrxd.debug', async () => {
                const editor = vscode.window.activeTextEditor;
                if (!editor) {
                    vscode.window.showErrorMessage('❌ No active editor');
                    return;
                }
                
                const sourceFile = editor.document.fileName;
                const exeFile = sourceFile.replace(/\.[^.]+$/, '.exe');
                
                // Check if executable exists
                const fs = require('fs');
                if (!fs.existsSync(exeFile)) {
                    vscode.window.showErrorMessage('❌ Executable not found. Build first.');
                    return;
                }
                
                outputChannel.appendLine(`🐛 Starting debug session for ${path.basename(exeFile)}...`);
                
                // Start DAP debug session using DebugIntegration.cpp via debugAdapter
                try {
                    await debugAdapter.startDebugSession(
                        exeFile,
                        path.dirname(exeFile),
                        false
                    );
                    outputChannel.appendLine('✅ Debug session started');
                    vscode.window.showInformationMessage('🐛 Debug session started');
                } catch (err: any) {
                    outputChannel.appendLine(`❌ Debug failed: ${err.message}`);
                    vscode.window.showErrorMessage(`Debug failed: ${err.message}`);
                }
            })
        );
        
        // Debug control commands
        context.subscriptions.push(
            vscode.commands.registerCommand('rawrxd.debug.continue', async () => {
                await debugAdapter.continue();
            }),
            vscode.commands.registerCommand('rawrxd.debug.pause', async () => {
                await debugAdapter.pause();
            }),
            vscode.commands.registerCommand('rawrxd.debug.stepIn', async () => {
                await debugAdapter.stepIn();
            }),
            vscode.commands.registerCommand('rawrxd.debug.stepOver', async () => {
                await debugAdapter.stepOver();
            }),
            vscode.commands.registerCommand('rawrxd.debug.stepOut', async () => {
                await debugAdapter.stepOut();
            }),
            vscode.commands.registerCommand('rawrxd.debug.stop', async () => {
                await debugAdapter.stopDebugSession();
                vscode.window.showInformationMessage('Debug session stopped');
            })
        );
        
        // Clean command
        context.subscriptions.push(
            vscode.commands.registerCommand('rawrxd.clean', async () => {
                const editor = vscode.window.activeTextEditor;
                if (!editor) return;
                
                const sourceFile = editor.document.fileName;
                const exeFile = sourceFile.replace(/\.[^.]+$/, '.exe');
                
                const fs = require('fs');
                if (fs.existsSync(exeFile)) {
                    fs.unlinkSync(exeFile);
                    outputChannel.appendLine(`🧹 Cleaned ${path.basename(exeFile)}`);
                }
            })
        );

        vscode.window.showInformationMessage('RawrXD LSP Client activated');

    } catch (error) {
        vscode.window.showErrorMessage(`RawrXD activation failed: ${error}`);
    }
}

export function deactivate() {
    lspProcess?.kill();
    clusterClient?.dispose();
    wsServer?.stop();
    inlineChatController?.dispose();
    smartActionsController?.dispose();
    agentMode?.dispose();
    terminalIntegration?.dispose();
}
