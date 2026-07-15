"use strict";
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
const completionProvider_1 = require("./completionProvider");
const clusterClient_1 = require("./clusterClient");
const chat_1 = require("./chat");
const inlineChat_1 = require("./inlineChat");
const smartActions_1 = require("./smartActions");
const agent_1 = require("./agent");
const terminal_1 = require("./terminal");
const sidecar_1 = require("./sidecar");
const child_process_1 = require("child_process");
const path = __importStar(require("path"));
let lspProcess;
let completionProvider;
let clusterClient;
let wsServer;
let inlineChatController;
let smartActionsController;
let agentMode;
let terminalIntegration;
let sidecarClient;
function activate(context) {
    const config = vscode.workspace.getConfiguration('rawrxd');
    if (!config.get('enabled', true)) {
        console.log('RawrXD: Extension disabled in settings');
        return;
    }
    // Spawn the RawrXD LSP server
    const lspPath = 'd:\\rawrxd-ci-bootstrap\\build\\cmake-preset-ninja-release\\bin\\RawrXD_LSPServer.exe';
    try {
        lspProcess = (0, child_process_1.spawn)(lspPath, [], {
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
        const endpoint = config.get('clusterEndpoint', 'http://localhost:8080');
        clusterClient = new clusterClient_1.RawrXDClusterClient(endpoint);
        // Register completion provider for supported languages
        const languages = ['python', 'javascript', 'typescript', 'cpp', 'c', 'asm', 'rawrxd-script'];
        for (const lang of languages) {
            const provider = vscode.languages.registerCompletionItemProvider({ scheme: 'file', language: lang }, new completionProvider_1.RawrXDCompletionProvider(clusterClient, lspProcess), '.', // Trigger on dot
            '>', // Trigger on arrow
            '(' // Trigger on paren
            );
            context.subscriptions.push(provider);
        }
        // Register commands
        context.subscriptions.push(vscode.commands.registerCommand('rawrxd.enable', () => {
            config.update('enabled', true, true);
            vscode.window.showInformationMessage('RawrXD completion enabled');
        }), vscode.commands.registerCommand('rawrxd.disable', () => {
            config.update('enabled', false, true);
            vscode.window.showInformationMessage('RawrXD completion disabled');
        }), vscode.commands.registerCommand('rawrxd.status', async () => {
            const status = await clusterClient?.getStatus();
            vscode.window.showInformationMessage(`RawrXD Cluster: ${status?.nodes || 0} nodes, ${status?.tps || 0} TPS`);
        }), vscode.commands.registerCommand('rawrxd.openChat', () => {
            chat_1.ChatPanel.createOrShow(context.extensionUri);
        }));
        // Start WebSocket server for chat
        wsServer = new chat_1.WebSocketServer(8081);
        wsServer.start();
        // Initialize inline chat controller
        inlineChatController = new inlineChat_1.InlineChatController(clusterClient);
        context.subscriptions.push(inlineChatController);
        // Register inline chat command
        context.subscriptions.push(vscode.commands.registerCommand('rawrxd.inlineChat', () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                inlineChatController?.show(editor);
            }
            else {
                vscode.window.showWarningMessage('Open a file to use RawrXD inline chat');
            }
        }));
        // Initialize smart actions controller
        smartActionsController = new smartActions_1.SmartActionsController(clusterClient);
        // Register smart actions code action provider
        const smartActionsProvider = new smartActions_1.SmartActionsProvider(clusterClient);
        context.subscriptions.push(vscode.languages.registerCodeActionsProvider([{ scheme: 'file' }], smartActionsProvider, { providedCodeActionKinds: smartActions_1.SmartActionsProvider.providedCodeActionKinds }));
        // Register smart action commands
        context.subscriptions.push(vscode.commands.registerCommand('rawrxd.smartGenerate', (document, range) => {
            smartActionsController?.handleGenerate(document, range);
        }), vscode.commands.registerCommand('rawrxd.smartExplain', (document, range) => {
            smartActionsController?.handleExplain(document, range);
        }), vscode.commands.registerCommand('rawrxd.smartFix', (document, range, diagnostics) => {
            smartActionsController?.handleFix(document, range, diagnostics);
        }), vscode.commands.registerCommand('rawrxd.smartTest', (document, range) => {
            smartActionsController?.handleTest(document, range);
        }), vscode.commands.registerCommand('rawrxd.smartDocument', (document, range) => {
            smartActionsController?.handleDocument(document, range);
        }));
        // Initialize Native Sidecar
        sidecarClient = new sidecar_1.SidecarClient();
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
        }
        catch (error) {
            console.warn('[RawrXD] Failed to start native sidecar:', error);
            vscode.window.showWarningMessage('RawrXD native sidecar unavailable - falling back to TypeScript agent');
        }
        context.subscriptions.push(sidecarClient);
        // Initialize Agent Mode (using sidecar if available)
        agentMode = new agent_1.AgentMode();
        context.subscriptions.push(agentMode);
        // Register Agent Mode commands - route through sidecar when available
        context.subscriptions.push(vscode.commands.registerCommand('rawrxd.agentMode', async () => {
            const goal = await vscode.window.showInputBox({
                prompt: 'What should the agent do?',
                placeHolder: 'e.g., Fix all build errors, Refactor auth module, Add tests for utils',
                title: 'RawrXD Agent Mode'
            });
            if (!goal)
                return;
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
                }
                catch (error) {
                    vscode.window.showErrorMessage(`Agent failed: ${error}`);
                }
            }
            else {
                // Fallback to TypeScript agent
                agentMode?.startAgentSession(goal);
            }
        }), vscode.commands.registerCommand('rawrxd.agentStop', () => {
            if (sidecarClient?.isConnected()) {
                sidecarClient.sendRequest({ action: 'stop', taskId: 'active' });
            }
            agentMode?.stop();
        }));
        // Initialize Terminal Integration
        terminalIntegration = new terminal_1.TerminalIntegration();
        context.subscriptions.push(terminalIntegration);
        // Register terminal commands
        context.subscriptions.push(vscode.commands.registerCommand('rawrxd.terminalBuild', async () => {
            const result = await terminalIntegration?.build();
            vscode.window.showInformationMessage(`Build ${result?.exitCode === 0 ? 'succeeded' : 'failed'}`);
        }), vscode.commands.registerCommand('rawrxd.terminalTest', async () => {
            const result = await terminalIntegration?.test();
            vscode.window.showInformationMessage(`Tests ${result?.exitCode === 0 ? 'passed' : 'failed'}`);
        }));
        vscode.window.showInformationMessage('RawrXD LSP Client activated');
    }
    catch (error) {
        vscode.window.showErrorMessage(`RawrXD activation failed: ${error}`);
    }
}
function deactivate() {
    lspProcess?.kill();
    clusterClient?.dispose();
    wsServer?.stop();
    inlineChatController?.dispose();
    smartActionsController?.dispose();
    agentMode?.dispose();
    terminalIntegration?.dispose();
}
//# sourceMappingURL=extension.js.map