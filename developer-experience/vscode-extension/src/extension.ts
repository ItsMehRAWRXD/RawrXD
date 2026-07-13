import * as vscode from 'vscode';
import { RawrXDProvider } from './rawrxdProvider';
import { ChatPanel } from './chatPanel';
import { ModelTreeProvider } from './modelTreeProvider';
import { SessionTreeProvider } from './sessionTreeProvider';

export function activate(context: vscode.ExtensionContext) {
    console.log('RawrXD extension activated');

    const rawrxdProvider = new RawrXDProvider();
    const modelTreeProvider = new ModelTreeProvider();
    const sessionTreeProvider = new SessionTreeProvider();

    // Register tree data providers
    vscode.window.registerTreeDataProvider('rawrxdModels', modelTreeProvider);
    vscode.window.registerTreeDataProvider('rawrxdSessions', sessionTreeProvider);

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('rawrxd.startServer', () => {
            vscode.window.showInformationMessage('Starting RawrXD server...');
            rawrxdProvider.startServer();
        }),

        vscode.commands.registerCommand('rawrxd.stopServer', () => {
            vscode.window.showInformationMessage('Stopping RawrXD server...');
            rawrxdProvider.stopServer();
        }),

        vscode.commands.registerCommand('rawrxd.restartServer', () => {
            vscode.window.showInformationMessage('Restarting RawrXD server...');
            rawrxdProvider.restartServer();
        }),

        vscode.commands.registerCommand('rawrxd.openChat', () => {
            ChatPanel.createOrShow(context.extensionUri);
        }),

        vscode.commands.registerCommand('rawrxd.generateCompletion', async () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                const document = editor.document;
                const selection = editor.selection;
                const text = document.getText(selection);
                
                if (text) {
                    const completion = await rawrxdProvider.generateCompletion(text);
                    editor.edit(editBuilder => {
                        editBuilder.insert(selection.end, completion);
                    });
                }
            }
        }),

        vscode.commands.registerCommand('rawrxd.explainCode', async () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                const text = editor.document.getText(editor.selection);
                if (text) {
                    const explanation = await rawrxdProvider.explainCode(text);
                    vscode.window.showInformationMessage(explanation);
                }
            }
        }),

        vscode.commands.registerCommand('rawrxd.refactorCode', async () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                const text = editor.document.getText(editor.selection);
                if (text) {
                    const refactored = await rawrxdProvider.refactorCode(text);
                    editor.edit(editBuilder => {
                        editBuilder.replace(editor.selection, refactored);
                    });
                }
            }
        }),

        vscode.commands.registerCommand('rawrxd.generateTests', async () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                const text = editor.document.getText(editor.selection);
                if (text) {
                    const tests = await rawrxdProvider.generateTests(text);
                    vscode.workspace.openTextDocument({ content: tests, language: 'typescript' })
                        .then(doc => vscode.window.showTextDocument(doc));
                }
            }
        }),

        vscode.commands.registerCommand('rawrxd.loadModel', async () => {
            const models = ['llama3', 'qwen2', 'phi3', 'mistral'];
            const selected = await vscode.window.showQuickPick(models, { placeHolder: 'Select model to load' });
            if (selected) {
                await rawrxdProvider.loadModel(selected);
                vscode.window.showInformationMessage(`Loaded model: ${selected}`);
                modelTreeProvider.refresh();
            }
        }),

        vscode.commands.registerCommand('rawrxd.unloadModel', async () => {
            const models = ['llama3', 'qwen2'];
            const selected = await vscode.window.showQuickPick(models, { placeHolder: 'Select model to unload' });
            if (selected) {
                await rawrxdProvider.unloadModel(selected);
                vscode.window.showInformationMessage(`Unloaded model: ${selected}`);
                modelTreeProvider.refresh();
            }
        }),

        vscode.commands.registerCommand('rawrxd.showStatus', () => {
            rawrxdProvider.getStatus().then(status => {
                vscode.window.showInformationMessage(`RawrXD Status: ${status}`);
            });
        }),

        vscode.commands.registerCommand('rawrxd.openSettings', () => {
            vscode.commands.executeCommand('workbench.action.openSettings', 'rawrxd');
        })
    );

    // Set context for views
    vscode.commands.executeCommand('setContext', 'rawrxd:enabled', true);
}

export function deactivate() {
    console.log('RawrXD extension deactivated');
}
