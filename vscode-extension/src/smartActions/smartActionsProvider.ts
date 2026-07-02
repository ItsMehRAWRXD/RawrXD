import * as vscode from 'vscode';
import { RawrXDClusterClient } from '../clusterClient';

export class SmartActionsProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix,
        vscode.CodeActionKind.RefactorRewrite
    ];

    constructor(private clusterClient: RawrXDClusterClient) {}

    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        // Generate action
        const generateAction = new vscode.CodeAction(
            'RawrXD: Generate code...',
            vscode.CodeActionKind.RefactorRewrite
        );
        generateAction.command = {
            command: 'rawrxd.smartGenerate',
            title: 'Generate code',
            arguments: [document, range]
        };
        generateAction.isPreferred = false;
        actions.push(generateAction);

        // Explain action
        const explainAction = new vscode.CodeAction(
            'RawrXD: Explain this code',
            vscode.CodeActionKind.QuickFix
        );
        explainAction.command = {
            command: 'rawrxd.smartExplain',
            title: 'Explain code',
            arguments: [document, range]
        };
        actions.push(explainAction);

        // Fix action (only if diagnostics exist)
        if (context.diagnostics.length > 0) {
            const fixAction = new vscode.CodeAction(
                'RawrXD: Fix this issue',
                vscode.CodeActionKind.QuickFix
            );
            fixAction.command = {
                command: 'rawrxd.smartFix',
                title: 'Fix issue',
                arguments: [document, range, context.diagnostics]
            };
            fixAction.isPreferred = true;
            actions.push(fixAction);
        }

        // Test action
        const testAction = new vscode.CodeAction(
            'RawrXD: Generate tests',
            vscode.CodeActionKind.RefactorRewrite
        );
        testAction.command = {
            command: 'rawrxd.smartTest',
            title: 'Generate tests',
            arguments: [document, range]
        };
        actions.push(testAction);

        // Document action
        const docAction = new vscode.CodeAction(
            'RawrXD: Add documentation',
            vscode.CodeActionKind.RefactorRewrite
        );
        docAction.command = {
            command: 'rawrxd.smartDocument',
            title: 'Add documentation',
            arguments: [document, range]
        };
        actions.push(docAction);

        return actions;
    }
}

export class SmartActionsController {
    constructor(private clusterClient: RawrXDClusterClient) {}

    async handleGenerate(document: vscode.TextDocument, range: vscode.Range): Promise<void> {
        const code = document.getText(range);
        const language = document.languageId;

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'RawrXD is generating code...'
        }, async () => {
            try {
                const response = await this.clusterClient.complete({
                    uri: document.uri.toString(),
                    languageId: language,
                    prefix: `Generate code based on this context:\n\n${code}`,
                    line: range.start.line,
                    character: range.start.character,
                    maxTokens: 512,
                    temperature: 0.2
                });

                const generatedCode = response.items[0]?.insertText;
                if (generatedCode) {
                    const edit = new vscode.WorkspaceEdit();
                    edit.insert(document.uri, range.end, '\n\n' + generatedCode);
                    await vscode.workspace.applyEdit(edit);
                }
            } catch (error) {
                vscode.window.showErrorMessage(`Generation failed: ${error}`);
            }
        });
    }

    async handleExplain(document: vscode.TextDocument, range: vscode.Range): Promise<void> {
        const code = document.getText(range);
        const language = document.languageId;

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'RawrXD is analyzing...'
        }, async () => {
            try {
                const response = await this.clusterClient.complete({
                    uri: document.uri.toString(),
                    languageId: language,
                    prefix: `Explain this ${language} code in detail:\n\n${code}`,
                    line: range.start.line,
                    character: range.start.character,
                    maxTokens: 1024,
                    temperature: 0.2
                });

                const explanation = response.items[0]?.insertText || 'No explanation available';
                
                // Show in output channel
                const channel = vscode.window.createOutputChannel('RawrXD Explanation');
                channel.clear();
                channel.appendLine('=== Code Explanation ===');
                channel.appendLine('');
                channel.appendLine(explanation);
                channel.show();
            } catch (error) {
                vscode.window.showErrorMessage(`Explanation failed: ${error}`);
            }
        });
    }

    async handleFix(document: vscode.TextDocument, range: vscode.Range, diagnostics: vscode.Diagnostic[]): Promise<void> {
        const code = document.getText(range);
        const language = document.languageId;
        const errorMessages = diagnostics.map(d => d.message).join('\n');

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'RawrXD is fixing...'
        }, async () => {
            try {
                const response = await this.clusterClient.complete({
                    uri: document.uri.toString(),
                    languageId: language,
                    prefix: `Fix these issues in the ${language} code:\nErrors: ${errorMessages}\n\nCode:\n${code}`,
                    line: range.start.line,
                    character: range.start.character,
                    maxTokens: 1024,
                    temperature: 0.1
                });

                const fixedCode = response.items[0]?.insertText;
                if (fixedCode) {
                    const edit = new vscode.WorkspaceEdit();
                    edit.replace(document.uri, range, fixedCode);
                    await vscode.workspace.applyEdit(edit);
                }
            } catch (error) {
                vscode.window.showErrorMessage(`Fix failed: ${error}`);
            }
        });
    }

    async handleTest(document: vscode.TextDocument, range: vscode.Range): Promise<void> {
        const code = document.getText(range);
        const language = document.languageId;

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'RawrXD is generating tests...'
        }, async () => {
            try {
                const response = await this.clusterClient.complete({
                    uri: document.uri.toString(),
                    languageId: language,
                    prefix: `Generate comprehensive unit tests for this ${language} code:\n\n${code}`,
                    line: range.start.line,
                    character: range.start.character,
                    maxTokens: 2048,
                    temperature: 0.2
                });

                const testCode = response.items[0]?.insertText;
                if (testCode) {
                    // Create new file for tests
                    const testUri = document.uri.with({ 
                        path: document.uri.path.replace(/\.[^.]+$/, '.test.$&') 
                    });
                    
                    const edit = new vscode.WorkspaceEdit();
                    edit.createFile(testUri, { overwrite: false });
                    edit.insert(testUri, new vscode.Position(0, 0), testCode);
                    await vscode.workspace.applyEdit(edit);
                    
                    // Open the test file
                    const doc = await vscode.workspace.openTextDocument(testUri);
                    await vscode.window.showTextDocument(doc);
                }
            } catch (error) {
                vscode.window.showErrorMessage(`Test generation failed: ${error}`);
            }
        });
    }

    async handleDocument(document: vscode.TextDocument, range: vscode.Range): Promise<void> {
        const code = document.getText(range);
        const language = document.languageId;

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'RawrXD is adding documentation...'
        }, async () => {
            try {
                const response = await this.clusterClient.complete({
                    uri: document.uri.toString(),
                    languageId: language,
                    prefix: `Add comprehensive documentation/comments to this ${language} code:\n\n${code}`,
                    line: range.start.line,
                    character: range.start.character,
                    maxTokens: 1024,
                    temperature: 0.2
                });

                const documentedCode = response.items[0]?.insertText;
                if (documentedCode) {
                    const edit = new vscode.WorkspaceEdit();
                    edit.replace(document.uri, range, documentedCode);
                    await vscode.workspace.applyEdit(edit);
                }
            } catch (error) {
                vscode.window.showErrorMessage(`Documentation failed: ${error}`);
            }
        });
    }
}
