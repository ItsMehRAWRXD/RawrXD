import * as vscode from 'vscode';
import { RawrXDClusterClient, StreamingCompletionRequest } from '../clusterClient';
import { gatherContext, buildPrompt, CodeContext } from '../context';

export interface InlineChatRequest {
    document: vscode.TextDocument;
    selection: vscode.Selection;
    input: string;
    intent: 'edit' | 'explain' | 'fix' | 'generate' | 'doc';
}

export interface InlineChatResponse {
    edits: vscode.TextEdit[];
    explanation?: string;
}

export class InlineChatController implements vscode.Disposable {
    private _decorationType: vscode.TextEditorDecorationType;
    private _inputBox: vscode.InputBox | undefined;
    private _currentEditor: vscode.TextEditor | undefined;
    private _currentRange: vscode.Range | undefined;
    private _disposables: vscode.Disposable[] = [];

    constructor(private clusterClient: RawrXDClusterClient) {
        this._decorationType = vscode.window.createTextEditorDecorationType({
            backgroundColor: new vscode.ThemeColor('editor.inlayHint.background'),
            border: '1px solid',
            borderColor: new vscode.ThemeColor('editor.inlayHint.border'),
            borderRadius: '3px'
        });
    }

    async show(editor: vscode.TextEditor): Promise<void> {
        this._currentEditor = editor;
        const selection = editor.selection;
        
        // If no selection, use current line
        if (selection.isEmpty) {
            const line = editor.document.lineAt(selection.active.line);
            this._currentRange = line.range;
        } else {
            this._currentRange = new vscode.Range(selection.start, selection.end);
        }

        // Highlight the target range
        editor.setDecorations(this._decorationType, [this._currentRange]);

        // Create input box
        this._inputBox = vscode.window.createInputBox();
        this._inputBox.placeholder = 'Ask RawrXD to edit, explain, fix, or generate...';
        this._inputBox.prompt = 'Enter your request (e.g., "explain this", "add error handling", "generate tests")';
        
        this._inputBox.onDidAccept(() => {
            const input = this._inputBox?.value;
            if (input) {
                this._handleInput(input);
            }
            this._cleanup();
        });

        this._inputBox.onDidHide(() => {
            this._cleanup();
        });

        this._inputBox.show();
    }

    private async _handleInput(input: string): Promise<void> {
        if (!this._currentEditor || !this._currentRange) {
            return;
        }

        const intent = this._detectIntent(input);
        const editor = this._currentEditor;
        const range = this._currentRange;
        
        // Show progress with cancellation
        const cancellationTokenSource = new vscode.CancellationTokenSource();
        
        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'RawrXD is thinking...',
            cancellable: true
        }, async (progress, token) => {
            // Link external cancellation to internal token
            token.onCancellationRequested(() => cancellationTokenSource.cancel());
            
            try {
                const response = await this._requestInlineChat({
                    document: editor.document,
                    selection: range,
                    input,
                    intent
                }, cancellationTokenSource.token);

                if (cancellationTokenSource.token.isCancellationRequested) {
                    return;
                }

                if (intent === 'explain' || intent === 'doc') {
                    this._showExplanation(response.explanation || 'No explanation provided');
                } else {
                    await this._applyStreamingEdit(editor, range, response.edits);
                }
            } catch (error) {
                if (!cancellationTokenSource.token.isCancellationRequested) {
                    vscode.window.showErrorMessage(`RawrXD inline chat failed: ${error}`);
                }
            }
        });
    }

    private _detectIntent(input: string): InlineChatRequest['intent'] {
        const lower = input.toLowerCase();
        if (lower.includes('explain') || lower.includes('what does')) return 'explain';
        if (lower.includes('fix') || lower.includes('bug') || lower.includes('error')) return 'fix';
        if (lower.includes('test') || lower.includes('spec')) return 'generate';
        if (lower.includes('doc') || lower.includes('comment')) return 'doc';
        return 'edit';
    }

    private async _requestInlineChat(
        request: InlineChatRequest, 
        token: vscode.CancellationToken
    ): Promise<InlineChatResponse> {
        if (token.isCancellationRequested) {
            return { edits: [] };
        }

        // Gather rich context
        const context = await gatherContext(request.document, request.selection);
        
        if (token.isCancellationRequested) {
            return { edits: [] };
        }

        // Build rich prompt with context
        const prompt = buildPrompt(request.intent, context, request.input);

        // Check cancellation before network call
        if (token.isCancellationRequested) {
            return { edits: [] };
        }

        // For explain/doc, use batch completion
        if (request.intent === 'explain' || request.intent === 'doc') {
            const response = await this.clusterClient.complete({
                uri: request.document.uri.toString(),
                languageId: request.document.languageId,
                prefix: prompt,
                line: request.selection.start.line,
                character: request.selection.start.character,
                maxTokens: 1024,
                temperature: 0.2
            });

            return {
                edits: [],
                explanation: response.items[0]?.insertText || 'No response'
            };
        }

        // For edits, use streaming completion
        let accumulatedText = '';
        
        await this.clusterClient.completeStreaming({
            uri: request.document.uri.toString(),
            languageId: request.document.languageId,
            prefix: prompt,
            line: request.selection.start.line,
            character: request.selection.start.character,
            maxTokens: 1024,
            temperature: 0.2,
            onToken: (token: string) => {
                accumulatedText += token;
                // Could update UI here for real-time preview
            },
            onComplete: () => {
                // Streaming complete
            },
            onError: (error: Error) => {
                console.error('Streaming error:', error);
            }
        });

        if (token.isCancellationRequested) {
            return { edits: [] };
        }

        // Parse response into text edits
        const edit = vscode.TextEdit.replace(request.selection, accumulatedText);
        
        return {
            edits: [edit],
            explanation: undefined
        };
    }

    private async _applyStreamingEdit(
        editor: vscode.TextEditor, 
        range: vscode.Range, 
        edits: vscode.TextEdit[]
    ): Promise<void> {
        if (edits.length === 0) {
            return;
        }

        // Apply edit atomically with proper undo grouping
        await editor.edit(
            editBuilder => {
                for (const edit of edits) {
                    editBuilder.replace(edit.range, edit.newText);
                }
            },
            {
                undoStopBefore: false,
                undoStopAfter: false
            }
        );

        // Show diff/notification of changes
        const newText = edits[0].newText;
        const oldTextLength = range.end.character - range.start.character + 
            (range.end.line - range.start.line) * 1000; // Approximate
        
        vscode.window.setStatusBarMessage(
            `RawrXD: Applied ${newText.length} characters`,
            3000
        );
    }

    private _showExplanation(explanation: string): void {
        const channel = vscode.window.createOutputChannel('RawrXD Explanation');
        channel.clear();
        channel.appendLine('=== RawrXD Explanation ===');
        channel.appendLine('');
        channel.appendLine(explanation);
        channel.show();
    }

    private _cleanup(): void {
        if (this._currentEditor) {
            this._currentEditor.setDecorations(this._decorationType, []);
        }
        this._inputBox?.dispose();
        this._inputBox = undefined;
        this._currentEditor = undefined;
        this._currentRange = undefined;
    }

    dispose(): void {
        this._cleanup();
        this._decorationType.dispose();
        this._disposables.forEach(d => d.dispose());
    }
}
