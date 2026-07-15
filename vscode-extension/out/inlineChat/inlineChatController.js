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
exports.InlineChatController = void 0;
const vscode = __importStar(require("vscode"));
const context_1 = require("../context");
class InlineChatController {
    clusterClient;
    _decorationType;
    _inputBox;
    _currentEditor;
    _currentRange;
    _disposables = [];
    constructor(clusterClient) {
        this.clusterClient = clusterClient;
        this._decorationType = vscode.window.createTextEditorDecorationType({
            backgroundColor: new vscode.ThemeColor('editor.inlayHint.background'),
            border: '1px solid',
            borderColor: new vscode.ThemeColor('editor.inlayHint.border'),
            borderRadius: '3px'
        });
    }
    async show(editor) {
        this._currentEditor = editor;
        const selection = editor.selection;
        // If no selection, use current line
        if (selection.isEmpty) {
            const line = editor.document.lineAt(selection.active.line);
            this._currentRange = line.range;
        }
        else {
            this._currentRange = selection;
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
    async _handleInput(input) {
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
                }
                else {
                    await this._applyStreamingEdit(editor, range, response.edits);
                }
            }
            catch (error) {
                if (!cancellationTokenSource.token.isCancellationRequested) {
                    vscode.window.showErrorMessage(`RawrXD inline chat failed: ${error}`);
                }
            }
        });
    }
    _detectIntent(input) {
        const lower = input.toLowerCase();
        if (lower.includes('explain') || lower.includes('what does'))
            return 'explain';
        if (lower.includes('fix') || lower.includes('bug') || lower.includes('error'))
            return 'fix';
        if (lower.includes('test') || lower.includes('spec'))
            return 'generate';
        if (lower.includes('doc') || lower.includes('comment'))
            return 'doc';
        return 'edit';
    }
    async _requestInlineChat(request, token) {
        if (token.isCancellationRequested) {
            return { edits: [] };
        }
        // Gather rich context
        const context = await (0, context_1.gatherContext)(request.document, request.selection);
        if (token.isCancellationRequested) {
            return { edits: [] };
        }
        // Build rich prompt with context
        const prompt = (0, context_1.buildPrompt)(request.intent, context, request.input);
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
            onToken: (token) => {
                accumulatedText += token;
                // Could update UI here for real-time preview
            },
            onComplete: () => {
                // Streaming complete
            },
            onError: (error) => {
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
    async _applyStreamingEdit(editor, range, edits) {
        if (edits.length === 0) {
            return;
        }
        // Apply edit atomically with proper undo grouping
        await editor.edit(editBuilder => {
            for (const edit of edits) {
                editBuilder.replace(edit.range, edit.newText);
            }
        }, {
            undoStopBefore: false,
            undoStopAfter: false
        });
        // Show diff/notification of changes
        const newText = edits[0].newText;
        const oldTextLength = range.end.character - range.start.character +
            (range.end.line - range.start.line) * 1000; // Approximate
        vscode.window.setStatusBarMessage(`RawrXD: Applied ${newText.length} characters`, 3000);
    }
    _showExplanation(explanation) {
        const channel = vscode.window.createOutputChannel('RawrXD Explanation');
        channel.clear();
        channel.appendLine('=== RawrXD Explanation ===');
        channel.appendLine('');
        channel.appendLine(explanation);
        channel.show();
    }
    _cleanup() {
        if (this._currentEditor) {
            this._currentEditor.setDecorations(this._decorationType, []);
        }
        this._inputBox?.dispose();
        this._inputBox = undefined;
        this._currentEditor = undefined;
        this._currentRange = undefined;
    }
    dispose() {
        this._cleanup();
        this._decorationType.dispose();
        this._disposables.forEach(d => d.dispose());
    }
}
exports.InlineChatController = InlineChatController;
//# sourceMappingURL=inlineChatController.js.map