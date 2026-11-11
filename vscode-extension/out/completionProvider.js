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
exports.RawrXDCompletionProvider = void 0;
const vscode = __importStar(require("vscode"));
class RawrXDCompletionProvider {
    clusterClient;
    lspProcess;
    constructor(clusterClient, lspProcess) {
        this.clusterClient = clusterClient;
        this.lspProcess = lspProcess;
    }
    async provideCompletionItems(document, position, token, context) {
        const config = vscode.workspace.getConfiguration('rawrxd');
        if (!config.get('enabled', true)) {
            return [];
        }
        // Get document context (last 8K tokens)
        const prefix = document.getText(new vscode.Range(new vscode.Position(0, 0), position));
        // Truncate to reasonable context window
        const contextWindow = prefix.slice(-8192);
        const request = {
            uri: document.uri.toString(),
            languageId: document.languageId,
            prefix: contextWindow,
            line: position.line,
            character: position.character,
            maxTokens: config.get('maxTokens', 128),
            temperature: config.get('temperature', 0.2)
        };
        try {
            const response = await this.clusterClient.complete(request);
            if (!response || !response.items) {
                return [];
            }
            const items = response.items.map((item, index) => {
                const completion = new vscode.CompletionItem(item.label, this.mapKind(item.kind));
                completion.insertText = item.insertText;
                completion.detail = `RawrXD (${(item.score * 100).toFixed(1)}%)`;
                completion.documentation = new vscode.MarkdownString(`**Confidence:** ${(item.score * 100).toFixed(2)}%\n\n` +
                    `**Tokens:** ${item.tokens || 'N/A'}`);
                // Higher score = higher sort order
                completion.preselect = index === 0;
                completion.sortText = String(index).padStart(3, '0');
                return completion;
            });
            return items;
        }
        catch (error) {
            console.error('RawrXD completion error:', error);
            return [];
        }
    }
    mapKind(kind) {
        switch (kind) {
            case 'function': return vscode.CompletionItemKind.Function;
            case 'variable': return vscode.CompletionItemKind.Variable;
            case 'class': return vscode.CompletionItemKind.Class;
            case 'method': return vscode.CompletionItemKind.Method;
            case 'property': return vscode.CompletionItemKind.Property;
            case 'keyword': return vscode.CompletionItemKind.Keyword;
            case 'snippet': return vscode.CompletionItemKind.Snippet;
            default: return vscode.CompletionItemKind.Text;
        }
    }
}
exports.RawrXDCompletionProvider = RawrXDCompletionProvider;
//# sourceMappingURL=completionProvider.js.map