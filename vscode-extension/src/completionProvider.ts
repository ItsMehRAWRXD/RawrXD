import * as vscode from 'vscode';
import { ChildProcess } from 'child_process';
import { RawrXDClusterClient, CompletionRequest, CompletionResponse } from './clusterClient';

export class RawrXDCompletionProvider implements vscode.CompletionItemProvider {
    constructor(
        private clusterClient: RawrXDClusterClient,
        private lspProcess: ChildProcess | undefined
    ) {}

    async provideCompletionItems(
        document: vscode.TextDocument,
        position: vscode.Position,
        token: vscode.CancellationToken,
        context: vscode.CompletionContext
    ): Promise<vscode.CompletionItem[] | vscode.CompletionList> {
        
        const config = vscode.workspace.getConfiguration('rawrxd');
        if (!config.get('enabled', true)) {
            return [];
        }

        // Get document context (last 8K tokens)
        const prefix = document.getText(new vscode.Range(
            new vscode.Position(0, 0),
            position
        ));
        
        // Truncate to reasonable context window
        const contextWindow = prefix.slice(-8192);

        const request: CompletionRequest = {
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

            const items: vscode.CompletionItem[] = response.items.map((item, index) => {
                const completion = new vscode.CompletionItem(
                    item.label,
                    this.mapKind(item.kind)
                );
                completion.insertText = item.insertText;
                completion.detail = `RawrXD (${(item.score * 100).toFixed(1)}%)`;
                completion.documentation = new vscode.MarkdownString(
                    `**Confidence:** ${(item.score * 100).toFixed(2)}%\n\n` +
                    `**Tokens:** ${item.tokens || 'N/A'}`
                );
                // Higher score = higher sort order
                completion.preselect = index === 0;
                completion.sortText = String(index).padStart(3, '0');
                
                return completion;
            });

            return items;

        } catch (error) {
            console.error('RawrXD completion error:', error);
            return [];
        }
    }

    private mapKind(kind?: string): vscode.CompletionItemKind {
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
