import * as vscode from 'vscode';

export interface CodeContext {
    selection: string;
    surroundingFunction?: string;
    imports: string[];
    symbols: string[];
    filePath: string;
    languageId: string;
}

/**
 * Gather rich context for AI prompts
 * This gives the model surrounding code, imports, and symbols
 */
export async function gatherContext(
    document: vscode.TextDocument,
    selection: vscode.Range
): Promise<CodeContext> {
    const selectionText = document.getText(selection);
    
    // Get surrounding function/class
    const surroundingFunction = await findSurroundingFunction(document, selection);
    
    // Get imports/includes
    const imports = extractImports(document);
    
    // Get symbols in file
    const symbols = await extractSymbols(document);
    
    return {
        selection: selectionText,
        surroundingFunction,
        imports,
        symbols,
        filePath: document.uri.fsPath,
        languageId: document.languageId
    };
}

async function findSurroundingFunction(
    document: vscode.TextDocument,
    selection: vscode.Range
): Promise<string | undefined> {
    try {
        const symbols = await vscode.commands.executeCommand<vscode.DocumentSymbol[]>(
            'vscode.executeDocumentSymbolProvider',
            document.uri
        );
        
        if (!symbols) return undefined;
        
        // Find the symbol that contains the selection
        for (const symbol of symbols) {
            if (symbol.range.contains(selection)) {
                return document.getText(symbol.range);
            }
            
            // Check children
            if (symbol.children) {
                for (const child of symbol.children) {
                    if (child.range.contains(selection)) {
                        return document.getText(child.range);
                    }
                }
            }
        }
    } catch {
        // Fallback: extract surrounding 50 lines
    }
    
    // Fallback: get surrounding context
    const startLine = Math.max(0, selection.start.line - 25);
    const endLine = Math.min(document.lineCount - 1, selection.end.line + 25);
    const range = new vscode.Range(startLine, 0, endLine, document.lineAt(endLine).text.length);
    return document.getText(range);
}

function extractImports(document: vscode.TextDocument): string[] {
    const text = document.getText();
    const imports: string[] = [];
    const language = document.languageId;
    
    if (language === 'typescript' || language === 'javascript') {
        // Match: import ... from '...' or import { ... } from '...'
        const importRegex = /import\s+(?:(?:\{[^}]*\}|[^'"])*\s+from\s+)?['"]([^'"]+)['"];?/g;
        let match;
        while ((match = importRegex.exec(text)) !== null) {
            imports.push(match[0]);
        }
    } else if (language === 'python') {
        // Match: import ... or from ... import ...
        const importRegex = /^(?:from\s+\S+\s+)?import\s+.+$/gm;
        let match;
        while ((match = importRegex.exec(text)) !== null) {
            imports.push(match[0]);
        }
    } else if (language === 'cpp' || language === 'c') {
        // Match: #include <...> or #include "..."
        const includeRegex = /#include\s+[<"][^">]+[>"]/g;
        let match;
        while ((match = includeRegex.exec(text)) !== null) {
            imports.push(match[0]);
        }
    }
    
    return imports.slice(0, 20); // Limit to 20 imports
}

async function extractSymbols(document: vscode.TextDocument): Promise<string[]> {
    try {
        const symbols = await vscode.commands.executeCommand<vscode.DocumentSymbol[]>(
            'vscode.executeDocumentSymbolProvider',
            document.uri
        );
        
        if (!symbols) return [];
        
        const names: string[] = [];
        const extractNames = (syms: vscode.DocumentSymbol[]) => {
            for (const sym of syms) {
                names.push(sym.name);
                if (sym.children) {
                    extractNames(sym.children);
                }
            }
        };
        
        extractNames(symbols);
        return names.slice(0, 50); // Limit to 50 symbols
    } catch {
        return [];
    }
}

/**
 * Build a rich prompt with context
 */
export function buildPrompt(
    intent: string,
    context: CodeContext,
    userInput: string
): string {
    const parts: string[] = [];
    
    // File context
    parts.push(`File: ${context.filePath}`);
    parts.push(`Language: ${context.languageId}`);
    
    // Imports
    if (context.imports.length > 0) {
        parts.push('\nImports:');
        parts.push(context.imports.join('\n'));
    }
    
    // Symbols
    if (context.symbols.length > 0) {
        parts.push('\nSymbols in file:');
        parts.push(context.symbols.join(', '));
    }
    
    // Surrounding context
    if (context.surroundingFunction) {
        parts.push('\nSurrounding context:');
        parts.push('```');
        parts.push(context.surroundingFunction);
        parts.push('```');
    }
    
    // Selection
    parts.push('\nSelected code:');
    parts.push('```');
    parts.push(context.selection);
    parts.push('```');
    
    // Intent-specific instruction
    parts.push(`\nInstruction: ${userInput}`);
    
    return parts.join('\n');
}
