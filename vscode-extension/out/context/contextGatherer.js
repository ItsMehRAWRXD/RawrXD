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
exports.gatherContext = gatherContext;
exports.buildPrompt = buildPrompt;
const vscode = __importStar(require("vscode"));
/**
 * Gather rich context for AI prompts
 * This gives the model surrounding code, imports, and symbols
 */
async function gatherContext(document, selection) {
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
async function findSurroundingFunction(document, selection) {
    try {
        const symbols = await vscode.commands.executeCommand('vscode.executeDocumentSymbolProvider', document.uri);
        if (!symbols)
            return undefined;
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
    }
    catch {
        // Fallback: extract surrounding 50 lines
    }
    // Fallback: get surrounding context
    const startLine = Math.max(0, selection.start.line - 25);
    const endLine = Math.min(document.lineCount - 1, selection.end.line + 25);
    const range = new vscode.Range(startLine, 0, endLine, document.lineAt(endLine).text.length);
    return document.getText(range);
}
function extractImports(document) {
    const text = document.getText();
    const imports = [];
    const language = document.languageId;
    if (language === 'typescript' || language === 'javascript') {
        // Match: import ... from '...' or import { ... } from '...'
        const importRegex = /import\s+(?:(?:\{[^}]*\}|[^'"])*\s+from\s+)?['"]([^'"]+)['"];?/g;
        let match;
        while ((match = importRegex.exec(text)) !== null) {
            imports.push(match[0]);
        }
    }
    else if (language === 'python') {
        // Match: import ... or from ... import ...
        const importRegex = /^(?:from\s+\S+\s+)?import\s+.+$/gm;
        let match;
        while ((match = importRegex.exec(text)) !== null) {
            imports.push(match[0]);
        }
    }
    else if (language === 'cpp' || language === 'c') {
        // Match: #include <...> or #include "..."
        const includeRegex = /#include\s+[<"][^">]+[>"]/g;
        let match;
        while ((match = includeRegex.exec(text)) !== null) {
            imports.push(match[0]);
        }
    }
    return imports.slice(0, 20); // Limit to 20 imports
}
async function extractSymbols(document) {
    try {
        const symbols = await vscode.commands.executeCommand('vscode.executeDocumentSymbolProvider', document.uri);
        if (!symbols)
            return [];
        const names = [];
        const extractNames = (syms) => {
            for (const sym of syms) {
                names.push(sym.name);
                if (sym.children) {
                    extractNames(sym.children);
                }
            }
        };
        extractNames(symbols);
        return names.slice(0, 50); // Limit to 50 symbols
    }
    catch {
        return [];
    }
}
/**
 * Build a rich prompt with context
 */
function buildPrompt(intent, context, userInput) {
    const parts = [];
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
//# sourceMappingURL=contextGatherer.js.map