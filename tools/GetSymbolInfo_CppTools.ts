/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { SymbolInformation, Location, Hover, Position, SymbolKind } from 'vscode';

/**
 * Interface for symbol information request
 */
interface GetSymbolInfoRequest {
    symbol: string;
    filePath?: string;
    line?: number;
}

/**
 * Interface for memory layout information (classes/structs)
 */
interface MemoryLayoutInfo {
    size: number;
    alignment: number;
    members: Array<{
        name: string;
        type: string;
        offset: number;
        size: number;
    }>;
}

/**
 * Interface for symbol information response
 */
interface GetSymbolInfoResponse {
    found: boolean;
    symbol: {
        name: string;
        kind: string;
        type?: string;
        signature?: string;
        documentation?: string;
    };
    location?: {
        filePath: string;
        line: number;
        column: number;
        endLine?: number;
        endColumn?: number;
    };
    typeInfo?: {
        canonicalType?: string;
        underlyingType?: string;
        isConst: boolean;
        isVolatile: boolean;
        isPointer: boolean;
        isReference: boolean;
        isArray: boolean;
        arraySize?: number;
    };
    memoryLayout?: MemoryLayoutInfo;
    error?: string;
}

/**
 * Get detailed symbol information for C/C++ symbols
 * 
 * This tool provides comprehensive information about a C/C++ symbol including:
 * - Symbol location (file, line, column)
 * - Type information (kind, signature, canonical type)
 * - Memory layout (for classes/structs: size, alignment, member offsets)
 * 
 * @param request The symbol information request
 * @returns Detailed symbol information
 */
export async function GetSymbolInfo_CppTools(request: GetSymbolInfoRequest): Promise<GetSymbolInfoResponse> {
    const { symbol, filePath, line } = request;

    if (!symbol) {
        return {
            found: false,
            symbol: { name: '', kind: 'unknown' },
            error: 'Symbol name is required'
        };
    }

    try {
        // Step 1: Find the symbol in the workspace
        const locations = await findSymbol(symbol, filePath, line);
        
        if (!locations || locations.length === 0) {
            return {
                found: false,
                symbol: { name: symbol, kind: 'unknown' },
                error: `Symbol '${symbol}' not found in workspace`
            };
        }

        // Use the first (best) match
        const location = locations[0];
        const document = await vscode.workspace.openTextDocument(location.uri);
        const position = location.range.start;

        // Step 2: Get hover information for type details
        const hover = await vscode.commands.executeCommand<Hover[]>(
            'vscode.executeHoverProvider',
            location.uri,
            position
        );

        // Step 3: Get document symbols to find the exact symbol kind
        const documentSymbols = await vscode.commands.executeCommand<SymbolInformation[]>(
            'vscode.executeDocumentSymbolProvider',
            location.uri
        );

        // Find matching symbol in document symbols
        const matchingSymbol = findMatchingSymbol(documentSymbols, symbol, position);

        // Step 4: Build the response
        const response: GetSymbolInfoResponse = {
            found: true,
            symbol: {
                name: symbol,
                kind: matchingSymbol ? getSymbolKindString(matchingSymbol.kind) : 'unknown',
                documentation: extractDocumentation(hover)
            },
            location: {
                filePath: location.uri.fsPath,
                line: position.line + 1, // Convert to 1-based
                column: position.character + 1,
                endLine: location.range.end.line + 1,
                endColumn: location.range.end.character + 1
            }
        };

        // Step 5: Extract type information from hover
        if (hover && hover.length > 0) {
            const hoverText = hover[0].contents.map(c => 
                typeof c === 'string' ? c : c.value
            ).join('\n');
            
            response.symbol.type = extractTypeFromHover(hoverText);
            response.symbol.signature = extractSignature(hoverText);
            response.typeInfo = parseTypeInfo(hoverText);
        }

        // Step 6: For classes/structs, get memory layout information
        if (matchingSymbol && 
            (matchingSymbol.kind === SymbolKind.Class || 
             matchingSymbol.kind === SymbolKind.Struct)) {
            response.memoryLayout = await getMemoryLayout(document, matchingSymbol);
        }

        return response;

    } catch (error) {
        return {
            found: false,
            symbol: { name: symbol, kind: 'unknown' },
            error: `Error retrieving symbol information: ${error instanceof Error ? error.message : String(error)}`
        };
    }
}

/**
 * Find symbol locations in the workspace
 */
async function findSymbol(
    symbol: string, 
    filePath?: string, 
    line?: number
): Promise<Location[]> {
    
    // If filePath is provided, search in that specific file first
    if (filePath) {
        const uri = vscode.Uri.file(filePath);
        try {
            const locations = await vscode.commands.executeCommand<Location[]>(
                'vscode.executeDefinitionProvider',
                uri,
                new Position(line ? line - 1 : 0, 0)
            );
            
            if (locations && locations.length > 0) {
                return locations;
            }
        } catch {
            // Fall through to workspace search
        }
    }

    // Search entire workspace
    const symbols = await vscode.commands.executeCommand<SymbolInformation[]>(
        'vscode.executeWorkspaceSymbolProvider',
        symbol
    );

    if (symbols && symbols.length > 0) {
        return symbols
            .filter(s => s.name === symbol || s.name.includes(symbol))
            .map(s => s.location);
    }

    return [];
}

/**
 * Find matching symbol in document symbols
 */
function findMatchingSymbol(
    symbols: SymbolInformation[] | undefined,
    name: string,
    position: Position
): SymbolInformation | undefined {
    if (!symbols) return undefined;

    return symbols.find(s => {
        const nameMatch = s.name === name || s.name.includes(name);
        const positionMatch = s.location.range.start.line === position.line;
        return nameMatch && positionMatch;
    }) || symbols.find(s => s.name === name || s.name.includes(name));
}

/**
 * Convert SymbolKind to string
 */
function getSymbolKindString(kind: SymbolKind): string {
    const kindMap: Record<SymbolKind, string> = {
        [SymbolKind.File]: 'file',
        [SymbolKind.Module]: 'module',
        [SymbolKind.Namespace]: 'namespace',
        [SymbolKind.Package]: 'package',
        [SymbolKind.Class]: 'class',
        [SymbolKind.Method]: 'method',
        [SymbolKind.Property]: 'property',
        [SymbolKind.Field]: 'field',
        [SymbolKind.Constructor]: 'constructor',
        [SymbolKind.Enum]: 'enum',
        [SymbolKind.Interface]: 'interface',
        [SymbolKind.Function]: 'function',
        [SymbolKind.Variable]: 'variable',
        [SymbolKind.Constant]: 'constant',
        [SymbolKind.String]: 'string',
        [SymbolKind.Number]: 'number',
        [SymbolKind.Boolean]: 'boolean',
        [SymbolKind.Array]: 'array',
        [SymbolKind.Object]: 'object',
        [SymbolKind.Key]: 'key',
        [SymbolKind.Null]: 'null',
        [SymbolKind.EnumMember]: 'enum member',
        [SymbolKind.Struct]: 'struct',
        [SymbolKind.Event]: 'event',
        [SymbolKind.Operator]: 'operator',
        [SymbolKind.TypeParameter]: 'type parameter'
    };

    return kindMap[kind] || 'unknown';
}

/**
 * Extract documentation from hover information
 */
function extractDocumentation(hover: Hover[] | undefined): string | undefined {
    if (!hover || hover.length === 0) return undefined;
    
    const contents = hover[0].contents;
    if (Array.isArray(contents)) {
        // Find the documentation section (usually after the code block)
        const text = contents.map(c => typeof c === 'string' ? c : c.value).join('\n');
        const lines = text.split('\n');
        
        // Skip the first code block and return the rest as documentation
        let inCodeBlock = false;
        let docLines: string[] = [];
        
        for (const line of lines) {
            if (line.startsWith('```')) {
                inCodeBlock = !inCodeBlock;
                continue;
            }
            if (!inCodeBlock && line.trim()) {
                docLines.push(line);
            }
        }
        
        return docLines.length > 0 ? docLines.join('\n') : undefined;
    }
    
    return undefined;
}

/**
 * Extract type from hover text
 */
function extractTypeFromHover(hoverText: string): string | undefined {
    // Look for patterns like "type: typename" or in code blocks
    const lines = hoverText.split('\n');
    
    for (const line of lines) {
        // Match variable declarations: "type name"
        const varMatch = line.match(/^\s*(\w[\w\s:*&<>]+)\s+\w+\s*[=;)]/);
        if (varMatch) return varMatch[1].trim();
        
        // Match function returns in code blocks
        const funcMatch = line.match(/^(\w[\w\s:*&<>]*)\s+\w+\s*\(/);
        if (funcMatch) return funcMatch[1].trim();
        
        // Match after "type:"
        const typeMatch = line.match(/type:\s*(.+)/i);
        if (typeMatch) return typeMatch[1].trim();
    }
    
    return undefined;
}

/**
 * Extract function signature from hover text
 */
function extractSignature(hoverText: string): string | undefined {
    const lines = hoverText.split('\n');
    
    for (const line of lines) {
        // Look for function signatures
        const signatureMatch = line.match(/^[\w\s:*&<>]+\s+\w+\s*\([^)]*\)/);
        if (signatureMatch) return signatureMatch[0].trim();
        
        // Look for code block content
        if (line.includes('(') && line.includes(')') && !line.startsWith('```')) {
            return line.trim();
        }
    }
    
    return undefined;
}

/**
 * Parse type information from hover text
 */
function parseTypeInfo(hoverText: string): GetSymbolInfoResponse['typeInfo'] {
    const info: NonNullable<GetSymbolInfoResponse['typeInfo']> = {
        isConst: false,
        isVolatile: false,
        isPointer: false,
        isReference: false,
        isArray: false
    };

    // Check for const/volatile qualifiers
    info.isConst = /\bconst\b/.test(hoverText);
    info.isVolatile = /\bvolatile\b/.test(hoverText);
    
    // Check for pointer/reference
    info.isPointer = /\*/.test(hoverText);
    info.isReference = /&/.test(hoverText);
    
    // Check for array
    const arrayMatch = hoverText.match(/\[(\d+)\]/);
    if (arrayMatch) {
        info.isArray = true;
        info.arraySize = parseInt(arrayMatch[1], 10);
    }

    // Extract canonical type (simplified)
    const typeMatch = hoverText.match(/type:\s*([\w\s:*&<>]+)/i);
    if (typeMatch) {
        info.canonicalType = typeMatch[1].trim();
    }

    return info;
}

/**
 * Get memory layout information for classes/structs
 * This uses the C/C++ extension's custom hover information
 */
async function getMemoryLayout(
    document: vscode.TextDocument,
    symbol: SymbolInformation
): Promise<MemoryLayoutInfo | undefined> {
    
    try {
        // Request hover at the symbol location to get size information
        const hover = await vscode.commands.executeCommand<Hover[]>(
            'vscode.executeHoverProvider',
            document.uri,
            symbol.location.range.start
        );

        if (!hover || hover.length === 0) return undefined;

        const hoverText = hover[0].contents.map(c => 
            typeof c === 'string' ? c : c.value
        ).join('\n');

        // Parse size information from hover text
        // C/C++ extension typically includes size in bytes
        const sizeMatch = hoverText.match(/size:\s*(\d+)\s*bytes/i) ||
                          hoverText.match(/sizeof\([^)]+\)\s*=\s*(\d+)/i);
        
        const alignmentMatch = hoverText.match(/alignment:\s*(\d+)/i) ||
                               hoverText.match(/alignof\([^)]+\)\s*=\s*(\d+)/i);

        const layout: MemoryLayoutInfo = {
            size: sizeMatch ? parseInt(sizeMatch[1], 10) : 0,
            alignment: alignmentMatch ? parseInt(alignmentMatch[1], 10) : 0,
            members: []
        };

        // Try to get member information from document symbols
        const childSymbols = await vscode.commands.executeCommand<SymbolInformation[]>(
            'vscode.executeDocumentSymbolProvider',
            document.uri
        );

        if (childSymbols) {
            // Find members of this class/struct
            const members = findChildMembers(childSymbols, symbol);
            
            for (const member of members) {
                const memberHover = await vscode.commands.executeCommand<Hover[]>(
                    'vscode.executeHoverProvider',
                    document.uri,
                    member.location.range.start
                );

                const memberText = memberHover?.[0]?.contents.map(c => 
                    typeof c === 'string' ? c : c.value
                ).join('\n') || '';

                const memberSizeMatch = memberText.match(/size:\s*(\d+)\s*bytes/i);
                const memberOffsetMatch = memberText.match(/offset:\s*(\d+)/i) ||
                                          memberText.match(/at\s+offset\s+(\d+)/i);

                layout.members.push({
                    name: member.name,
                    type: extractTypeFromHover(memberText) || 'unknown',
                    offset: memberOffsetMatch ? parseInt(memberOffsetMatch[1], 10) : 0,
                    size: memberSizeMatch ? parseInt(memberSizeMatch[1], 10) : 0
                });
            }
        }

        return layout.size > 0 ? layout : undefined;

    } catch {
        return undefined;
    }
}

/**
 * Find child members of a class/struct
 */
function findChildMembers(
    symbols: SymbolInformation[],
    parent: SymbolInformation
): SymbolInformation[] {
    // This is a simplified implementation
    // In practice, you'd need to parse the document structure more carefully
    return symbols.filter(s => {
        // Check if symbol is within parent's range
        const parentRange = parent.location.range;
        const childRange = s.location.range;
        
        return childRange.start.line > parentRange.start.line &&
               childRange.end.line < parentRange.end.line &&
               (s.kind === SymbolKind.Field || 
                s.kind === SymbolKind.Property ||
                s.kind === SymbolKind.Variable);
    });
}

// Export the tool for registration
export const GetSymbolInfo_CppTools_Definition = {
    name: 'GetSymbolInfo_CppTools',
    description: 'Get detailed information about a C/C++ symbol including its type, location, and memory layout details',
    parameters: {
        type: 'object',
        properties: {
            symbol: {
                type: 'string',
                description: 'The symbol name to look up'
            },
            filePath: {
                type: 'string',
                description: 'Optional path to the file containing the symbol'
            },
            line: {
                type: 'number',
                description: 'Optional 1-based line number of the symbol occurrence'
            }
        },
        required: ['symbol']
    }
};
