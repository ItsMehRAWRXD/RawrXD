/**
 * @file ast_completion_bridge.cpp
 * @brief AST Completion Bridge Implementation
 */

#include "ide/ast_completion_bridge.h"
#include "LanguageServerIntegration.h"
#include "completion/smart_completion.h"
#include <algorithm>
#include <sstream>

namespace RawrXD {
namespace IDE {

// ============================================================================
// Constructor / Destructor
// ============================================================================

ASTCompletionBridge::ASTCompletionBridge() = default;
ASTCompletionBridge::~ASTCompletionBridge() = default;

// ============================================================================
// Initialization
// ============================================================================

void ASTCompletionBridge::initialize(std::shared_ptr<LanguageServerIntegration> lsp) {
    m_lsp = lsp;
}

// ============================================================================
// AST Context Capture
// ============================================================================

ASTContext ASTCompletionBridge::captureASTContext(const std::string& uri,
                                                const std::string& language,
                                                int line, int column) {
    ASTContext ast;
    ast.uri = uri;
    ast.language = language;
    
    if (!m_lsp) {
        ast.isValid = false;
        return ast;
    }
    
    // Get document symbols from LSP
    // This would typically call m_lsp->getDocumentSymbols(uri)
    // For now, we construct from available context
    
    // Build scope context from position
    ast.scope.currentScope = "global";
    ast.scope.scopeStack.push_back("global");
    
    // Parse the file to extract scope information
    // In a full implementation, this would use LSP's documentSymbol
    
    ast.isValid = true;
    return ast;
}

// ============================================================================
// Completion Context Enrichment
// ============================================================================

void ASTCompletionBridge::enrichCompletionContext(Completion::CompletionContext& ctx,
                                               const ASTContext& ast) {
    if (!ast.isValid) return;
    
    // Add scope information to context
    ctx.definedSymbols["__current_scope__"] = ast.scope.currentScope;
    ctx.definedSymbols["__in_class__"] = ast.scope.inClass ? "true" : "false";
    ctx.definedSymbols["__in_function__"] = ast.scope.inFunction ? "true" : "false";
    ctx.definedSymbols["__access__"] = ast.scope.inPrivateBlock ? "private" :
                                        ast.scope.inProtectedBlock ? "protected" : "public";
    
    // Add visible symbols
    for (const auto& symbol : ast.visibleSymbols) {
        if (isSymbolAccessible(symbol, ast.scope)) {
            ctx.definedSymbols[symbol.name] = symbol.type;
        }
    }
    
    // Add member symbols if in class context
    if (ast.scope.inClass && ast.currentClass) {
        for (const auto& member : ast.memberSymbols) {
            if (isSymbolAccessible(member, ast.scope)) {
                ctx.definedSymbols[member.name] = member.type;
            }
        }
    }
    
    // Add local symbols if in function
    if (ast.scope.inFunction) {
        for (const auto& local : ast.localSymbols) {
            ctx.definedSymbols[local.name] = local.type;
        }
    }
}

// ============================================================================
// Scope-Based Filtering
// ============================================================================

std::vector<Completion::CompletionItem> ASTCompletionBridge::filterByScope(
    const std::vector<Completion::CompletionItem>& items,
    const ASTContext& ast) {
    
    if (!ast.isValid) return items;
    
    std::vector<Completion::CompletionItem> filtered;
    
    for (const auto& item : items) {
        // Check if item is accessible from current scope
        // This uses the detail field which may contain scope info
        bool accessible = true;
        
        // Filter private members if not in class scope
        if (ast.scope.inClass) {
            if (item.detail.find("private") != std::string::npos &&
                !ast.scope.inPrivateBlock && !ast.scope.inProtectedBlock) {
                accessible = false;
            }
        }
        
        if (accessible) {
            filtered.push_back(item);
        }
    }
    
    return filtered;
}

// ============================================================================
// Scope-Aware Completions
// ============================================================================

std::vector<Completion::CompletionItem> ASTCompletionBridge::getScopeCompletions(
    const ASTContext& ast,
    const std::string& prefix) {
    
    std::vector<Completion::CompletionItem> completions;
    
    if (!ast.isValid) return completions;
    
    // Add visible symbols
    for (const auto& symbol : ast.visibleSymbols) {
        if (symbol.name.find(prefix) == 0) {
            Completion::CompletionItem item;
            item.label = symbol.name;
            item.insertText = symbol.name;
            item.detail = symbol.type + " (" + symbol.kind + ")";
            item.documentation = "Scope: " + symbol.scope;
            
            // Set kind based on symbol type
            if (symbol.kind == "function") {
                item.kind = Completion::CompletionItem::Kind::Function;
            } else if (symbol.kind == "class" || symbol.kind == "struct") {
                item.kind = Completion::CompletionItem::Kind::Class;
            } else if (symbol.kind == "variable") {
                item.kind = Completion::CompletionItem::Kind::Variable;
            } else {
                item.kind = Completion::CompletionItem::Kind::Text;
            }
            
            completions.push_back(item);
        }
    }
    
    // Add member symbols if in class
    if (ast.scope.inClass) {
        for (const auto& member : ast.memberSymbols) {
            if (member.name.find(prefix) == 0 && isSymbolAccessible(member, ast.scope)) {
                Completion::CompletionItem item;
                item.label = member.name;
                item.insertText = member.name;
                item.detail = member.type + " (" + member.kind + ")";
                item.documentation = "Member of " + ast.currentClass->name;
                item.kind = Completion::CompletionItem::Kind::Field;
                completions.push_back(item);
            }
        }
    }
    
    return completions;
}

// ============================================================================
// Symbol Accessibility
// ============================================================================

bool ASTCompletionBridge::isSymbolAccessible(const SymbolInfo& symbol,
                                            const ScopeContext& scope) {
    // Public symbols are always accessible
    if (symbol.isPublic) return true;
    
    // Private symbols only accessible within same class
    if (!symbol.isPublic && scope.inClass) {
        // Check if we're in the same class or a friend
        // For now, simplified: accessible if in any class scope
        return true;
    }
    
    return false;
}

// ============================================================================
// Member Completions
// ============================================================================

std::vector<Completion::CompletionItem> ASTCompletionBridge::getMemberCompletions(
    const std::string& typeName,
    const ASTContext& ast) {
    
    std::vector<Completion::CompletionItem> completions;
    
    // Find the type in visible symbols
    auto it = std::find_if(ast.visibleSymbols.begin(), ast.visibleSymbols.end(),
        [&typeName](const SymbolInfo& s) { return s.name == typeName && s.kind == "class"; });
    
    if (it == ast.visibleSymbols.end()) return completions;
    
    // Get members of this type
    // In a full implementation, this would query the LSP for type members
    // For now, we return member symbols that match the type
    
    for (const auto& member : ast.memberSymbols) {
        if (member.scope == it->scope + "::" + it->name) {
            Completion::CompletionItem item;
            item.label = member.name;
            item.insertText = member.name;
            item.detail = member.type;
            item.kind = member.kind == "function" ? 
                Completion::CompletionItem::Kind::Method : 
                Completion::CompletionItem::Kind::Field;
            completions.push_back(item);
        }
    }
    
    return completions;
}

// ============================================================================
// C API Implementation
// ============================================================================

extern "C" {

void* ASTBridge_Create() {
    return new ASTCompletionBridge();
}

void ASTBridge_Destroy(void* bridge) {
    delete static_cast<ASTCompletionBridge*>(bridge);
}

void ASTBridge_Initialize(void* bridge, void* lsp) {
    if (!bridge || !lsp) return;
    auto* b = static_cast<ASTCompletionBridge*>(bridge);
    auto* lspPtr = static_cast<LanguageServerIntegration*>(lsp);
    // Note: This is a simplification - in practice we'd need shared_ptr management
}

const char* ASTBridge_CaptureContext(void* bridge,
                                    const char* uri,
                                    const char* language,
                                    int line, int column) {
    if (!bridge || !uri || !language) return nullptr;
    
    auto* b = static_cast<ASTCompletionBridge*>(bridge);
    auto ast = b->captureASTContext(uri, language, line, column);
    
    // Serialize to JSON
    nlohmann::json j;
    j["uri"] = ast.uri;
    j["language"] = ast.language;
    j["isValid"] = ast.isValid;
    j["scope"]["current"] = ast.scope.currentScope;
    j["scope"]["inClass"] = ast.scope.inClass;
    j["scope"]["inFunction"] = ast.scope.inFunction;
    
    std::string result = j.dump();
    char* cstr = new char[result.length() + 1];
    strcpy(cstr, result.c_str());
    return cstr;
}

void ASTBridge_FreeString(const char* str) {
    delete[] str;
}

} // extern "C"

} // namespace IDE
} // namespace RawrXD
