// ============================================================================
// rawrxd_script_lsp_adapter.hpp — RawrXD-Script Language Server Adapter
// ============================================================================
// Bridges RawrXD-Script (JavaScript engine) to the RawrXD LSP infrastructure.
//
// Integration: Registers with LanguageRegistry for .rxs files and provides
// symbol extraction using the RawrXD-Script lexer/parser.
//
// Copyright (c) 2026 RawrXD Project — All rights reserved.
// ============================================================================

#pragma once

#include "lsp/language_registry.h"
#include "script/ast/ast_schema.hpp"

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace LSP {

// Forward declarations
class RawrXDLSPServer;
struct SymbolInfo;

// ============================================================================
// RawrXD-Script Symbol Information
// ============================================================================

struct RawrXDScriptSymbol {
    std::string name;
    std::string detail;
    SymbolKind kind;
    std::string filePath;
    int line;
    int startChar;
    int endChar;
    std::string containerName;
    std::string documentation;
    
    // RawrXD-Script specific
    Script::AST::NodeType astNodeType;
    std::shared_ptr<Script::AST::ASTNode> astNode;
};

// ============================================================================
// RawrXD-Script LSP Adapter
// ============================================================================

class RawrXDScriptLSPAdapter {
public:
    RawrXDScriptLSPAdapter();
    ~RawrXDScriptLSPAdapter();
    
    // Initialize and register with LanguageRegistry
    bool initialize();
    
    // Register with LSP server for custom handlers
    void registerWithServer(RawrXDLSPServer* server);
    void unregisterFromServer(RawrXDLSPServer* server);
    
    // Document lifecycle
    void didOpen(const std::string& uri, const std::string& content);
    void didChange(const std::string& uri, const std::string& content);
    void didClose(const std::string& uri);
    void didSave(const std::string& uri);
    
    // LSP Request Handlers
    nlohmann::json onHover(const std::string& uri, int line, int character);
    nlohmann::json onCompletion(const std::string& uri, int line, int character);
    nlohmann::json onDefinition(const std::string& uri, int line, int character);
    nlohmann::json onReferences(const std::string& uri, int line, int character);
    nlohmann::json onDocumentSymbol(const std::string& uri);
    nlohmann::json onSemanticTokens(const std::string& uri);
    
    // Symbol extraction from AST
    std::vector<RawrXDScriptSymbol> extractSymbols(const std::string& content, const std::string& filePath);
    
    // Find symbol at position
    std::optional<RawrXDScriptSymbol> findSymbolAtPosition(
        const std::string& uri, int line, int character);
    
    // Get all symbols for a document
    std::vector<RawrXDScriptSymbol> getDocumentSymbols(const std::string& uri);
    
    // Convert to LSP SymbolInfo for server integration
    SymbolInfo toLspSymbolInfo(const RawrXDScriptSymbol& sym);
    
private:
    // Document cache
    struct Document {
        std::string uri;
        std::string content;
        std::shared_ptr<Script::AST::ASTNode> ast;
        std::vector<RawrXDScriptSymbol> symbols;
        std::chrono::steady_clock::time_point lastModified;
    };
    
    std::unordered_map<std::string, Document> m_documents;
    std::mutex m_documentsMutex;
    
    // Language info reference
    const LanguageInfo* m_languageInfo = nullptr;
    
    // Server reference (for registering custom handlers)
    RawrXDLSPServer* m_server = nullptr;
    
    // AST parsing
    std::shared_ptr<Script::AST::ASTNode> parseDocument(const std::string& content);
    
    // Symbol extraction helpers
    void extractSymbolsFromNode(
        const std::shared_ptr<Script::AST::ASTNode>& node,
        const std::string& filePath,
        std::vector<RawrXDScriptSymbol>& symbols,
        const std::string& containerName = "");
    
    SymbolKind mapAstNodeTypeToSymbolKind(Script::AST::NodeType type);
    std::string generateDetail(const RawrXDScriptSymbol& sym);
    std::string generateDocumentation(const RawrXDScriptSymbol& sym);
    
    // Content helpers
    std::string getWordAtPosition(const std::string& content, int line, int character);
    std::string uriToFilePath(const std::string& uri);
    std::string filePathToUri(const std::string& filePath);
};

// ============================================================================
// Registration Helper
// ============================================================================

// Call this to register RawrXD-Script support with the LSP system
bool RegisterRawrXDScriptLanguageSupport();

// Get the global adapter instance
RawrXDScriptLSPAdapter* GetRawrXDScriptLSPAdapter();

} // namespace LSP
} // namespace RawrXD
