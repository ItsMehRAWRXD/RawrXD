// RawrXD-Script LSP Adapter
// Bridges RawrXD-Script parser to RawrXD_LSPServer infrastructure
// File: d:\rawrxd\src\script\lsp\rawrxd_script_lsp_adapter.hpp

#ifndef RAWRXD_SCRIPT_LSP_ADAPTER_HPP
#define RAWRXD_SCRIPT_LSP_ADAPTER_HPP

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <nlohmann/json.hpp>

// Forward declarations
namespace RawrXD {
namespace LSPServer {
    class RawrXDLSPServer;
}
namespace Script {
namespace AST {
    struct ASTNode;
    struct ProgramNode;
}
}
}

namespace RawrXD {
namespace Script {
namespace LSP {

using json = nlohmann::json;

// ============================================================================
// Symbol Information for RawrXD-Script
// ============================================================================

enum class ScriptSymbolKind {
    Variable = 1,
    Function = 2,
    Parameter = 3,
    Class = 4,
    Property = 5,
    Constant = 6
};

struct ScriptSymbol {
    std::string name;
    ScriptSymbolKind kind;
    std::string detail;
    std::string filePath;
    int line;
    int startChar;
    int endChar;
    std::string containerName;
    std::string documentation;
};

// ============================================================================
// Document State
// ============================================================================

struct ScriptDocument {
    std::string uri;
    std::string content;
    std::string version;
    std::shared_ptr<AST::ProgramNode> ast;
    std::vector<ScriptSymbol> symbols;
    bool parsed = false;
};

// ============================================================================
// RawrXD-Script LSP Adapter
// ============================================================================

class RawrXDScriptLSPAdapter {
public:
    RawrXDScriptLSPAdapter();
    ~RawrXDScriptLSPAdapter();

    // Register with the main LSP server
    void registerWithServer(RawrXD::LSPServer::RawrXDLSPServer* server);

    // Language identification
    static constexpr const char* LANGUAGE_ID = "rawrxd-script";
    static constexpr const char* FILE_EXTENSION = ".rxs";

    // Document lifecycle
    void onDocumentOpen(const std::string& uri, const std::string& content, int version);
    void onDocumentChange(const std::string& uri, const std::string& content, int version);
    void onDocumentClose(const std::string& uri);
    void onDocumentSave(const std::string& uri);

    // LSP Features
    json handleHover(const std::string& uri, int line, int character);
    json handleCompletion(const std::string& uri, int line, int character, const std::string& prefix);
    json handleDefinition(const std::string& uri, int line, int character);
    json handleReferences(const std::string& uri, int line, int character);
    json handleDocumentSymbol(const std::string& uri);
    json handleSemanticTokens(const std::string& uri);

    // Diagnostics
    json generateDiagnostics(const std::string& uri);

    // Server capabilities contribution
    json getServerCapabilities();

private:
    // Document store
    std::unordered_map<std::string, std::unique_ptr<ScriptDocument>> m_documents;
    std::mutex m_docMutex;

    // Parse document and build AST
    void parseDocument(ScriptDocument& doc);

    // Extract symbols from AST
    void extractSymbols(ScriptDocument& doc);

    // Find symbol at position
    const ScriptSymbol* findSymbolAtPosition(const ScriptDocument& doc, int line, int character);

    // Find all symbols with name
    std::vector<const ScriptSymbol*> findSymbolsByName(const std::string& name);

    // Get word at position from content
    std::string getWordAtPosition(const std::string& content, int line, int character);

    // Convert ScriptSymbolKind to LSP CompletionItemKind
    int toCompletionItemKind(ScriptSymbolKind kind);

    // Convert ScriptSymbolKind to LSP SymbolKind
    int toSymbolKind(ScriptSymbolKind kind);

    // Semantic token encoding
    std::vector<uint32_t> encodeSemanticTokens(const ScriptDocument& doc);
};

// ============================================================================
// Registration Helper
// ============================================================================

// Call this to register RawrXD-Script support with the main LSP server
void RegisterRawrXDScriptLanguage(RawrXD::LSPServer::RawrXDLSPServer* server);

} // namespace LSP
} // namespace Script
} // namespace RawrXD

#endif // RAWRXD_SCRIPT_LSP_ADAPTER_HPP
