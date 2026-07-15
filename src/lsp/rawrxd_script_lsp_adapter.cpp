// ============================================================================
// rawrxd_script_lsp_adapter.cpp — RawrXD-Script LSP Adapter Implementation
// ============================================================================

#include "lsp/rawrxd_script_lsp_adapter.hpp"
#include "lsp/RawrXD_LSPServer.h"

#include <algorithm>
#include <regex>
#include <sstream>
#include <filesystem>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace RawrXD {
namespace LSP {

// ============================================================================
// Static Instance
// ============================================================================

static std::unique_ptr<RawrXDScriptLSPAdapter> g_rawrxdScriptAdapter;

RawrXDScriptLSPAdapter* GetRawrXDScriptLSPAdapter() {
    return g_rawrxdScriptAdapter.get();
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

RawrXDScriptLSPAdapter::RawrXDScriptLSPAdapter() = default;
RawrXDScriptLSPAdapter::~RawrXDScriptLSPAdapter() {
    if (m_server) {
        unregisterFromServer(m_server);
    }
}

// ============================================================================
// Initialization
// ============================================================================

bool RawrXDScriptLSPAdapter::initialize() {
    // Register with LanguageRegistry
    LanguageRegistry& registry = LanguageRegistry::instance();
    
    LanguageInfo rxsInfo;
    rxsInfo.id = "rawrxd-script";
    rxsInfo.name = "RawrXD-Script";
    rxsInfo.extensions = {".rxs", ".rawrxd", ".rx"};
    rxsInfo.shebangPatterns = {};  // No shebang support needed
    rxsInfo.astLanguage = LanguageId::JavaScript;  // Closest match
    rxsInfo.capabilities = LanguageCapability::All;
    rxsInfo.caseSensitive = true;
    rxsInfo.lineComment = "//";
    rxsInfo.blockCommentStart = "/*";
    rxsInfo.blockCommentEnd = "*/";
    
    // Keywords
    rxsInfo.keywords = {
        "var", "let", "const", "function", "return", "if", "else",
        "while", "for", "break", "continue", "switch", "case", "default",
        "try", "catch", "finally", "throw", "new", "this", "typeof",
        "instanceof", "in", "of", "async", "await", "yield", "class",
        "extends", "super", "import", "export", "from", "as", "with",
        "debugger", "delete", "void", "null", "undefined", "true", "false"
    };
    
    // Builtin types
    rxsInfo.builtinTypes = {
        "Number", "String", "Boolean", "Object", "Array", "Function",
        "Date", "RegExp", "Error", "Promise", "Map", "Set", "WeakMap", "WeakSet"
    };
    
    // Completion triggers
    rxsInfo.completionTriggers = {
        {".", true, false},    // Member access
        {"[", false, false},  // Computed property
        {"(", false, false},  // Function call
        {",", false, false},  // Arguments
        {"=", false, false},  // Assignment
    };
    
    // Symbol extraction rules (regex-based fallback)
    rxsInfo.extractionRules = {
        {"function\\s+([a-zA-Z_][a-zA-Z0-9_]*)\\s*\\(", SymbolKind::Function, 10, false},
        {"var\\s+([a-zA-Z_][a-zA-Z0-9_]*)\\s*[=:]", SymbolKind::Variable, 5, false},
        {"let\\s+([a-zA-Z_][a-zA-Z0-9_]*)\\s*[=:]", SymbolKind::Variable, 5, false},
        {"const\\s+([a-zA-Z_][a-zA-Z0-9_]*)\\s*[=:]", SymbolKind::Constant, 5, false},
        {"class\\s+([a-zA-Z_][a-zA-Z0-9_]*)", SymbolKind::Class, 10, false},
    };
    
    m_languageInfo = registry.registerLanguage(rxsInfo);
    
    return m_languageInfo != nullptr;
}

// ============================================================================
// Server Registration
// ============================================================================

void RawrXDScriptLSPAdapter::registerWithServer(RawrXDLSPServer* server) {
    if (!server) return;
    
    m_server = server;
    
    // Register custom request handlers for RawrXD-Script
    // These will be called when the server receives requests for .rxs files
    
    // Note: The actual registration depends on RawrXDLSPServer's API
    // This is a placeholder for the integration pattern
}

void RawrXDScriptLSPAdapter::unregisterFromServer(RawrXDLSPServer* server) {
    if (!server || server != m_server) return;
    
    // Unregister custom handlers
    m_server = nullptr;
}

// ============================================================================
// Document Lifecycle
// ============================================================================

void RawrXDScriptLSPAdapter::didOpen(const std::string& uri, const std::string& content) {
    std::lock_guard<std::mutex> lk(m_documentsMutex);
    
    Document doc;
    doc.uri = uri;
    doc.content = content;
    doc.ast = parseDocument(content);
    doc.symbols = extractSymbols(content, uriToFilePath(uri));
    doc.lastModified = std::chrono::steady_clock::now();
    
    m_documents[uri] = std::move(doc);
}

void RawrXDScriptLSPAdapter::didChange(const std::string& uri, const std::string& content) {
    std::lock_guard<std::mutex> lk(m_documentsMutex);
    
    auto it = m_documents.find(uri);
    if (it != m_documents.end()) {
        it->second.content = content;
        it->second.ast = parseDocument(content);
        it->second.symbols = extractSymbols(content, uriToFilePath(uri));
        it->second.lastModified = std::chrono::steady_clock::now();
    }
}

void RawrXDScriptLSPAdapter::didClose(const std::string& uri) {
    std::lock_guard<std::mutex> lk(m_documentsMutex);
    m_documents.erase(uri);
}

void RawrXDScriptLSPAdapter::didSave(const std::string& uri) {
    // Re-parse and validate on save
    std::lock_guard<std::mutex> lk(m_documentsMutex);
    
    auto it = m_documents.find(uri);
    if (it != m_documents.end()) {
        it->second.ast = parseDocument(it->second.content);
        it->second.symbols = extractSymbols(it->second.content, uriToFilePath(uri));
    }
}

// ============================================================================
// LSP Request Handlers
// ============================================================================

json RawrXDScriptLSPAdapter::onHover(const std::string& uri, int line, int character) {
    auto symOpt = findSymbolAtPosition(uri, line, character);
    if (!symOpt.has_value()) {
        return nullptr;
    }
    
    const auto& sym = symOpt.value();
    
    json result;
    result["contents"]["kind"] = "markdown";
    result["contents"]["value"] = generateDocumentation(sym);
    result["range"]["start"]["line"] = sym.line;
    result["range"]["start"]["character"] = sym.startChar;
    result["range"]["end"]["line"] = sym.line;
    result["range"]["end"]["character"] = sym.endChar;
    
    return result;
}

json RawrXDScriptLSPAdapter::onCompletion(const std::string& uri, int line, int character) {
    // Get prefix at cursor
    std::string prefix;
    {
        std::lock_guard<std::mutex> lk(m_documentsMutex);
        auto it = m_documents.find(uri);
        if (it != m_documents.end()) {
            std::istringstream iss(it->second.content);
            std::string curLine;
            for (int i = 0; i <= line && std::getline(iss, curLine); i++) {}
            
            // Walk backwards to find identifier start
            int start = character - 1;
            while (start >= 0 && (std::isalnum(curLine[start]) || curLine[start] == '_')) {
                start--;
            }
            prefix = curLine.substr(start + 1, character - start - 1);
        }
    }
    
    json items = json::array();
    auto symbols = getDocumentSymbols(uri);
    
    for (const auto& sym : symbols) {
        if (!prefix.empty() && sym.name.find(prefix) != 0) {
            continue;  // Simple prefix matching
        }
        
        json item;
        item["label"] = sym.name;
        item["detail"] = sym.detail;
        item["kind"] = static_cast<int>(sym.kind);
        item["documentation"]["kind"] = "markdown";
        item["documentation"]["value"] = sym.documentation;
        
        items.push_back(std::move(item));
    }
    
    // Add keywords
    if (m_languageInfo) {
        for (const auto& kw : m_languageInfo->keywords) {
            if (kw.find(prefix) == 0 || prefix.empty()) {
                json item;
                item["label"] = kw;
                item["kind"] = 14;  // Keyword
                item["detail"] = "keyword";
                items.push_back(std::move(item));
            }
        }
    }
    
    json result;
    result["isIncomplete"] = false;
    result["items"] = std::move(items);
    return result;
}

json RawrXDScriptLSPAdapter::onDefinition(const std::string& uri, int line, int character) {
    auto symOpt = findSymbolAtPosition(uri, line, character);
    if (!symOpt.has_value()) {
        return json::array();
    }
    
    const auto& sym = symOpt.value();
    
    // Find all definitions of this symbol
    json locations = json::array();
    auto symbols = getDocumentSymbols(uri);
    
    for (const auto& s : symbols) {
        if (s.name == sym.name) {
            json loc;
            loc["uri"] = sym.filePath;
            loc["range"]["start"]["line"] = s.line;
            loc["range"]["start"]["character"] = s.startChar;
            loc["range"]["end"]["line"] = s.line;
            loc["range"]["end"]["character"] = s.endChar;
            locations.push_back(std::move(loc));
        }
    }
    
    return locations;
}

json RawrXDScriptLSPAdapter::onReferences(const std::string& uri, int line, int character) {
    // Similar to definition but finds all references
    auto symOpt = findSymbolAtPosition(uri, line, character);
    if (!symOpt.has_value()) {
        return json::array();
    }
    
    const auto& sym = symOpt.value();
    
    // For now, return same as definition (would need full text search for true references)
    return onDefinition(uri, line, character);
}

json RawrXDScriptLSPAdapter::onDocumentSymbol(const std::string& uri) {
    auto symbols = getDocumentSymbols(uri);
    
    json result = json::array();
    for (const auto& sym : symbols) {
        json item;
        item["name"] = sym.name;
        item["detail"] = sym.detail;
        item["kind"] = static_cast<int>(sym.kind);
        item["range"]["start"]["line"] = sym.line;
        item["range"]["start"]["character"] = sym.startChar;
        item["range"]["end"]["line"] = sym.line;
        item["range"]["end"]["character"] = sym.endChar;
        item["selectionRange"] = item["range"];
        
        if (!sym.containerName.empty()) {
            item["containerName"] = sym.containerName;
        }
        
        result.push_back(std::move(item));
    }
    
    return result;
}

json RawrXDScriptLSPAdapter::onSemanticTokens(const std::string& uri) {
    // Return semantic tokens for syntax highlighting
    // This is a simplified implementation
    
    json result;
    result["data"] = json::array();  // Empty for now - would need token stream
    return result;
}

// ============================================================================
// Symbol Extraction
// ============================================================================

std::vector<RawrXDScriptSymbol> RawrXDScriptLSPAdapter::extractSymbols(
    const std::string& content, const std::string& filePath) {
    
    std::vector<RawrXDScriptSymbol> symbols;
    
    // Parse AST
    auto ast = parseDocument(content);
    if (ast) {
        extractSymbolsFromNode(ast, filePath, symbols);
    }
    
    // Fallback: regex-based extraction for symbols not in AST
    // Function declarations
    std::regex funcRegex(R"(function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\()");
    std::sregex_iterator funcIt(content.begin(), content.end(), funcRegex);
    std::sregex_iterator funcEnd;
    
    for (; funcIt != funcEnd; ++funcIt) {
        RawrXDScriptSymbol sym;
        sym.name = (*funcIt)[1].str();
        sym.kind = SymbolKind::Function;
        sym.filePath = filePath;
        
        // Calculate line/position
        size_t pos = funcIt->position();
        int line = 0, col = 0;
        for (size_t i = 0; i < pos; i++) {
            if (content[i] == '\n') {
                line++;
                col = 0;
            } else {
                col++;
            }
        }
        sym.line = line;
        sym.startChar = col + 9;  // After "function "
        sym.endChar = sym.startChar + sym.name.length();
        sym.detail = "function " + sym.name + "()";
        sym.documentation = "Function defined in " + filePath;
        
        symbols.push_back(std::move(sym));
    }
    
    // Variable declarations
    std::regex varRegex(R"((var|let|const)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[=:])");
    std::sregex_iterator varIt(content.begin(), content.end(), varRegex);
    std::sregex_iterator varEnd;
    
    for (; varIt != varEnd; ++varIt) {
        RawrXDScriptSymbol sym;
        sym.name = (*varIt)[2].str();
        std::string kind = (*varIt)[1].str();
        sym.kind = (kind == "const") ? SymbolKind::Constant : SymbolKind::Variable;
        sym.filePath = filePath;
        
        size_t pos = varIt->position();
        int line = 0, col = 0;
        for (size_t i = 0; i < pos; i++) {
            if (content[i] == '\n') {
                line++;
                col = 0;
            } else {
                col++;
            }
        }
        sym.line = line;
        sym.startChar = col + kind.length() + 1;
        sym.endChar = sym.startChar + sym.name.length();
        sym.detail = kind + " " + sym.name;
        sym.documentation = kind + " declaration in " + filePath;
        
        symbols.push_back(std::move(sym));
    }
    
    return symbols;
}

void RawrXDScriptLSPAdapter::extractSymbolsFromNode(
    const std::shared_ptr<Script::AST::ASTNode>& node,
    const std::string& filePath,
    std::vector<RawrXDScriptSymbol>& symbols,
    const std::string& containerName) {
    
    if (!node) return;
    
    // Create symbol for this node if it's a definition
    RawrXDScriptSymbol sym;
    bool isDefinition = false;
    
    switch (node->type) {
        case Script::AST::NodeType::FunctionDeclaration:
        case Script::AST::NodeType::FunctionExpression: {
            // Extract function name
            // TODO: Get name from child identifier node
            sym.kind = SymbolKind::Function;
            isDefinition = true;
            break;
        }
        case Script::AST::NodeType::VariableDeclaration: {
            sym.kind = SymbolKind::Variable;
            isDefinition = true;
            break;
        }
        case Script::AST::NodeType::Identifier: {
            // Only create symbol if this is a declaration context
            break;
        }
        default:
            break;
    }
    
    if (isDefinition) {
        sym.filePath = filePath;
        sym.line = node->loc.start.line - 1;  // LSP uses 0-based
        sym.startChar = node->loc.start.column;
        sym.endChar = node->loc.end.column;
        sym.containerName = containerName;
        sym.astNodeType = node->type;
        sym.astNode = node;
        
        symbols.push_back(std::move(sym));
    }
    
    // Recurse into children
    for (const auto& child : node->GetChildren()) {
        std::string newContainer = containerName;
        if (isDefinition && !sym.name.empty()) {
            newContainer = sym.name;
        }
        extractSymbolsFromNode(child, filePath, symbols, newContainer);
    }
}

// ============================================================================
// Helper Methods
// ============================================================================

std::shared_ptr<Script::AST::ASTNode> RawrXDScriptLSPAdapter::parseDocument(const std::string& content) {
    // TODO: Integrate with actual RawrXD-Script parser
    // For now, return nullptr (regex fallback will be used)
    return nullptr;
}

std::optional<RawrXDScriptSymbol> RawrXDScriptLSPAdapter::findSymbolAtPosition(
    const std::string& uri, int line, int character) {
    
    auto symbols = getDocumentSymbols(uri);
    
    for (const auto& sym : symbols) {
        if (sym.line == line && 
            character >= sym.startChar && 
            character <= sym.endChar) {
            return sym;
        }
    }
    
    return std::nullopt;
}

std::vector<RawrXDScriptSymbol> RawrXDScriptLSPAdapter::getDocumentSymbols(const std::string& uri) {
    std::lock_guard<std::mutex> lk(m_documentsMutex);
    
    auto it = m_documents.find(uri);
    if (it != m_documents.end()) {
        return it->second.symbols;
    }
    
    return {};
}

SymbolKind RawrXDScriptLSPAdapter::mapAstNodeTypeToSymbolKind(Script::AST::NodeType type) {
    switch (type) {
        case Script::AST::NodeType::FunctionDeclaration:
        case Script::AST::NodeType::FunctionExpression:
        case Script::AST::NodeType::ArrowFunctionExpression:
            return SymbolKind::Function;
        case Script::AST::NodeType::VariableDeclaration:
            return SymbolKind::Variable;
        case Script::AST::NodeType::ClassDeclaration:
            return SymbolKind::Class;
        case Script::AST::NodeType::MethodDefinition:
            return SymbolKind::Method;
        case Script::AST::NodeType::Property:
            return SymbolKind::Property;
        case Script::AST::NodeType::Identifier:
            return SymbolKind::Variable;
        default:
            return SymbolKind::Variable;
    }
}

std::string RawrXDScriptLSPAdapter::generateDetail(const RawrXDScriptSymbol& sym) {
    switch (sym.kind) {
        case SymbolKind::Function:
            return "function " + sym.name + "()";
        case SymbolKind::Variable:
            return "var " + sym.name;
        case SymbolKind::Constant:
            return "const " + sym.name;
        case SymbolKind::Class:
            return "class " + sym.name;
        default:
            return sym.name;
    }
}

std::string RawrXDScriptLSPAdapter::generateDocumentation(const RawrXDScriptSymbol& sym) {
    std::string doc = "```javascript\n";
    doc += generateDetail(sym);
    doc += "\n```\n\n";
    
    if (!sym.containerName.empty()) {
        doc += "*Defined in* `" + sym.containerName + "`\n\n";
    }
    
    doc += "*Location:* " + sym.filePath + ":" + std::to_string(sym.line + 1);
    
    if (!sym.documentation.empty()) {
        doc += "\n\n" + sym.documentation;
    }
    
    return doc;
}

std::string RawrXDScriptLSPAdapter::uriToFilePath(const std::string& uri) {
    if (uri.rfind("file:///", 0) == 0) {
        std::string path = uri.substr(8);
        // URL decode
        std::string result;
        for (size_t i = 0; i < path.length(); i++) {
            if (path[i] == '%' && i + 2 < path.length()) {
                int hex = std::stoi(path.substr(i + 1, 2), nullptr, 16);
                result += static_cast<char>(hex);
                i += 2;
            } else if (path[i] == '/') {
                result += '\\';  // Windows path
            } else {
                result += path[i];
            }
        }
        return result;
    }
    return uri;
}

std::string RawrXDScriptLSPAdapter::filePathToUri(const std::string& filePath) {
    std::string uri = "file:///";
    for (char c : filePath) {
        if (c == '\\') {
            uri += '/';
        } else if (c == ' ' || c == '%' || c == '#' || c == '?') {
            char buf[4];
            snprintf(buf, sizeof(buf), "%%%02X", static_cast<unsigned char>(c));
            uri += buf;
        } else {
            uri += c;
        }
    }
    return uri;
}

// ============================================================================
// Global Registration
// ============================================================================

bool RegisterRawrXDScriptLanguageSupport() {
    if (!g_rawrxdScriptAdapter) {
        g_rawrxdScriptAdapter = std::make_unique<RawrXDScriptLSPAdapter>();
    }
    return g_rawrxdScriptAdapter->initialize();
}

} // namespace LSP
} // namespace RawrXD
