// ============================================================================
// LspClient.hpp — Language Server Protocol Client
// ============================================================================
// Architecture: C++20, Win32, no Qt, no exceptions
//
// Provides bi-directional JSON-RPC 2.0 communication with LSP servers
// (clangd, pyright, rust-analyzer, etc.) via stdio pipes.
//
// Design: Async I/O with dedicated reader thread, message queue for UI thread
// dispatch. Supports full LSP 3.17 lifecycle.
//
// Phase 21: LSP Client Integration
// Copyright (c) 2024-2026 RawrXD IDE Project
// ============================================================================

#pragma once

#ifndef RAWRXD_LSP_CLIENT_HPP
#define RAWRXD_LSP_CLIENT_HPP

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include <atomic>
#include <mutex>
#include <queue>
#include <thread>
#include <optional>
#include <variant>

// Forward declarations
namespace RawrXD {
namespace LSP {

// ============================================================================
// JSON VALUE — Lightweight JSON representation
// ============================================================================

class JsonValue {
public:
    enum class Type {
        Null,
        Bool,
        Number,
        String,
        Array,
        Object
    };

    JsonValue() = default;
    JsonValue(bool b) : m_type(Type::Bool), m_bool(b) {}
    JsonValue(int n) : m_type(Type::Number), m_number(n) {}
    JsonValue(double n) : m_type(Type::Number), m_number(n) {}
    JsonValue(const char* s) : m_type(Type::String), m_string(s) {}
    JsonValue(std::string s) : m_type(Type::String), m_string(std::move(s)) {}

    // Type checking
    Type getType() const { return m_type; }
    bool isNull() const { return m_type == Type::Null; }
    bool isBool() const { return m_type == Type::Bool; }
    bool isNumber() const { return m_type == Type::Number; }
    bool isString() const { return m_type == Type::String; }
    bool isArray() const { return m_type == Type::Array; }
    bool isObject() const { return m_type == Type::Object; }

    // Value access
    bool asBool() const { return m_bool; }
    double asNumber() const { return m_number; }
    const std::string& asString() const { return m_string; }
    std::vector<JsonValue>& asArray() { return m_array; }
    const std::vector<JsonValue>& asArray() const { return m_array; }
    std::map<std::string, JsonValue>& asObject() { return m_object; }
    const std::map<std::string, JsonValue>& asObject() const { return m_object; }

    // Object accessors
    JsonValue& operator[](const std::string& key);
    const JsonValue& operator[](const std::string& key) const;
    bool hasKey(const std::string& key) const;

    // Array accessors
    JsonValue& operator[](size_t index);
    const JsonValue& operator[](size_t index) const;
    size_t size() const;

    void push_back(JsonValue value);

    // Serialization
    std::string toString() const;
    static JsonValue parse(const std::string& json);

private:
    Type m_type = Type::Null;
    bool m_bool = false;
    double m_number = 0.0;
    std::string m_string;
    std::vector<JsonValue> m_array;
    std::map<std::string, JsonValue> m_object;
};

// ============================================================================
// LSP MESSAGE — JSON-RPC 2.0 envelope
// ============================================================================

struct LspMessage {
    enum class Type {
        Request,      // Has id, method
        Response,     // Has id, result OR error
        Notification  // No id, just method
    };

    Type type = Type::Notification;
    std::optional<int> id;
    std::string method;
    JsonValue params;
    JsonValue result;
    JsonValue error;

    // Serialization
    std::string toJsonRpc() const;
    static std::optional<LspMessage> fromJsonRpc(const std::string& json);
};

// ============================================================================
// LSP CAPABILITIES — Server/client capability negotiation
// ============================================================================

struct ServerCapabilities {
    bool textDocumentSync = false;
    bool hoverProvider = false;
    bool completionProvider = false;
    bool definitionProvider = false;
    bool referencesProvider = false;
    bool documentSymbolProvider = false;
    bool workspaceSymbolProvider = false;
    bool codeActionProvider = false;
    bool codeLensProvider = false;
    bool documentFormattingProvider = false;
    bool documentRangeFormattingProvider = false;
    bool documentOnTypeFormattingProvider = false;
    bool renameProvider = false;
    bool foldingRangeProvider = false;
    bool executeCommandProvider = false;
    bool selectionRangeProvider = false;
    bool semanticTokensProvider = false;
    bool inlayHintProvider = false;
    bool inlineValueProvider = false;
    bool monikerProvider = false;
    bool typeHierarchyProvider = false;
    bool callHierarchyProvider = false;
    bool linkedEditingRangeProvider = false;

    void fromJson(const JsonValue& json);
};

struct ClientCapabilities {
    // Text document capabilities
    struct {
        bool synchronization = true;
        bool completion = true;
        bool hover = true;
        bool signatureHelp = true;
        bool definition = true;
        bool references = true;
        bool documentHighlight = true;
        bool documentSymbol = true;
        bool codeAction = true;
        bool codeLens = true;
        bool formatting = true;
        bool rangeFormatting = true;
        bool onTypeFormatting = true;
        bool rename = true;
        bool foldingRange = true;
        bool selectionRange = true;
        bool semanticTokens = true;
        bool inlayHint = true;
    } textDocument;

    // Workspace capabilities
    struct {
        bool applyEdit = true;
        bool workspaceEdit = true;
        bool didChangeConfiguration = true;
        bool didChangeWatchedFiles = true;
        bool symbol = true;
        bool executeCommand = true;
    } workspace;

    JsonValue toJson() const;
};

// ============================================================================
// LSP POSITION/RANGE — Text document locations
// ============================================================================

struct Position {
    uint32_t line = 0;
    uint32_t character = 0;

    JsonValue toJson() const;
    static Position fromJson(const JsonValue& json);
};

struct Range {
    Position start;
    Position end;

    JsonValue toJson() const;
    static Range fromJson(const JsonValue& json);
};

struct Location {
    std::string uri;
    Range range;

    JsonValue toJson() const;
    static Location fromJson(const JsonValue& json);
};

// ============================================================================
// DIAGNOSTIC — Error/warning/info markers
// ============================================================================

enum class DiagnosticSeverity {
    Error = 1,
    Warning = 2,
    Information = 3,
    Hint = 4
};

struct Diagnostic {
    Range range;
    DiagnosticSeverity severity;
    std::string code;
    std::string source;
    std::string message;
    std::vector<Range> relatedInformation;

    static Diagnostic fromJson(const JsonValue& json);
};

// ============================================================================
// COMPLETION ITEM — IntelliSense entries
// ============================================================================

enum class CompletionItemKind {
    Text = 1, Method = 2, Function = 3, Constructor = 4,
    Field = 5, Variable = 6, Class = 7, Interface = 8,
    Module = 9, Property = 10, Unit = 11, Value = 12,
    Enum = 13, Keyword = 14, Snippet = 15, Color = 16,
    File = 17, Reference = 18, Folder = 19, EnumMember = 20,
    Constant = 21, Struct = 22, Event = 23, Operator = 24,
    TypeParameter = 25
};

struct CompletionItem {
    std::string label;
    CompletionItemKind kind = CompletionItemKind::Text;
    std::string detail;
    std::string documentation;
    std::string insertText;
    std::string filterText;
    std::string sortText;

    static CompletionItem fromJson(const JsonValue& json);
};

// ============================================================================
// HOVER — Tooltip information
// ============================================================================

struct Hover {
    std::string contents;
    Range range;

    static Hover fromJson(const JsonValue& json);
};

// ============================================================================
// DOCUMENT SYMBOL — Outline/navigation tree
// ============================================================================

enum class SymbolKind {
    File = 1, Module = 2, Namespace = 3, Package = 4,
    Class = 5, Method = 6, Property = 7, Field = 8,
    Constructor = 9, Enum = 10, Interface = 11, Function = 12,
    Variable = 13, Constant = 14, String = 15, Number = 16,
    Boolean = 17, Array = 18, Object = 19, Key = 20,
    Null = 21, EnumMember = 22, Struct = 23, Event = 24,
    Operator = 25, TypeParameter = 26
};

struct DocumentSymbol {
    std::string name;
    std::string detail;
    SymbolKind kind;
    Range range;
    Range selectionRange;
    std::vector<DocumentSymbol> children;

    static DocumentSymbol fromJson(const JsonValue& json);
};

// ============================================================================
// LSP CLIENT — Main interface
// ============================================================================

class LspClient {
public:
    // Server configuration
    struct ServerConfig {
        std::string command;           // e.g., "clangd.exe"
        std::vector<std::string> args; // e.g., {"--background-index"}
        std::string rootUri;           // Workspace root
        std::map<std::string, std::string> env; // Environment variables
    };

    // Callback types
    using DiagnosticsCallback = std::function<void(const std::string& uri, const std::vector<Diagnostic>&)>;
    using LogMessageCallback = std::function<void(const std::string& message)>;
    using ShowMessageCallback = std::function<void(const std::string& message)>;
    using RequestCallback = std::function<void(const LspMessage& response)>;

    LspClient();
    ~LspClient();

    // Lifecycle
    bool initialize(const ServerConfig& config);
    void shutdown();
    bool isConnected() const { return m_connected; }

    // Document synchronization
    void textDocumentDidOpen(const std::string& uri, const std::string& languageId, const std::string& text);
    void textDocumentDidChange(const std::string& uri, const std::vector<Range>& changes, const std::vector<std::string>& texts);
    void textDocumentDidClose(const std::string& uri);
    void textDocumentDidSave(const std::string& uri);

    // Language features (requests)
    int requestHover(const std::string& uri, const Position& position, RequestCallback callback);
    int requestCompletion(const std::string& uri, const Position& position, RequestCallback callback);
    int requestDefinition(const std::string& uri, const Position& position, RequestCallback callback);
    int requestReferences(const std::string& uri, const Position& position, RequestCallback callback);
    int requestDocumentSymbols(const std::string& uri, RequestCallback callback);
    int requestWorkspaceSymbols(const std::string& query, RequestCallback callback);
    int requestSignatureHelp(const std::string& uri, const Position& position, RequestCallback callback);
    int requestCodeActions(const std::string& uri, const Range& range, RequestCallback callback);
    int requestFormatting(const std::string& uri, RequestCallback callback);
    int requestRename(const std::string& uri, const Position& position, const std::string& newName, RequestCallback callback);

    // Cancel a pending request
    void cancelRequest(int id);

    // Callback registration
    void setDiagnosticsCallback(DiagnosticsCallback callback) { m_diagnosticsCallback = callback; }
    void setLogMessageCallback(LogMessageCallback callback) { m_logMessageCallback = callback; }
    void setShowMessageCallback(ShowMessageCallback callback) { m_showMessageCallback = callback; }

    // Server capabilities
    const ServerCapabilities& getServerCapabilities() const { return m_serverCapabilities; }

    // Process pending messages (call from UI thread)
    void processMessages();

    // Static factory methods for common servers
    static ServerConfig createClangdConfig(const std::string& rootPath);
    static ServerConfig createPyrightConfig(const std::string& rootPath);
    static ServerConfig createRustAnalyzerConfig(const std::string& rootPath);

private:
    // Process/pipe management
    HANDLE m_hProcess = nullptr;
    HANDLE m_hStdinWrite = nullptr;
    HANDLE m_hStdoutRead = nullptr;
    HANDLE m_hStderrRead = nullptr;

    // Reader thread
    std::thread m_readerThread;
    std::atomic<bool> m_readerRunning{false};

    // Message queue (thread-safe)
    std::mutex m_queueMutex;
    std::queue<LspMessage> m_incomingMessages;

    // Request tracking
    std::mutex m_requestsMutex;
    int m_nextRequestId = 1;
    std::map<int, RequestCallback> m_pendingRequests;

    // State
    std::atomic<bool> m_connected{false};
    std::atomic<bool> m_initialized{false};
    ServerCapabilities m_serverCapabilities;
    ClientCapabilities m_clientCapabilities;
    std::string m_rootUri;

    // Callbacks
    DiagnosticsCallback m_diagnosticsCallback;
    LogMessageCallback m_logMessageCallback;
    ShowMessageCallback m_showMessageCallback;

    // Internal methods
    bool spawnProcess(const ServerConfig& config);
    void readerLoop();
    void sendMessage(const LspMessage& message);
    void sendRawMessage(const std::string& json);
    void handleIncomingMessage(const LspMessage& message);
    void handleResponse(const LspMessage& message);
    void handleNotification(const LspMessage& message);
    int getNextRequestId();

    // JSON-RPC framing
    std::string readMessage();
    bool writeMessage(const std::string& message);
};

// ============================================================================
// LSP CLIENT MANAGER — Multi-server management
// ============================================================================

class LspClientManager {
public:
    static LspClientManager& instance();

    // Server management
    bool startServer(const std::string& languageId, const LspClient::ServerConfig& config);
    void stopServer(const std::string& languageId);
    void stopAll();

    // Get client for language
    std::shared_ptr<LspClient> getClient(const std::string& languageId);
    std::shared_ptr<LspClient> getClientForFile(const std::string& filepath);

    // Auto-detect and start appropriate server
    bool autoStartForFile(const std::string& filepath, const std::string& rootPath);

    // Process messages for all clients
    void processAllMessages();

private:
    LspClientManager() = default;
    ~LspClientManager() { stopAll(); }

    std::mutex m_clientsMutex;
    std::map<std::string, std::shared_ptr<LspClient>> m_clients;

    // Language detection
    std::string detectLanguage(const std::string& filepath);
};

} // namespace LSP
} // namespace RawrXD

#endif // RAWRXD_LSP_CLIENT_HPP
