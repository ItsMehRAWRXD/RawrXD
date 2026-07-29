// ============================================================================
// LSPClient.h - Production Language Server Protocol Client
// ============================================================================
// Features: JSON-RPC 2.0, process management, diagnostics, completions
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <atomic>

namespace RawrXD {
namespace LSP {

// LSP Position (0-based line, 0-based character)
struct Position {
    uint32_t line = 0;
    uint32_t character = 0;
};

// LSP Range
struct Range {
    Position start;
    Position end;
};

// LSP Location (file + range)
struct Location {
    std::string uri;
    Range range;
};

// LSP Diagnostic
struct Diagnostic {
    Range range;
    int severity = 0; // 1=Error, 2=Warning, 3=Info, 4=Hint
    std::string code;
    std::string source;
    std::string message;
};

// LSP TextEdit
struct TextEdit {
    Range range;
    std::string newText;
};

// LSP CompletionItem
struct CompletionItem {
    std::string label;
    int kind = 0; // 1=Text, 2=Method, 3=Function, etc.
    std::string detail;
    std::string documentation;
    std::string insertText;
    TextEdit textEdit;
};

// LSP SignatureInformation
struct SignatureInformation {
    std::string label;
    std::string documentation;
    std::vector<std::string> parameters;
    int activeParameter = 0;
};

// LSP Hover
struct Hover {
    std::string contents;
    Range range;
};

// LSP DocumentSymbol
struct DocumentSymbol {
    std::string name;
    std::string detail;
    int kind = 0;
    Range range;
    Range selectionRange;
    std::vector<DocumentSymbol> children;
};

// Callback types
using DiagnosticsCallback = std::function<void(const std::string& uri, const std::vector<Diagnostic>& diagnostics)>;
using CompletionCallback = std::function<void(const std::vector<CompletionItem>& items)>;
using HoverCallback = std::function<void(const Hover& hover)>;
using SignatureCallback = std::function<void(const SignatureInformation& sig)>;
using SymbolCallback = std::function<void(const std::vector<DocumentSymbol>& symbols)>;

// ============================================================================
// LSPClient - Production LSP Client
// ============================================================================

class LSPClient {
public:
    LSPClient();
    ~LSPClient();

    // Initialize with language server command
    bool Initialize(const std::string& command, const std::vector<std::string>& args,
                    const std::string& workspaceRoot);

    // Shutdown
    void Shutdown();

    // Check if connected
    bool IsConnected() const;

    // Set callbacks
    void SetDiagnosticsCallback(DiagnosticsCallback callback);
    void SetServerLogCallback(std::function<void(const std::string&)> callback);

    // Text Document Synchronization
    bool DidOpen(const std::string& uri, const std::string& languageId, 
                 const std::string& text);
    bool DidChange(const std::string& uri, const std::vector<TextEdit>& changes);
    bool DidClose(const std::string& uri);
    bool DidSave(const std::string& uri);

    // Language Features
    void Completion(const std::string& uri, Position position, CompletionCallback callback);
    void Hover(const std::string& uri, Position position, HoverCallback callback);
    void SignatureHelp(const std::string& uri, Position position, SignatureCallback callback);
    void GoToDefinition(const std::string& uri, Position position, 
                        std::function<void(const std::vector<Location>&)> callback);
    void DocumentSymbols(const std::string& uri, SymbolCallback callback);

    // Request/Response handling
    std::string SendRequest(const std::string& method, const std::string& params);
    void SendNotification(const std::string& method, const std::string& params);

    // Process management
    bool IsServerRunning() const;
    void KillServer();

private:
    // Process handles
    void* hProcess_ = nullptr;
    void* hStdInWrite_ = nullptr;
    void* hStdInRead_ = nullptr;
    void* hStdOutWrite_ = nullptr;
    void* hStdOutRead_ = nullptr;
    void* hStdErrRead_ = nullptr;

    // State
    std::atomic<bool> connected_{false};
    std::atomic<bool> running_{false};
    std::atomic<int> nextId_{1};
    std::string workspaceRoot_;

    // Callbacks
    DiagnosticsCallback diagnosticsCallback_;
    std::function<void(const std::string&)> serverLogCallback_;

    // Response handling
    std::unordered_map<int, std::function<void(const std::string&)>> pendingRequests_;
    std::mutex pendingMutex_;

    // Reader thread
    std::thread readerThread_;
    void ReaderLoop();

    // Message handling
    void ProcessMessage(const std::string& message);
    void HandleResponse(const std::string& id, const std::string& result);
    void HandleNotification(const std::string& method, const std::string& params);

    // JSON-RPC helpers
    std::string BuildRequest(const std::string& method, const std::string& params, int id);
    std::string BuildNotification(const std::string& method, const std::string& params);
    bool SendMessage(const std::string& message);
    std::string ReadMessage();

    // JSON helpers
    std::string EscapeJson(const std::string& str);
    std::string PositionToJson(Position pos);
    std::string RangeToJson(Range range);
    std::string LocationToJson(Location loc);
    Position JsonToPosition(const std::string& json);
    Range JsonToRange(const std::string& json);
    Diagnostic ParseDiagnostic(const std::string& json);
    CompletionItem ParseCompletionItem(const std::string& json);
    Hover ParseHover(const std::string& json);
    SignatureInformation ParseSignature(const std::string& json);
    DocumentSymbol ParseDocumentSymbol(const std::string& json);
    Location ParseLocation(const std::string& json);
};

// ============================================================================
// C API
// ============================================================================

extern "C" {
    void* LSPClient_Create();
    void LSPClient_Destroy(void* client);
    int LSPClient_Initialize(void* client, const char* command, 
                             const char** args, int argCount,
                             const char* workspaceRoot);
    void LSPClient_Shutdown(void* client);
    int LSPClient_IsConnected(void* client);
    
    int LSPClient_DidOpen(void* client, const char* uri, 
                          const char* languageId, const char* text);
    int LSPClient_DidChange(void* client, const char* uri,
                            int line, int startChar, int endChar, const char* newText);
    int LSPClient_DidClose(void* client, const char* uri);
    
    // Async requests - results come via callback
    void LSPClient_RequestCompletion(void* client, const char* uri, 
                                     int line, int character);
    void LSPClient_RequestHover(void* client, const char* uri,
                                int line, int character);
    void LSPClient_RequestSignature(void* client, const char* uri,
                                      int line, int character);
    
    // Set callbacks
    void LSPClient_SetDiagnosticsCallback(void* client, 
        void (*callback)(const char* uri, const char* diagnosticsJson));
    void LSPClient_SetCompletionCallback(void* client,
        void (*callback)(const char* itemsJson));
    void LSPClient_SetHoverCallback(void* client,
        void (*callback)(const char* hoverJson));
}

} // namespace LSP
} // namespace RawrXD
