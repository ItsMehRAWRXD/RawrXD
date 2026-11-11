// ============================================================================
// LspClient.cpp — Language Server Protocol Client Implementation
// ============================================================================

#include "lsp/LspClient.hpp"
#include <windows.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace RawrXD {
namespace LSP {

// ============================================================================
// JSON VALUE IMPLEMENTATION
// ============================================================================

JsonValue& JsonValue::operator[](const std::string& key) {
    if (m_type != Type::Object) {
        m_type = Type::Object;
        m_object.clear();
    }
    return m_object[key];
}

const JsonValue& JsonValue::operator[](const std::string& key) const {
    static const JsonValue nullValue;
    if (m_type != Type::Object) return nullValue;
    auto it = m_object.find(key);
    return (it != m_object.end()) ? it->second : nullValue;
}

bool JsonValue::hasKey(const std::string& key) const {
    return m_type == Type::Object && m_object.find(key) != m_object.end();
}

JsonValue& JsonValue::operator[](size_t index) {
    if (m_type != Type::Array) {
        m_type = Type::Array;
        m_array.clear();
    }
    if (index >= m_array.size()) {
        m_array.resize(index + 1);
    }
    return m_array[index];
}

const JsonValue& JsonValue::operator[](size_t index) const {
    static const JsonValue nullValue;
    if (m_type != Type::Array || index >= m_array.size()) return nullValue;
    return m_array[index];
}

size_t JsonValue::size() const {
    if (m_type == Type::Array) return m_array.size();
    if (m_type == Type::Object) return m_object.size();
    return 0;
}

void JsonValue::push_back(JsonValue value) {
    if (m_type != Type::Array) {
        m_type = Type::Array;
        m_array.clear();
    }
    m_array.push_back(std::move(value));
}

std::string JsonValue::toString() const {
    switch (m_type) {
        case Type::Null: return "null";
        case Type::Bool: return m_bool ? "true" : "false";
        case Type::Number: {
            std::ostringstream oss;
            oss << m_number;
            return oss.str();
        }
        case Type::String: {
            std::string result = "\"";
            for (char c : m_string) {
                switch (c) {
                    case '"': result += "\\\""; break;
                    case '\\': result += "\\\\"; break;
                    case '\b': result += "\\b"; break;
                    case '\f': result += "\\f"; break;
                    case '\n': result += "\\n"; break;
                    case '\r': result += "\\r"; break;
                    case '\t': result += "\\t"; break;
                    default:
                        if (static_cast<unsigned char>(c) < 0x20) {
                            std::ostringstream oss;
                            oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
                            result += oss.str();
                        } else {
                            result += c;
                        }
                }
            }
            result += '"';
            return result;
        }
        case Type::Array: {
            std::string result = "[";
            for (size_t i = 0; i < m_array.size(); ++i) {
                if (i > 0) result += ",";
                result += m_array[i].toString();
            }
            result += "]";
            return result;
        }
        case Type::Object: {
            std::string result = "{";
            bool first = true;
            for (const auto& [key, value] : m_object) {
                if (!first) result += ",";
                first = false;
                result += JsonValue(key).toString() + ":" + value.toString();
            }
            result += "}";
            return result;
        }
    }
    return "null";
}

// Simple JSON parser (simplified for LSP use)
JsonValue JsonValue::parse(const std::string& json) {
    // TODO: Implement full JSON parser
    // For now, return null
    return JsonValue();
}

// ============================================================================
// LSP MESSAGE IMPLEMENTATION
// ============================================================================

std::string LspMessage::toJsonRpc() const {
    JsonValue envelope;
    envelope["jsonrpc"] = "2.0";

    if (type == Type::Request) {
        envelope["id"] = id.value_or(0);
        envelope["method"] = method;
        if (!params.isNull()) {
            envelope["params"] = params;
        }
    } else if (type == Type::Response) {
        envelope["id"] = id.value_or(0);
        if (!error.isNull()) {
            envelope["error"] = error;
        } else {
            envelope["result"] = result;
        }
    } else { // Notification
        envelope["method"] = method;
        if (!params.isNull()) {
            envelope["params"] = params;
        }
    }

    std::string content = envelope.toString();
    std::ostringstream oss;
    oss << "Content-Length: " << content.length() << "\r\n\r\n" << content;
    return oss.str();
}

std::optional<LspMessage> LspMessage::fromJsonRpc(const std::string& json) {
    // TODO: Parse JSON-RPC message
    return std::nullopt;
}

// ============================================================================
// POSITION/RANGE/LOCATION IMPLEMENTATION
// ============================================================================

JsonValue Position::toJson() const {
    JsonValue obj;
    obj["line"] = static_cast<int>(line);
    obj["character"] = static_cast<int>(character);
    return obj;
}

Position Position::fromJson(const JsonValue& json) {
    Position pos;
    if (json.hasKey("line")) pos.line = json["line"].asNumber();
    if (json.hasKey("character")) pos.character = json["character"].asNumber();
    return pos;
}

JsonValue Range::toJson() const {
    JsonValue obj;
    obj["start"] = start.toJson();
    obj["end"] = end.toJson();
    return obj;
}

Range Range::fromJson(const JsonValue& json) {
    Range range;
    if (json.hasKey("start")) range.start = Position::fromJson(json["start"]);
    if (json.hasKey("end")) range.end = Position::fromJson(json["end"]);
    return range;
}

JsonValue Location::toJson() const {
    JsonValue obj;
    obj["uri"] = uri;
    obj["range"] = range.toJson();
    return obj;
}

Location Location::fromJson(const JsonValue& json) {
    Location loc;
    if (json.hasKey("uri")) loc.uri = json["uri"].asString();
    if (json.hasKey("range")) loc.range = Range::fromJson(json["range"]);
    return loc;
}

// ============================================================================
// SERVER CAPABILITIES IMPLEMENTATION
// ============================================================================

void ServerCapabilities::fromJson(const JsonValue& json) {
    if (!json.hasKey("capabilities")) return;
    const auto& caps = json["capabilities"];

    textDocumentSync = caps.hasKey("textDocumentSync");
    hoverProvider = caps.hasKey("hoverProvider");
    completionProvider = caps.hasKey("completionProvider");
    definitionProvider = caps.hasKey("definitionProvider");
    referencesProvider = caps.hasKey("referencesProvider");
    documentSymbolProvider = caps.hasKey("documentSymbolProvider");
    workspaceSymbolProvider = caps.hasKey("workspaceSymbolProvider");
    codeActionProvider = caps.hasKey("codeActionProvider");
    codeLensProvider = caps.hasKey("codeLensProvider");
    documentFormattingProvider = caps.hasKey("documentFormattingProvider");
    documentRangeFormattingProvider = caps.hasKey("documentRangeFormattingProvider");
    documentOnTypeFormattingProvider = caps.hasKey("documentOnTypeFormattingProvider");
    renameProvider = caps.hasKey("renameProvider");
    foldingRangeProvider = caps.hasKey("foldingRangeProvider");
    executeCommandProvider = caps.hasKey("executeCommandProvider");
    selectionRangeProvider = caps.hasKey("selectionRangeProvider");
    semanticTokensProvider = caps.hasKey("semanticTokensProvider");
    inlayHintProvider = caps.hasKey("inlayHintProvider");
    inlineValueProvider = caps.hasKey("inlineValueProvider");
    monikerProvider = caps.hasKey("monikerProvider");
    typeHierarchyProvider = caps.hasKey("typeHierarchyProvider");
    callHierarchyProvider = caps.hasKey("callHierarchyProvider");
    linkedEditingRangeProvider = caps.hasKey("linkedEditingRangeProvider");
}

JsonValue ClientCapabilities::toJson() const {
    JsonValue caps;

    JsonValue textDoc;
    textDoc["synchronization"] = textDocument.synchronization;
    textDoc["completion"] = textDocument.completion;
    textDoc["hover"] = textDocument.hover;
    textDoc["signatureHelp"] = textDocument.signatureHelp;
    textDoc["definition"] = textDocument.definition;
    textDoc["references"] = textDocument.references;
    textDoc["documentHighlight"] = textDocument.documentHighlight;
    textDoc["documentSymbol"] = textDocument.documentSymbol;
    textDoc["codeAction"] = textDocument.codeAction;
    textDoc["codeLens"] = textDocument.codeLens;
    textDoc["formatting"] = textDocument.formatting;
    textDoc["rangeFormatting"] = textDocument.rangeFormatting;
    textDoc["onTypeFormatting"] = textDocument.onTypeFormatting;
    textDoc["rename"] = textDocument.rename;
    textDoc["foldingRange"] = textDocument.foldingRange;
    textDoc["selectionRange"] = textDocument.selectionRange;
    textDoc["semanticTokens"] = textDocument.semanticTokens;
    textDoc["inlayHint"] = textDocument.inlayHint;
    caps["textDocument"] = textDoc;

    JsonValue workspace;
    workspace["applyEdit"] = this->workspace.applyEdit;
    workspace["workspaceEdit"] = this->workspace.workspaceEdit;
    workspace["didChangeConfiguration"] = this->workspace.didChangeConfiguration;
    workspace["didChangeWatchedFiles"] = this->workspace.didChangeWatchedFiles;
    workspace["symbol"] = this->workspace.symbol;
    workspace["executeCommand"] = this->workspace.executeCommand;
    caps["workspace"] = workspace;

    return caps;
}

// ============================================================================
// LSP CLIENT IMPLEMENTATION
// ============================================================================

LspClient::LspClient() = default;

LspClient::~LspClient() {
    shutdown();
}

bool LspClient::initialize(const ServerConfig& config) {
    if (m_connected) {
        return true; // Already initialized
    }

    m_rootUri = config.rootUri;

    // Spawn the LSP server process
    if (!spawnProcess(config)) {
        return false;
    }

    // Start reader thread
    m_readerRunning = true;
    m_readerThread = std::thread(&LspClient::readerLoop, this);

    // Send initialize request
    JsonValue initParams;
    initParams["processId"] = static_cast<int>(GetCurrentProcessId());
    initParams["rootUri"] = m_rootUri;
    initParams["capabilities"] = m_clientCapabilities.toJson();

    LspMessage initMsg;
    initMsg.type = LspMessage::Type::Request;
    initMsg.id = getNextRequestId();
    initMsg.method = "initialize";
    initMsg.params = initParams;

    sendMessage(initMsg);

    // Wait for initialize response (simplified - should be async)
    // TODO: Implement proper async initialization

    m_connected = true;
    return true;
}

void LspClient::shutdown() {
    if (!m_connected) return;

    // Send shutdown request
    LspMessage shutdownMsg;
    shutdownMsg.type = LspMessage::Type::Request;
    shutdownMsg.id = getNextRequestId();
    shutdownMsg.method = "shutdown";
    sendMessage(shutdownMsg);

    // Send exit notification
    LspMessage exitMsg;
    exitMsg.type = LspMessage::Type::Notification;
    exitMsg.method = "exit";
    sendMessage(exitMsg);

    // Stop reader thread
    m_readerRunning = false;
    if (m_readerThread.joinable()) {
        m_readerThread.join();
    }

    // Close handles
    if (m_hStdinWrite) {
        CloseHandle(m_hStdinWrite);
        m_hStdinWrite = nullptr;
    }
    if (m_hStdoutRead) {
        CloseHandle(m_hStdoutRead);
        m_hStdoutRead = nullptr;
    }
    if (m_hStderrRead) {
        CloseHandle(m_hStderrRead);
        m_hStderrRead = nullptr;
    }
    if (m_hProcess) {
        TerminateProcess(m_hProcess, 0);
        CloseHandle(m_hProcess);
        m_hProcess = nullptr;
    }

    m_connected = false;
    m_initialized = false;
}

bool LspClient::spawnProcess(const ServerConfig& config) {
    // Build command line
    std::wstring cmdLine = L"\"" + std::wstring(config.command.begin(), config.command.end()) + L"\"";
    for (const auto& arg : config.args) {
        cmdLine += L" \"" + std::wstring(arg.begin(), arg.end()) + L"\"";
    }

    // Create pipes for stdin/stdout/stderr
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = nullptr;
    sa.bInheritHandle = TRUE;

    HANDLE hStdinRead, hStdoutWrite, hStderrWrite;

    if (!CreatePipe(&hStdinRead, &m_hStdinWrite, &sa, 0)) {
        return false;
    }
    if (!SetHandleInformation(m_hStdinWrite, HANDLE_FLAG_INHERIT, 0)) {
        return false;
    }

    if (!CreatePipe(&m_hStdoutRead, &hStdoutWrite, &sa, 0)) {
        return false;
    }
    if (!SetHandleInformation(m_hStdoutRead, HANDLE_FLAG_INHERIT, 0)) {
        return false;
    }

    if (!CreatePipe(&m_hStderrRead, &hStderrWrite, &sa, 0)) {
        return false;
    }
    if (!SetHandleInformation(m_hStderrRead, HANDLE_FLAG_INHERIT, 0)) {
        return false;
    }

    // Create process
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = hStdinRead;
    si.hStdOutput = hStdoutWrite;
    si.hStdError = hStderrWrite;

    PROCESS_INFORMATION pi = {};

    BOOL success = CreateProcessW(
        nullptr,
        cmdLine.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si,
        &pi
    );

    // Close our copies of the child's ends
    CloseHandle(hStdinRead);
    CloseHandle(hStdoutWrite);
    CloseHandle(hStderrWrite);

    if (!success) {
        CloseHandle(m_hStdinWrite);
        CloseHandle(m_hStdoutRead);
        CloseHandle(m_hStderrRead);
        m_hStdinWrite = nullptr;
        m_hStdoutRead = nullptr;
        m_hStderrRead = nullptr;
        return false;
    }

    m_hProcess = pi.hProcess;
    CloseHandle(pi.hThread);

    return true;
}

void LspClient::readerLoop() {
    while (m_readerRunning) {
        std::string message = readMessage();
        if (!message.empty()) {
            auto parsed = LspMessage::fromJsonRpc(message);
            if (parsed) {
                std::lock_guard<std::mutex> lock(m_queueMutex);
                m_incomingMessages.push(*parsed);
            }
        }
        Sleep(1); // Prevent busy-waiting
    }
}

std::string LspClient::readMessage() {
    // Read Content-Length header
    std::string header;
    char c;
    DWORD bytesRead;

    while (true) {
        if (!ReadFile(m_hStdoutRead, &c, 1, &bytesRead, nullptr) || bytesRead == 0) {
            return "";
        }
        header += c;
        if (header.size() >= 4 && header.substr(header.size() - 4) == "\r\n\r\n") {
            break;
        }
    }

    // Parse Content-Length
    size_t contentLength = 0;
    size_t pos = header.find("Content-Length: ");
    if (pos != std::string::npos) {
        size_t end = header.find("\r\n", pos);
        if (end != std::string::npos) {
            contentLength = std::stoull(header.substr(pos + 16, end - pos - 16));
        }
    }

    if (contentLength == 0) {
        return "";
    }

    // Read content
    std::string content;
    content.resize(contentLength);
    DWORD totalRead = 0;
    while (totalRead < contentLength) {
        DWORD toRead = static_cast<DWORD>(contentLength - totalRead);
        if (!ReadFile(m_hStdoutRead, &content[totalRead], toRead, &bytesRead, nullptr)) {
            return "";
        }
        totalRead += bytesRead;
    }

    return content;
}

void LspClient::sendMessage(const LspMessage& message) {
    sendRawMessage(message.toJsonRpc());
}

void LspClient::sendRawMessage(const std::string& json) {
    if (!m_hStdinWrite) return;

    DWORD written;
    WriteFile(m_hStdinWrite, json.c_str(), static_cast<DWORD>(json.length()), &written, nullptr);
}

int LspClient::getNextRequestId() {
    return ++m_nextRequestId;
}

// ============================================================================
// DOCUMENT SYNCHRONIZATION
// ============================================================================

void LspClient::textDocumentDidOpen(const std::string& uri, const std::string& languageId, const std::string& text) {
    JsonValue params;
    JsonValue doc;
    doc["uri"] = uri;
    doc["languageId"] = languageId;
    doc["version"] = 1;
    doc["text"] = text;
    params["textDocument"] = doc;

    LspMessage msg;
    msg.type = LspMessage::Type::Notification;
    msg.method = "textDocument/didOpen";
    msg.params = params;
    sendMessage(msg);
}

void LspClient::textDocumentDidChange(const std::string& uri, const std::vector<Range>& changes, const std::vector<std::string>& texts) {
    JsonValue params;
    params["textDocument"]["uri"] = uri;
    params["textDocument"]["version"] = 2; // TODO: Track versions properly

    JsonValue contentChanges;
    for (size_t i = 0; i < changes.size() && i < texts.size(); ++i) {
        JsonValue change;
        change["range"] = changes[i].toJson();
        change["text"] = texts[i];
        contentChanges.push_back(change);
    }
    params["contentChanges"] = contentChanges;

    LspMessage msg;
    msg.type = LspMessage::Type::Notification;
    msg.method = "textDocument/didChange";
    msg.params = params;
    sendMessage(msg);
}

void LspClient::textDocumentDidClose(const std::string& uri) {
    JsonValue params;
    params["textDocument"]["uri"] = uri;

    LspMessage msg;
    msg.type = LspMessage::Type::Notification;
    msg.method = "textDocument/didClose";
    msg.params = params;
    sendMessage(msg);
}

void LspClient::textDocumentDidSave(const std::string& uri) {
    JsonValue params;
    params["textDocument"]["uri"] = uri;

    LspMessage msg;
    msg.type = LspMessage::Type::Notification;
    msg.method = "textDocument/didSave";
    msg.params = params;
    sendMessage(msg);
}

// ============================================================================
// LANGUAGE FEATURE REQUESTS
// ============================================================================

int LspClient::requestHover(const std::string& uri, const Position& position, RequestCallback callback) {
    JsonValue params;
    params["textDocument"]["uri"] = uri;
    params["position"] = position.toJson();

    int id = getNextRequestId();
    {
        std::lock_guard<std::mutex> lock(m_requestsMutex);
        m_pendingRequests[id] = callback;
    }

    LspMessage msg;
    msg.type = LspMessage::Type::Request;
    msg.id = id;
    msg.method = "textDocument/hover";
    msg.params = params;
    sendMessage(msg);

    return id;
}

int LspClient::requestCompletion(const std::string& uri, const Position& position, RequestCallback callback) {
    JsonValue params;
    params["textDocument"]["uri"] = uri;
    params["position"] = position.toJson();

    int id = getNextRequestId();
    {
        std::lock_guard<std::mutex> lock(m_requestsMutex);
        m_pendingRequests[id] = callback;
    }

    LspMessage msg;
    msg.type = LspMessage::Type::Request;
    msg.id = id;
    msg.method = "textDocument/completion";
    msg.params = params;
    sendMessage(msg);

    return id;
}

int LspClient::requestDefinition(const std::string& uri, const Position& position, RequestCallback callback) {
    JsonValue params;
    params["textDocument"]["uri"] = uri;
    params["position"] = position.toJson();

    int id = getNextRequestId();
    {
        std::lock_guard<std::mutex> lock(m_requestsMutex);
        m_pendingRequests[id] = callback;
    }

    LspMessage msg;
    msg.type = LspMessage::Type::Request;
    msg.id = id;
    msg.method = "textDocument/definition";
    msg.params = params;
    sendMessage(msg);

    return id;
}

int LspClient::requestReferences(const std::string& uri, const Position& position, RequestCallback callback) {
    JsonValue params;
    params["textDocument"]["uri"] = uri;
    params["position"] = position.toJson();
    params["context"]["includeDeclaration"] = true;

    int id = getNextRequestId();
    {
        std::lock_guard<std::mutex> lock(m_requestsMutex);
        m_pendingRequests[id] = callback;
    }

    LspMessage msg;
    msg.type = LspMessage::Type::Request;
    msg.id = id;
    msg.method = "textDocument/references";
    msg.params = params;
    sendMessage(msg);

    return id;
}

int LspClient::requestDocumentSymbols(const std::string& uri, RequestCallback callback) {
    JsonValue params;
    params["textDocument"]["uri"] = uri;

    int id = getNextRequestId();
    {
        std::lock_guard<std::mutex> lock(m_requestsMutex);
        m_pendingRequests[id] = callback;
    }

    LspMessage msg;
    msg.type = LspMessage::Type::Request;
    msg.id = id;
    msg.method = "textDocument/documentSymbol";
    msg.params = params;
    sendMessage(msg);

    return id;
}

int LspClient::requestWorkspaceSymbols(const std::string& query, RequestCallback callback) {
    JsonValue params;
    params["query"] = query;

    int id = getNextRequestId();
    {
        std::lock_guard<std::mutex> lock(m_requestsMutex);
        m_pendingRequests[id] = callback;
    }

    LspMessage msg;
    msg.type = LspMessage::Type::Request;
    msg.id = id;
    msg.method = "workspace/symbol";
    msg.params = params;
    sendMessage(msg);

    return id;
}

int LspClient::requestSignatureHelp(const std::string& uri, const Position& position, RequestCallback callback) {
    JsonValue params;
    params["textDocument"]["uri"] = uri;
    params["position"] = position.toJson();

    int id = getNextRequestId();
    {
        std::lock_guard<std::mutex> lock(m_requestsMutex);
        m_pendingRequests[id] = callback;
    }

    LspMessage msg;
    msg.type = LspMessage::Type::Request;
    msg.id = id;
    msg.method = "textDocument/signatureHelp";
    msg.params = params;
    sendMessage(msg);

    return id;
}

int LspClient::requestCodeActions(const std::string& uri, const Range& range, RequestCallback callback) {
    JsonValue params;
    params["textDocument"]["uri"] = uri;
    params["range"] = range.toJson();
    params["context"]["diagnostics"] = JsonValue(); // Empty array

    int id = getNextRequestId();
    {
        std::lock_guard<std::mutex> lock(m_requestsMutex);
        m_pendingRequests[id] = callback;
    }

    LspMessage msg;
    msg.type = LspMessage::Type::Request;
    msg.id = id;
    msg.method = "textDocument/codeAction";
    msg.params = params;
    sendMessage(msg);

    return id;
}

int LspClient::requestFormatting(const std::string& uri, RequestCallback callback) {
    JsonValue params;
    params["textDocument"]["uri"] = uri;
    params["options"]["tabSize"] = 4;
    params["options"]["insertSpaces"] = true;

    int id = getNextRequestId();
    {
        std::lock_guard<std::mutex> lock(m_requestsMutex);
        m_pendingRequests[id] = callback;
    }

    LspMessage msg;
    msg.type = LspMessage::Type::Request;
    msg.id = id;
    msg.method = "textDocument/formatting";
    msg.params = params;
    sendMessage(msg);

    return id;
}

int LspClient::requestRename(const std::string& uri, const Position& position, const std::string& newName, RequestCallback callback) {
    JsonValue params;
    params["textDocument"]["uri"] = uri;
    params["position"] = position.toJson();
    params["newName"] = newName;

    int id = getNextRequestId();
    {
        std::lock_guard<std::mutex> lock(m_requestsMutex);
        m_pendingRequests[id] = callback;
    }

    LspMessage msg;
    msg.type = LspMessage::Type::Request;
    msg.id = id;
    msg.method = "textDocument/rename";
    msg.params = params;
    sendMessage(msg);

    return id;
}

void LspClient::cancelRequest(int id) {
    JsonValue params;
    params["id"] = id;

    LspMessage msg;
    msg.type = LspMessage::Type::Notification;
    msg.method = "$/cancelRequest";
    msg.params = params;
    sendMessage(msg);

    std::lock_guard<std::mutex> lock(m_requestsMutex);
    m_pendingRequests.erase(id);
}

// ============================================================================
// MESSAGE PROCESSING
// ============================================================================

void LspClient::processMessages() {
    std::queue<LspMessage> messages;
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        messages = std::move(m_incomingMessages);
        m_incomingMessages = std::queue<LspMessage>();
    }

    while (!messages.empty()) {
        handleIncomingMessage(messages.front());
        messages.pop();
    }
}

void LspClient::handleIncomingMessage(const LspMessage& message) {
    switch (message.type) {
        case LspMessage::Type::Response:
            handleResponse(message);
            break;
        case LspMessage::Type::Notification:
            handleNotification(message);
            break;
        default:
            break;
    }
}

void LspClient::handleResponse(const LspMessage& message) {
    if (!message.id) return;

    RequestCallback callback;
    {
        std::lock_guard<std::mutex> lock(m_requestsMutex);
        auto it = m_pendingRequests.find(*message.id);
        if (it != m_pendingRequests.end()) {
            callback = it->second;
            m_pendingRequests.erase(it);
        }
    }

    if (callback) {
        callback(message);
    }
}

void LspClient::handleNotification(const LspMessage& message) {
    if (message.method == "textDocument/publishDiagnostics") {
        if (m_diagnosticsCallback && message.params.hasKey("uri")) {
            std::string uri = message.params["uri"].asString();
            std::vector<Diagnostic> diagnostics;

            if (message.params.hasKey("diagnostics")) {
                const auto& diags = message.params["diagnostics"];
                for (size_t i = 0; i < diags.size(); ++i) {
                    diagnostics.push_back(Diagnostic::fromJson(diags[i]));
                }
            }

            m_diagnosticsCallback(uri, diagnostics);
        }
    } else if (message.method == "window/logMessage") {
        if (m_logMessageCallback && message.params.hasKey("message")) {
            m_logMessageCallback(message.params["message"].asString());
        }
    } else if (message.method == "window/showMessage") {
        if (m_showMessageCallback && message.params.hasKey("message")) {
            m_showMessageCallback(message.params["message"].asString());
        }
    }
}

// ============================================================================
// FACTORY METHODS
// ============================================================================

LspClient::ServerConfig LspClient::createClangdConfig(const std::string& rootPath) {
    ServerConfig config;
    config.command = "clangd.exe";
    config.args = {"--background-index", "--clang-tidy", "--header-insertion=iwyu"};
    config.rootUri = "file:///" + rootPath;
    return config;
}

LspClient::ServerConfig LspClient::createPyrightConfig(const std::string& rootPath) {
    ServerConfig config;
    config.command = "pyright-langserver.exe";
    config.args = {"--stdio"};
    config.rootUri = "file:///" + rootPath;
    return config;
}

LspClient::ServerConfig LspClient::createRustAnalyzerConfig(const std::string& rootPath) {
    ServerConfig config;
    config.command = "rust-analyzer.exe";
    config.args = {};
    config.rootUri = "file:///" + rootPath;
    return config;
}

// ============================================================================
// LSP CLIENT MANAGER
// ============================================================================

LspClientManager& LspClientManager::instance() {
    static LspClientManager manager;
    return manager;
}

bool LspClientManager::startServer(const std::string& languageId, const LspClient::ServerConfig& config) {
    std::lock_guard<std::mutex> lock(m_clientsMutex);

    auto it = m_clients.find(languageId);
    if (it != m_clients.end() && it->second->isConnected()) {
        return true; // Already running
    }

    auto client = std::make_shared<LspClient>();
    if (!client->initialize(config)) {
        return false;
    }

    m_clients[languageId] = client;
    return true;
}

void LspClientManager::stopServer(const std::string& languageId) {
    std::lock_guard<std::mutex> lock(m_clientsMutex);
    m_clients.erase(languageId);
}

void LspClientManager::stopAll() {
    std::lock_guard<std::mutex> lock(m_clientsMutex);
    m_clients.clear();
}

std::shared_ptr<LspClient> LspClientManager::getClient(const std::string& languageId) {
    std::lock_guard<std::mutex> lock(m_clientsMutex);
    auto it = m_clients.find(languageId);
    return (it != m_clients.end()) ? it->second : nullptr;
}

std::shared_ptr<LspClient> LspClientManager::getClientForFile(const std::string& filepath) {
    std::string lang = detectLanguage(filepath);
    return getClient(lang);
}

bool LspClientManager::autoStartForFile(const std::string& filepath, const std::string& rootPath) {
    std::string lang = detectLanguage(filepath);
    if (lang.empty()) return false;

    if (getClient(lang)) return true; // Already running

    LspClient::ServerConfig config;
    if (lang == "cpp" || lang == "c") {
        config = LspClient::createClangdConfig(rootPath);
    } else if (lang == "python") {
        config = LspClient::createPyrightConfig(rootPath);
    } else if (lang == "rust") {
        config = LspClient::createRustAnalyzerConfig(rootPath);
    } else {
        return false; // Unsupported language
    }

    return startServer(lang, config);
}

void LspClientManager::processAllMessages() {
    std::lock_guard<std::mutex> lock(m_clientsMutex);
    for (auto& [lang, client] : m_clients) {
        if (client) {
            client->processMessages();
        }
    }
}

std::string LspClientManager::detectLanguage(const std::string& filepath) {
    size_t dot = filepath.find_last_of('.');
    if (dot == std::string::npos) return "";

    std::string ext = filepath.substr(dot + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

    if (ext == "cpp" || ext == "cc" || ext == "cxx" || ext == "c++" || ext == "h" || ext == "hpp") return "cpp";
    if (ext == "c") return "c";
    if (ext == "py" || ext == "pyw") return "python";
    if (ext == "rs") return "rust";
    if (ext == "js" || ext == "jsx") return "javascript";
    if (ext == "ts" || ext == "tsx") return "typescript";
    if (ext == "go") return "go";
    if (ext == "java") return "java";

    return "";
}

} // namespace LSP
} // namespace RawrXD
