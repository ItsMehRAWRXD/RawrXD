// ============================================================================
// RawrXD LSP (Language Server Protocol) Client
// ============================================================================
// Provides IDE features via LSP:
// - Code completion
// - Go to definition
// - Find references
// - Hover information
// - Diagnostics
// ============================================================================

#ifndef UNICODE
#define UNICODE
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <json/json.h>

#pragma comment(lib, "ws2_32.lib")

namespace RawrXD {
namespace LSP {

// LSP Message types
enum class MessageType {
    Request,
    Response,
    Notification
};

// LSP Message structure
struct LSPMessage {
    std::string jsonrpc = "2.0";
    int id = -1;
    std::string method;
    Json::Value params;
    Json::Value result;
    Json::Value error;
    MessageType type;
};

// Completion item
struct CompletionItem {
    std::string label;
    std::string detail;
    std::string documentation;
    std::string kind;
    std::string insertText;
};

// Location for go-to-definition
struct Location {
    std::string uri;
    int line;
    int character;
};

// Diagnostic
struct Diagnostic {
    std::string message;
    std::string severity; // error, warning, info, hint
    int line;
    int startChar;
    int endChar;
    std::string source;
};

// Symbol information
struct SymbolInfo {
    std::string name;
    std::string kind;
    Location location;
    std::string containerName;
};

class LSPClient {
public:
    HANDLE m_hProcess = nullptr;
    HANDLE m_hStdinWrite = nullptr;
    HANDLE m_hStdoutRead = nullptr;
    std::thread m_readThread;
    std::thread m_writeThread;
    std::atomic<bool> m_running{false};
    std::atomic<int> m_nextId{1};
    
    std::queue<LSPMessage> m_outgoingQueue;
    std::mutex m_queueMutex;
    std::condition_variable m_queueCV;
    
    std::map<int, std::function<void(const Json::Value&)>> m_pendingRequests;
    std::mutex m_requestsMutex;
    
    // Callbacks
    std::function<void(const std::vector<CompletionItem>&)> m_onCompletion;
    std::function<void(const std::vector<Location>&)> m_onDefinition;
    std::function<void(const std::vector<Diagnostic>&)> m_onDiagnostics;
    std::function<void(const std::string&)> m_onHover;
    std::function<void(const std::vector<SymbolInfo>&)> m_onSymbols;
    
    bool Initialize(const std::wstring& languageServerPath, const std::vector<std::wstring>& args) {
        SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
        
        // Create pipes for stdin/stdout
        HANDLE hStdinRead, hStdoutWrite;
        
        if (!CreatePipe(&hStdinRead, &m_hStdinWrite, &sa, 0)) return false;
        if (!CreatePipe(&m_hStdoutRead, &hStdoutWrite, &sa, 0)) {
            CloseHandle(hStdinRead);
            CloseHandle(m_hStdinWrite);
            return false;
        }
        
        // Set up process
        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = hStdinRead;
        si.hStdOutput = hStdoutWrite;
        si.hStdError = hStdoutWrite;
        
        PROCESS_INFORMATION pi = {};
        
        std::wstring cmdLine = L"\"" + languageServerPath + L"\"";
        for (const auto& arg : args) {
            cmdLine += L" " + arg;
        }
        
        if (!CreateProcessW(nullptr, &cmdLine[0], nullptr, nullptr, TRUE,
                           CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            CloseHandle(hStdinRead);
            CloseHandle(m_hStdinWrite);
            CloseHandle(m_hStdoutRead);
            CloseHandle(hStdoutWrite);
            return false;
        }
        
        m_hProcess = pi.hProcess;
        CloseHandle(pi.hThread);
        CloseHandle(hStdinRead);
        CloseHandle(hStdoutWrite);
        
        m_running = true;
        
        // Start threads
        m_readThread = std::thread(&LSPClient::ReadLoop, this);
        m_writeThread = std::thread(&LSPClient::WriteLoop, this);
        
        // Send initialize request
        SendInitialize();
        
        return true;
    }
    
    void Shutdown() {
        m_running = false;
        
        // Send shutdown request
        SendRequest("shutdown", Json::Value(), nullptr);
        
        // Notify exit
        SendNotification("exit", Json::Value());
        
        // Wait for threads
        m_queueCV.notify_all();
        if (m_readThread.joinable()) m_readThread.join();
        if (m_writeThread.joinable()) m_writeThread.join();
        
        // Cleanup handles
        if (m_hStdinWrite) CloseHandle(m_hStdinWrite);
        if (m_hStdoutRead) CloseHandle(m_hStdoutRead);
        if (m_hProcess) {
            TerminateProcess(m_hProcess, 0);
            CloseHandle(m_hProcess);
        }
    }
    
    void SendInitialize() {
        Json::Value params;
        params["processId"] = GetCurrentProcessId();
        
        Json::Value capabilities;
        capabilities["textDocument"]["synchronization"]["dynamicRegistration"] = false;
        capabilities["textDocument"]["completion"]["dynamicRegistration"] = false;
        capabilities["textDocument"]["hover"]["dynamicRegistration"] = false;
        capabilities["textDocument"]["definition"]["dynamicRegistration"] = false;
        capabilities["textDocument"]["documentSymbol"]["dynamicRegistration"] = false;
        capabilities["textDocument"]["codeAction"]["dynamicRegistration"] = false;
        capabilities["textDocument"]["formatting"]["dynamicRegistration"] = false;
        capabilities["textDocument"]["rename"]["dynamicRegistration"] = false;
        capabilities["workspace"]["applyEdit"] = true;
        
        params["capabilities"] = capabilities;
        
        SendRequest("initialize", params, [this](const Json::Value& result) {
            // Server initialized
            SendNotification("initialized", Json::Value());
        });
    }
    
    void SendRequest(const std::string& method, const Json::Value& params,
                     std::function<void(const Json::Value&)> callback) {
        LSPMessage msg;
        msg.type = MessageType::Request;
        msg.id = m_nextId++;
        msg.method = method;
        msg.params = params;
        
        {
            std::lock_guard<std::mutex> lock(m_requestsMutex);
            m_pendingRequests[msg.id] = callback;
        }
        
        QueueMessage(msg);
    }
    
    void SendNotification(const std::string& method, const Json::Value& params) {
        LSPMessage msg;
        msg.type = MessageType::Notification;
        msg.method = method;
        msg.params = params;
        QueueMessage(msg);
    }
    
    void QueueMessage(const LSPMessage& msg) {
        {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            m_outgoingQueue.push(msg);
        }
        m_queueCV.notify_one();
    }
    
    void WriteLoop() {
        while (m_running) {
            std::unique_lock<std::mutex> lock(m_queueMutex);
            m_queueCV.wait(lock, [this] { return !m_outgoingQueue.empty() || !m_running; });
            
            if (!m_running) break;
            
            LSPMessage msg = m_outgoingQueue.front();
            m_outgoingQueue.pop();
            lock.unlock();
            
            SendMessageToServer(msg);
        }
    }
    
    void SendMessageToServer(const LSPMessage& msg) {
        Json::Value root;
        root["jsonrpc"] = msg.jsonrpc;
        
        if (msg.type == MessageType::Request) {
            root["id"] = msg.id;
            root["method"] = msg.method;
            root["params"] = msg.params;
        } else if (msg.type == MessageType::Notification) {
            root["method"] = msg.method;
            root["params"] = msg.params;
        }
        
        Json::StreamWriterBuilder builder;
        std::string jsonStr = Json::writeString(builder, root);
        
        // LSP header
        std::string header = "Content-Length: " + std::to_string(jsonStr.length()) + "\r\n\r\n";
        std::string fullMessage = header + jsonStr;
        
        DWORD written;
        WriteFile(m_hStdinWrite, fullMessage.c_str(), fullMessage.length(), &written, nullptr);
    }
    
    void ReadLoop() {
        std::string buffer;
        char readBuffer[4096];
        DWORD bytesRead;
        
        while (m_running) {
            if (!ReadFile(m_hStdoutRead, readBuffer, sizeof(readBuffer) - 1, &bytesRead, nullptr)) {
                break;
            }
            
            readBuffer[bytesRead] = '\0';
            buffer += readBuffer;
            
            // Parse messages
            while (true) {
                // Find Content-Length header
                size_t headerEnd = buffer.find("\r\n\r\n");
                if (headerEnd == std::string::npos) break;
                
                // Parse Content-Length
                size_t clPos = buffer.find("Content-Length: ");
                if (clPos == std::string::npos) break;
                
                size_t clEnd = buffer.find("\r\n", clPos);
                int contentLength = std::stoi(buffer.substr(clPos + 16, clEnd - clPos - 16));
                
                // Check if we have full message
                size_t messageStart = headerEnd + 4;
                if (buffer.length() < messageStart + contentLength) break;
                
                // Parse JSON
                std::string jsonStr = buffer.substr(messageStart, contentLength);
                buffer.erase(0, messageStart + contentLength);
                
                ParseMessage(jsonStr);
            }
        }
    }
    
    void ParseMessage(const std::string& jsonStr) {
        Json::Value root;
        Json::CharReaderBuilder builder;
        std::string errors;
        
        std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
        if (!reader->parse(jsonStr.c_str(), jsonStr.c_str() + jsonStr.length(), &root, &errors)) {
            return;
        }
        
        // Check if response or notification
        if (root.isMember("id")) {
            // Response
            int id = root["id"].asInt();
            
            std::lock_guard<std::mutex> lock(m_requestsMutex);
            auto it = m_pendingRequests.find(id);
            if (it != m_pendingRequests.end()) {
                if (it->second) {
                    it->second(root["result"]);
                }
                m_pendingRequests.erase(it);
            }
        } else if (root.isMember("method")) {
            // Notification
            std::string method = root["method"].asString();
            HandleNotification(method, root["params"]);
        }
    }
    
    void HandleNotification(const std::string& method, const Json::Value& params) {
        if (method == "textDocument/publishDiagnostics") {
            HandleDiagnostics(params);
        }
    }
    
    void HandleDiagnostics(const Json::Value& params) {
        std::vector<Diagnostic> diagnostics;
        
        const Json::Value& items = params["diagnostics"];
        for (const auto& item : items) {
            Diagnostic diag;
            diag.message = item["message"].asString();
            diag.line = item["range"]["start"]["line"].asInt();
            diag.startChar = item["range"]["start"]["character"].asInt();
            diag.endChar = item["range"]["end"]["character"].asInt();
            diag.severity = item["severity"].asInt() == 1 ? "error" :
                           item["severity"].asInt() == 2 ? "warning" :
                           item["severity"].asInt() == 3 ? "info" : "hint";
            diagnostics.push_back(diag);
        }
        
        if (m_onDiagnostics) {
            m_onDiagnostics(diagnostics);
        }
    }
    
    // Public API for IDE features
    void TextDocumentDidOpen(const std::string& uri, const std::string& languageId, const std::string& text) {
        Json::Value params;
        params["textDocument"]["uri"] = uri;
        params["textDocument"]["languageId"] = languageId;
        params["textDocument"]["version"] = 1;
        params["textDocument"]["text"] = text;
        SendNotification("textDocument/didOpen", params);
    }
    
    void TextDocumentDidChange(const std::string& uri, int version, const std::string& text) {
        Json::Value params;
        params["textDocument"]["uri"] = uri;
        params["textDocument"]["version"] = version;
        
        Json::Value change;
        change["text"] = text;
        params["contentChanges"].append(change);
        
        SendNotification("textDocument/didChange", params);
    }
    
    void RequestCompletion(const std::string& uri, int line, int character) {
        Json::Value params;
        params["textDocument"]["uri"] = uri;
        params["position"]["line"] = line;
        params["position"]["character"] = character;
        
        SendRequest("textDocument/completion", params, [this](const Json::Value& result) {
            std::vector<CompletionItem> items;
            
            const Json::Value& completions = result.isArray() ? result : result["items"];
            for (const auto& item : completions) {
                CompletionItem ci;
                ci.label = item["label"].asString();
                ci.detail = item["detail"].asString();
                ci.documentation = item["documentation"].asString();
                ci.kind = item["kind"].asString();
                ci.insertText = item["insertText"].asString();
                items.push_back(ci);
            }
            
            if (m_onCompletion) m_onCompletion(items);
        });
    }
    
    void RequestDefinition(const std::string& uri, int line, int character) {
        Json::Value params;
        params["textDocument"]["uri"] = uri;
        params["position"]["line"] = line;
        params["position"]["character"] = character;
        
        SendRequest("textDocument/definition", params, [this](const Json::Value& result) {
            std::vector<Location> locations;
            
            if (result.isArray()) {
                for (const auto& loc : result) {
                    Location l;
                    l.uri = loc["uri"].asString();
                    l.line = loc["range"]["start"]["line"].asInt();
                    l.character = loc["range"]["start"]["character"].asInt();
                    locations.push_back(l);
                }
            } else if (result.isObject()) {
                Location l;
                l.uri = result["uri"].asString();
                l.line = result["range"]["start"]["line"].asInt();
                l.character = result["range"]["start"]["character"].asInt();
                locations.push_back(l);
            }
            
            if (m_onDefinition) m_onDefinition(locations);
        });
    }
    
    void RequestHover(const std::string& uri, int line, int character) {
        Json::Value params;
        params["textDocument"]["uri"] = uri;
        params["position"]["line"] = line;
        params["position"]["character"] = character;
        
        SendRequest("textDocument/hover", params, [this](const Json::Value& result) {
            std::string contents = result["contents"]["value"].asString();
            if (m_onHover) m_onHover(contents);
        });
    }
    
    void RequestDocumentSymbols(const std::string& uri) {
        Json::Value params;
        params["textDocument"]["uri"] = uri;
        
        SendRequest("textDocument/documentSymbol", params, [this](const Json::Value& result) {
            std::vector<SymbolInfo> symbols;
            
            for (const auto& sym : result) {
                SymbolInfo si;
                si.name = sym["name"].asString();
                si.kind = sym["kind"].asString();
                si.location.uri = sym["location"]["uri"].asString();
                si.location.line = sym["location"]["range"]["start"]["line"].asInt();
                si.location.character = sym["location"]["range"]["start"]["character"].asInt();
                si.containerName = sym["containerName"].asString();
                symbols.push_back(si);
            }
            
            if (m_onSymbols) m_onSymbols(symbols);
        });
    }
};

} // namespace LSP
} // namespace RawrXD
