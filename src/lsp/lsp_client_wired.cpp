// ============================================================================
// lsp_client_wired.cpp — Phase 22: LSP Diagnostics Wiring Harness Implementation
// ============================================================================
// Bridges RawrXD's internal LSP server to the IDE's ProblemsPanel.
// Handles JSON-RPC 2.0 protocol, process management, and diagnostic routing.
//
// Pattern: Thread-safe singleton, PatchResult-style error handling.
// Copyright (c) 2025-2026 RawrXD Project — All rights reserved.
// ============================================================================

#include "lsp/lsp_client_wired.hpp"
#include "core/problems_aggregator.hpp"

#include <sstream>
#include <fstream>
#include <iostream>
#include <chrono>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#endif

namespace rawrxd::lsp {

// ============================================================================
// Singleton Instance
// ============================================================================
LSPClientWired& LSPClientWired::instance() {
    static LSPClientWired instance;
    return instance;
}

LSPClientWired::~LSPClientWired() {
    shutdown();
}

// ============================================================================
// Phase 22: Server Lifecycle
// ============================================================================
bool LSPClientWired::initializeForProject(const std::string& project_root) {
    if (m_connected.load()) {
        return true;  // Already connected
    }
    
    m_projectRoot = project_root;
    
    // Start the LSP server process
    if (!startServerProcess(project_root)) {
        std::cerr << "[LSPClientWired] Failed to start LSP server" << std::endl;
        return false;
    }
    
    // Start reader thread
    m_shutdown = false;
    m_readerThread = std::thread(&LSPClientWired::readerThread, this);
    
    // Send initialize request
    json initParams = {
        {"processId", GetCurrentProcessId()},
        {"rootUri", "file:///" + project_root},
        {"capabilities", {
            {"textDocument", {
                {"synchronization", {{"dynamicRegistration", false}}},
                {"completion", {{"dynamicRegistration", false}}},
                {"hover", {{"dynamicRegistration", false}}},
                {"definition", {{"dynamicRegistration", false}}},
                {"diagnostic", {{"dynamicRegistration", false}}}
            }},
            {"workspace", {
                {"workspaceFolders", true},
                {"configuration", true}
            }}
        }}
    };
    
    json initRequest = {
        {"jsonrpc", "2.0"},
        {"id", 0},
        {"method", "initialize"},
        {"params", initParams}
    };
    
    if (!sendRequest(initRequest)) {
        std::cerr << "[LSPClientWired] Failed to send initialize request" << std::endl;
        shutdown();
        return false;
    }
    
    // Wait for initialize response
    json response = waitForResponse("0", 10000);
    if (response.is_null()) {
        std::cerr << "[LSPClientWired] Initialize timeout" << std::endl;
        shutdown();
        return false;
    }
    
    // Send initialized notification
    json initializedNotification = {
        {"jsonrpc", "2.0"},
        {"method", "initialized"},
        {"params", {}}
    };
    sendRequest(initializedNotification);
    
    m_connected = true;
    std::cout << "[LSPClientWired] Connected to LSP server for: " << project_root << std::endl;
    return true;
}

void LSPClientWired::shutdown() {
    if (!m_connected.load() && m_shutdown.load()) {
        return;
    }
    
    m_shutdown = true;
    m_connected = false;
    
    // Send shutdown request
    json shutdownRequest = {
        {"jsonrpc", "2.0"},
        {"id", 99999},
        {"method", "shutdown"}
    };
    sendRequest(shutdownRequest);
    
    // Wait for reader thread
    if (m_readerThread.joinable()) {
        m_readerThread.join();
    }
    
    // Stop server process
    stopServerProcess();
    
    std::cout << "[LSPClientWired] Shutdown complete" << std::endl;
}

// ============================================================================
// Phase 22: Process Management (Windows)
// ============================================================================
bool LSPClientWired::startServerProcess(const std::string& project_root) {
#ifdef _WIN32
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;
    
    // Create pipes for stdin/stdout
    HANDLE hStdinRead, hStdinWrite;
    HANDLE hStdoutRead, hStdoutWrite;
    
    if (!CreatePipe(&hStdinRead, &hStdinWrite, &sa, 0)) {
        return false;
    }
    if (!CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0)) {
        CloseHandle(hStdinRead);
        CloseHandle(hStdinWrite);
        return false;
    }
    
    // Ensure write end of stdin and read end of stdout are not inherited
    SetHandleInformation(hStdinWrite, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);
    
    // Prepare process
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = hStdinRead;
    si.hStdOutput = hStdoutWrite;
    si.hStdError = hStdoutWrite;  // Redirect stderr to stdout
    
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    
    // Build command line - use RawrXD's embedded LSP server
    std::string cmdLine = "RawrXD_LSPServer.exe --stdio";
    
    // Try to find server executable
    std::string serverPath = project_root + "/build/RawrXD_LSPServer.exe";
    if (!std::filesystem::exists(serverPath)) {
        serverPath = "RawrXD_LSPServer.exe";  // Try PATH
    }
    
    cmdLine = serverPath + " --stdio";
    
    char cmdLineBuffer[1024];
    strncpy(cmdLineBuffer, cmdLine.c_str(), sizeof(cmdLineBuffer) - 1);
    cmdLineBuffer[sizeof(cmdLineBuffer) - 1] = '\0';
    
    BOOL success = CreateProcessA(
        nullptr,           // Application name
        cmdLineBuffer,     // Command line
        nullptr,           // Process security attributes
        nullptr,           // Thread security attributes
        TRUE,              // Inherit handles
        CREATE_NO_WINDOW,  // Creation flags
        nullptr,           // Environment
        project_root.c_str(), // Current directory
        &si,
        &pi
    );
    
    // Close handles we don't need in parent
    CloseHandle(hStdinRead);
    CloseHandle(hStdoutWrite);
    
    if (!success) {
        CloseHandle(hStdinWrite);
        CloseHandle(hStdoutRead);
        return false;
    }
    
    // Store handles
    m_hServerProcess = pi.hProcess;
    CloseHandle(pi.hThread);  // We don't need the thread handle
    m_hStdinWrite = hStdinWrite;
    m_hStdoutRead = hStdoutRead;
    
    return true;
#else
    // Linux/Mac implementation would go here
    (void)project_root;
    return false;
#endif
}

void LSPClientWired::stopServerProcess() {
#ifdef _WIN32
    if (m_hServerProcess) {
        TerminateProcess(m_hServerProcess, 0);
        CloseHandle(m_hServerProcess);
        m_hServerProcess = nullptr;
    }
    if (m_hStdinWrite) {
        CloseHandle(m_hStdinWrite);
        m_hStdinWrite = nullptr;
    }
    if (m_hStdoutRead) {
        CloseHandle(m_hStdoutRead);
        m_hStdoutRead = nullptr;
    }
#endif
}

// ============================================================================
// Phase 22: Communication Thread
// ============================================================================
void LSPClientWired::readerThread() {
    std::string buffer;
    char readBuffer[4096];
    
    while (!m_shutdown.load()) {
#ifdef _WIN32
        DWORD bytesRead = 0;
        BOOL success = ReadFile(m_hStdoutRead, readBuffer, sizeof(readBuffer) - 1, &bytesRead, nullptr);
        
        if (!success || bytesRead == 0) {
            if (!m_shutdown.load()) {
                std::cerr << "[LSPClientWired] Server process disconnected" << std::endl;
            }
            break;
        }
        
        readBuffer[bytesRead] = '\0';
        buffer += readBuffer;
        
        // Parse JSON-RPC messages (Content-Length header format)
        while (true) {
            // Look for Content-Length header
            size_t headerEnd = buffer.find("\r\n\r\n");
            if (headerEnd == std::string::npos) {
                break;  // Need more data
            }
            
            // Parse Content-Length
            size_t contentLengthPos = buffer.find("Content-Length: ");
            if (contentLengthPos == std::string::npos || contentLengthPos > headerEnd) {
                // Invalid header, skip
                buffer = buffer.substr(headerEnd + 4);
                continue;
            }
            
            size_t lengthStart = contentLengthPos + 16;
            size_t lengthEnd = buffer.find("\r\n", lengthStart);
            if (lengthEnd == std::string::npos || lengthEnd > headerEnd) {
                break;  // Need more data
            }
            
            int contentLength = std::stoi(buffer.substr(lengthStart, lengthEnd - lengthStart));
            
            // Check if we have the full message body
            size_t messageStart = headerEnd + 4;
            if (buffer.size() < messageStart + contentLength) {
                break;  // Need more data
            }
            
            // Extract and parse JSON
            std::string jsonStr = buffer.substr(messageStart, contentLength);
            buffer = buffer.substr(messageStart + contentLength);
            
            try {
                json msg = json::parse(jsonStr);
                dispatchMessage(msg);
            } catch (const std::exception& e) {
                std::cerr << "[LSPClientWired] JSON parse error: " << e.what() << std::endl;
            }
        }
#else
        // Linux/Mac implementation
        break;
#endif
    }
}

void LSPClientWired::dispatchMessage(const json& msg) {
    // Check if this is a response with an ID
    if (msg.contains("id")) {
        std::string id = std::to_string(msg["id"].get<int>());
        std::lock_guard<std::mutex> lock(m_responseMutex);
        m_pendingResponses[id] = msg;
        return;
    }
    
    // Check if this is a notification
    if (msg.contains("method")) {
        std::string method = msg["method"];
        
        if (method == "textDocument/publishDiagnostics") {
            // Extract diagnostics
            auto params = msg["params"];
            std::string uri = params["uri"];
            std::string file_path = uri;
            
            // Remove file:// prefix
            if (file_path.substr(0, 8) == "file:///") {
                file_path = file_path.substr(8);
            }
            
            // Convert to ProblemEntry and send to aggregator
            if (params.contains("diagnostics")) {
                for (const auto& diag : params["diagnostics"]) {
                    RawrXD::ProblemEntry entry;
                    entry.path = file_path;
                    entry.line = diag["range"]["start"]["line"].get<int>() + 1;  // 0-based to 1-based
                    entry.column = diag["range"]["start"]["character"].get<int>() + 1;
                    entry.message = diag["message"];
                    entry.severity = diag["severity"].get<int>();  // 1=Error, 2=Warning, etc.
                    
                    if (diag.contains("code")) {
                        entry.code = diag["code"].is_string() 
                            ? diag["code"].get<std::string>() 
                            : std::to_string(diag["code"].get<int>());
                    }
                    
                    // Add to aggregator
                    RawrXD::ProblemsAggregator::instance().add(entry);
                }
            }
        }
    }
}

// ============================================================================
// Phase 22: JSON-RPC Helpers
// ============================================================================
bool LSPClientWired::sendRequest(const json& request) {
    std::string jsonStr = request.dump();
    std::string message = "Content-Length: " + std::to_string(jsonStr.size()) + "\r\n\r\n" + jsonStr;
    
#ifdef _WIN32
    if (!m_hStdinWrite) {
        return false;
    }
    
    DWORD bytesWritten = 0;
    BOOL success = WriteFile(m_hStdinWrite, message.c_str(), message.size(), &bytesWritten, nullptr);
    
    if (!success || bytesWritten != message.size()) {
        std::cerr << "[LSPClientWired] Failed to write to server" << std::endl;
        return false;
    }
    
    return true;
#else
    return false;
#endif
}

json LSPClientWired::waitForResponse(const std::string& id, int timeout_ms) {
    auto start = std::chrono::steady_clock::now();
    
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - start).count() < timeout_ms) {
        {
            std::lock_guard<std::mutex> lock(m_responseMutex);
            auto it = m_pendingResponses.find(id);
            if (it != m_pendingResponses.end()) {
                json response = it->second;
                m_pendingResponses.erase(it);
                return response;
            }
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    return nullptr;  // Timeout
}

// ============================================================================
// Phase 22: File Change Notifications
// ============================================================================
void LSPClientWired::notifyFileOpened(const std::string& file_path, 
                                        const std::string& language, 
                                        const std::string& content) {
    if (!m_connected.load()) return;
    
    json notification = {
        {"jsonrpc", "2.0"},
        {"method", "textDocument/didOpen"},
        {"params", {
            {"textDocument", {
                {"uri", "file:///" + file_path},
                {"languageId", language},
                {"version", 1},
                {"text", content}
            }}
        }}
    };
    
    sendRequest(notification);
}

void LSPClientWired::notifyFileChanged(const std::string& file_path, const std::string& content) {
    if (!m_connected.load()) return;
    
    static std::map<std::string, int> versions;
    int version = ++versions[file_path];
    
    json notification = {
        {"jsonrpc", "2.0"},
        {"method", "textDocument/didChange"},
        {"params", {
            {"textDocument", {
                {"uri", "file:///" + file_path},
                {"version", version}
            }},
            {"contentChanges", json::array({
                {{"text", content}}
            })}
        }}
    };
    
    sendRequest(notification);
}

void LSPClientWired::notifyFileClosed(const std::string& file_path) {
    if (!m_connected.load()) return;
    
    json notification = {
        {"jsonrpc", "2.0"},
        {"method", "textDocument/didClose"},
        {"params", {
            {"textDocument", {
                {"uri", "file:///" + file_path}
            }}
        }}
    };
    
    sendRequest(notification);
}

void LSPClientWired::notifyFileSaved(const std::string& file_path) {
    if (!m_connected.load()) return;
    
    json notification = {
        {"jsonrpc", "2.0"},
        {"method", "textDocument/didSave"},
        {"params", {
            {"textDocument", {
                {"uri", "file:///" + file_path}
            }}
        }}
    };
    
    sendRequest(notification);
}

// ============================================================================
// Phase 22: Diagnostics Pipeline (Server → UI)
// ============================================================================
void LSPClientWired::publishDiagnostics(const std::string& file_path,
                                       std::vector<Diagnostic> diagnostics) {
    // Convert and send to ProblemsAggregator
    for (const auto& diag : diagnostics) {
        RawrXD::ProblemEntry entry;
        entry.path = file_path;
        entry.line = diag.line;
        entry.column = diag.column;
        entry.message = diag.message;
        entry.severity = diag.severity;
        entry.code = diag.code;
        
        RawrXD::ProblemsAggregator::instance().addProblem(entry);
    }
}

// ============================================================================
// Phase 22: LSP Features (Client → Server)
// ============================================================================
std::string LSPClientWired::getHoverInfo(const std::string& file, 
                                         uint32_t line, 
                                         uint32_t character) {
    if (!m_connected.load()) {
        return "LSP not connected";
    }
    
    uint32_t id = ++m_requestId;
    json request = {
        {"jsonrpc", "2.0"},
        {"id", id},
        {"method", "textDocument/hover"},
        {"params", {
            {"textDocument", {{"uri", "file:///" + file}}},
            {"position", {{"line", line}, {"character", character}}}
        }}
    };
    
    if (!sendRequest(request)) {
        return "Failed to send request";
    }
    
    json response = waitForResponse(std::to_string(id), 5000);
    if (response.is_null() || response.contains("error")) {
        return "No hover info available";
    }
    
    if (response.contains("result") && response["result"].contains("contents")) {
        auto contents = response["result"]["contents"];
        if (contents.is_string()) {
            return contents.get<std::string>();
        } else if (contents.is_object() && contents.contains("value")) {
            return contents["value"].get<std::string>();
        }
    }
    
    return "No hover info available";
}

Location LSPClientWired::getDefinition(const std::string& file,
                                      uint32_t line,
                                      uint32_t character) {
    Location loc;
    loc.uri = "";
    loc.start.line = 0;
    loc.start.character = 0;
    loc.end.line = 0;
    loc.end.character = 0;
    
    if (!m_connected.load()) {
        return loc;
    }
    
    uint32_t id = ++m_requestId;
    json request = {
        {"jsonrpc", "2.0"},
        {"id", id},
        {"method", "textDocument/definition"},
        {"params", {
            {"textDocument", {{"uri", "file:///" + file}}},
            {"position", {{"line", line}, {"character", character}}}
        }}
    };
    
    if (!sendRequest(request)) {
        return loc;
    }
    
    json response = waitForResponse(std::to_string(id), 5000);
    if (response.is_null() || response.contains("error")) {
        return loc;
    }
    
    if (response.contains("result") && !response["result"].is_null()) {
        auto result = response["result"];
        if (result.is_array() && !result.empty()) {
            result = result[0];  // Take first result
        }
        
        if (result.is_object()) {
            loc.uri = result["uri"];
            loc.start.line = result["range"]["start"]["line"];
            loc.start.character = result["range"]["start"]["character"];
            loc.end.line = result["range"]["end"]["line"];
            loc.end.character = result["range"]["end"]["character"];
        }
    }
    
    return loc;
}

std::vector<CompletionItem> LSPClientWired::getCompletions(const std::string& file,
                                                          uint32_t line,
                                                          uint32_t character,
                                                          const std::string& prefix) {
    (void)prefix;  // Prefix not used in LSP protocol
    
    std::vector<CompletionItem> items;
    
    if (!m_connected.load()) {
        return items;
    }
    
    uint32_t id = ++m_requestId;
    json request = {
        {"jsonrpc", "2.0"},
        {"id", id},
        {"method", "textDocument/completion"},
        {"params", {
            {"textDocument", {{"uri", "file:///" + file}}},
            {"position", {{"line", line}, {"character", character}}}
        }}
    };
    
    if (!sendRequest(request)) {
        return items;
    }
    
    json response = waitForResponse(std::to_string(id), 5000);
    if (response.is_null() || response.contains("error")) {
        return items;
    }
    
    if (response.contains("result") && !response["result"].is_null()) {
        auto result = response["result"];
        if (result.is_array()) {
            for (const auto& item : result) {
                CompletionItem ci;
                ci.label = item["label"];
                if (item.contains("detail")) {
                    ci.detail = item["detail"];
                }
                if (item.contains("documentation")) {
                    if (item["documentation"].is_string()) {
                        ci.documentation = item["documentation"];
                    } else if (item["documentation"].is_object()) {
                        ci.documentation = item["documentation"]["value"];
                    }
                }
                items.push_back(ci);
            }
        } else if (result.is_object() && result.contains("items")) {
            for (const auto& item : result["items"]) {
                CompletionItem ci;
                ci.label = item["label"];
                if (item.contains("detail")) {
                    ci.detail = item["detail"];
                }
                if (item.contains("documentation")) {
                    if (item["documentation"].is_string()) {
                        ci.documentation = item["documentation"];
                    } else if (item["documentation"].is_object()) {
                        ci.documentation = item["documentation"]["value"];
                    }
                }
                items.push_back(ci);
            }
        }
    }
    
    return items;
}

WorkspaceEdit LSPClientWired::renameSymbol(const std::string& file,
                                            uint32_t line,
                                            uint32_t character,
                                            const std::string& new_name) {
    WorkspaceEdit edit;
    
    if (!m_connected.load()) {
        return edit;
    }
    
    uint32_t id = ++m_requestId;
    json request = {
        {"jsonrpc", "2.0"},
        {"id", id},
        {"method", "textDocument/rename"},
        {"params", {
            {"textDocument", {{"uri", "file:///" + file}}},
            {"position", {{"line", line}, {"character", character}}},
            {"newName", new_name}
        }}
    };
    
    if (!sendRequest(request)) {
        return edit;
    }
    
    json response = waitForResponse(std::to_string(id), 5000);
    if (response.is_null() || response.contains("error")) {
        return edit;
    }
    
    if (response.contains("result") && !response["result"].is_null()) {
        auto result = response["result"];
        if (result.contains("changes")) {
            for (auto& [uri, edits] : result["changes"].items()) {
                std::vector<TextEdit> textEdits;
                for (const auto& e : edits) {
                    TextEdit te;
                    te.range.start.uri = uri;
                    te.range.start.line = e["range"]["start"]["line"];
                    te.range.start.character = e["range"]["start"]["character"];
                    te.range.end.line = e["range"]["end"]["line"];
                    te.range.end.character = e["range"]["end"]["character"];
                    te.newText = e["newText"];
                    textEdits.push_back(te);
                }
                edit.changes[uri] = textEdits;
            }
        }
    }
    
    return edit;
}

} // namespace rawrxd::lsp
