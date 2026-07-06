// ============================================================================
// main_dap_server.cpp — RawrXD-Script DAP Server Entry Point
// ============================================================================
// Standalone DAP server for RawrXD-Script debugging
// Communicates via stdin/stdout using JSON-RPC 2.0
//
// Usage: rxd-script-dap.exe [--port=port] [--stdio]
//   --stdio    : Use stdin/stdout (default, for VS Code)
//   --port=N   : Use TCP port N (for remote debugging)
//
// Copyright (c) 2026 RawrXD Project — All rights reserved.
// ============================================================================

#include "rawrxd_script_dap_adapter.hpp"
#include <nlohmann/json.hpp>

#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#endif

using json = nlohmann::json;

namespace RawrXD {
namespace Script {
namespace Debug {

// ============================================================================
// DAP Server
// ============================================================================

class DAPServer {
public:
    DAPServer() : m_adapter(std::make_unique<RawrXDScriptDAPAdapter>()) {}
    
    bool Initialize() {
        // Initialize with null interpreter (will be set on launch)
        return m_adapter->Initialize(nullptr);
    }
    
    void RunStdio() {
        #ifdef _WIN32
        // Set binary mode for stdin/stdout
        _setmode(_fileno(stdin), _O_BINARY);
        _setmode(_fileno(stdout), _O_BINARY);
        #endif
        
        std::cerr << "RawrXD-Script DAP Server started (stdio mode)\n";
        std::cerr << "Waiting for initialize request...\n";
        
        std::string message;
        while (ReadMessage(message)) {
            ProcessMessage(message);
        }
    }
    
    void Shutdown() {
        m_running = false;
        m_adapter->Shutdown();
    }

private:
    std::unique_ptr<RawrXDScriptDAPAdapter> m_adapter;
    std::atomic<bool> m_running{true};
    int m_seq = 0;
    
    bool ReadMessage(std::string& outMessage) {
        // Read Content-Length header
        std::string header;
        int contentLength = -1;
        
        while (std::getline(std::cin, header)) {
            // Remove trailing \r if present
            if (!header.empty() && header.back() == '\r') {
                header.pop_back();
            }
            
            if (header.empty()) {
                break; // End of headers
            }
            
            // Parse Content-Length
            const std::string prefix = "Content-Length: ";
            if (header.rfind(prefix, 0) == 0) {
                try {
                    contentLength = std::stoi(header.substr(prefix.length()));
                } catch (...) {
                    std::cerr << "Invalid Content-Length\n";
                    return false;
                }
            }
        }
        
        if (contentLength <= 0) {
            return false;
        }
        
        // Read exactly contentLength bytes
        outMessage.resize(contentLength);
        std::cin.read(&outMessage[0], contentLength);
        
        return std::cin.gcount() == contentLength;
    }
    
    void WriteMessage(const json& body) {
        std::string jsonStr = body.dump();
        std::string header = "Content-Length: " + std::to_string(jsonStr.length()) + "\r\n\r\n";
        
        std::cout << header << jsonStr;
        std::cout.flush();
    }
    
    void ProcessMessage(const std::string& rawJson) {
        try {
            json msg = json::parse(rawJson);
            
            if (!msg.contains("type")) {
                SendError(0, -32600, "Invalid Request: missing 'type'");
                return;
            }
            
            std::string type = msg["type"];
            
            if (type == "request") {
                HandleRequest(msg);
            } else if (type == "response") {
                // We don't send requests yet, so ignore responses
            }
        } catch (const json::exception& e) {
            SendError(0, -32700, std::string("Parse error: ") + e.what());
        }
    }
    
    void HandleRequest(const json& msg) {
        if (!msg.contains("command")) {
            SendError(msg.value("seq", 0), -32600, "Invalid Request: missing 'command'");
            return;
        }
        
        std::string command = msg["command"];
        int seq = msg.value("seq", 0);
        json args = msg.value("arguments", json::object());
        
        json response;
        
        if (command == "initialize") {
            response = m_adapter->OnInitialize(msg);
        } else if (command == "launch") {
            response = m_adapter->OnLaunch(msg);
        } else if (command == "attach") {
            response = m_adapter->OnAttach(msg);
        } else if (command == "disconnect") {
            response = m_adapter->OnDisconnect(msg);
        } else if (command == "setBreakpoints") {
            response = m_adapter->OnSetBreakpoints(msg);
        } else if (command == "continue") {
            response = m_adapter->OnContinue(msg);
        } else if (command == "next") {
            response = m_adapter->OnNext(msg);
        } else if (command == "stepIn") {
            response = m_adapter->OnStepIn(msg);
        } else if (command == "stepOut") {
            response = m_adapter->OnStepOut(msg);
        } else if (command == "pause") {
            response = m_adapter->OnPause(msg);
        } else if (command == "stackTrace") {
            response = m_adapter->OnStackTrace(msg);
        } else if (command == "scopes") {
            response = m_adapter->OnScopes(msg);
        } else if (command == "variables") {
            response = m_adapter->OnVariables(msg);
        } else if (command == "evaluate") {
            response = m_adapter->OnEvaluate(msg);
        } else {
            SendError(seq, -32601, "Method not found: " + command);
            return;
        }
        
        WriteMessage(response);
    }
    
    void SendError(int seq, int code, const std::string& message) {
        json error;
        error["type"] = "response";
        error["request_seq"] = seq;
        error["success"] = false;
        error["message"] = message;
        error["body"]["error"]["id"] = code;
        error["body"]["error"]["format"] = message;
        
        WriteMessage(error);
    }
};

} // namespace Debug
} // namespace Script
} // namespace RawrXD

// ============================================================================
// Main Entry Point
// ============================================================================

int main(int argc, char* argv[]) {
    using namespace RawrXD::Script::Debug;
    
    bool useStdio = true;
    int port = 0;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--stdio") {
            useStdio = true;
        } else if (arg.rfind("--port=", 0) == 0) {
            port = std::stoi(arg.substr(7));
            useStdio = false;
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "RawrXD-Script DAP Server\n";
            std::cout << "Usage: " << argv[0] << " [options]\n";
            std::cout << "Options:\n";
            std::cout << "  --stdio          Use stdin/stdout (default)\n";
            std::cout << "  --port=N         Use TCP port N\n";
            std::cout << "  --help, -h       Show this help\n";
            return 0;
        }
    }
    
    DAPServer server;
    
    if (!server.Initialize()) {
        std::cerr << "Failed to initialize DAP server\n";
        return 1;
    }
    
    if (useStdio) {
        server.RunStdio();
    }
    
    server.Shutdown();
    return 0;
}
