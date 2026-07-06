// ============================================================================
// minimal_dap_server.cpp — Minimal DAP Server for RawrXD-Script
// ============================================================================
// Standalone DAP implementation without debugger dependencies
// Provides basic protocol responses for VS Code integration
//
// Copyright (c) 2026 RawrXD Project — All rights reserved.
// ============================================================================

#define NOMINMAX
#include <nlohmann/json.hpp>

#include <iostream>
#include <string>
#include <string>
#include <vector>
#include <map>
#include <atomic>
#include <mutex>

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
// Minimal DAP Server
// ============================================================================
class MinimalDAPServer {
public:
    MinimalDAPServer() : m_seq(1), m_initialized(false), m_running(false) {}

    void Run() {
#ifdef _WIN32
        _setmode(_fileno(stdin), _O_BINARY);
        _setmode(_fileno(stdout), _O_BINARY);
#endif
        m_running = true;
        
        std::cerr << "RawrXD-Script DAP Server (minimal) started\n";
        
        std::string message;
        while (m_running && ReadMessage(message)) {
            ProcessMessage(message);
        }
    }

private:
    int m_seq;
    bool m_initialized;
    bool m_running;
    std::mutex m_mutex;
    
    struct Breakpoint {
        int id;
        std::string file;
        int line;
        bool verified;
    };
    std::vector<Breakpoint> m_breakpoints;
    int m_nextBreakpointId = 1;

    bool ReadMessage(std::string& outMessage) {
        std::string header;
        int contentLength = -1;
        
        while (std::getline(std::cin, header)) {
            if (!header.empty() && header.back() == '\r') {
                header.pop_back();
            }
            
            if (header.empty()) {
                break;
            }
            
            const std::string prefix = "Content-Length: ";
            if (header.rfind(prefix, 0) == 0) {
                try {
                    contentLength = std::stoi(header.substr(prefix.length()));
                } catch (...) {
                    return false;
                }
            }
        }
        
        if (contentLength <= 0) {
            return false;
        }
        
        outMessage.resize(contentLength);
        std::cin.read(&outMessage[0], contentLength);
        return std::cin.gcount() == contentLength;
    }

    void WriteMessage(const json& body) {
        std::lock_guard<std::mutex> lk(m_mutex);
        std::string jsonStr = body.dump();
        std::cout << "Content-Length: " << jsonStr.length() << "\r\n\r\n" << jsonStr;
        std::cout.flush();
    }

    void SendResponse(int requestSeq, const std::string& command, const json& body = json::object(), bool success = true) {
        json response;
        response["type"] = "response";
        response["request_seq"] = requestSeq;
        response["success"] = success;
        response["command"] = command;
        response["body"] = body;
        WriteMessage(response);
    }

    void SendEvent(const std::string& event, const json& body = json::object()) {
        json evt;
        evt["type"] = "event";
        evt["event"] = event;
        evt["body"] = body;
        WriteMessage(evt);
    }

    void ProcessMessage(const std::string& rawJson) {
        try {
            json msg = json::parse(rawJson);
            
            if (!msg.contains("type") || msg["type"].get<std::string>() != "request") {
                return;
            }
            
            std::string command = msg["command"];
            int seq = msg.value("seq", 0);
            json args = msg.value("arguments", json::object());
            
            HandleRequest(seq, command, args);
        } catch (const json::exception& e) {
            std::cerr << "Parse error: " << e.what() << "\n";
        }
    }

    void HandleRequest(int seq, const std::string& command, const json& args) {
        if (command == "initialize") {
            HandleInitialize(seq, args);
        } else if (command == "launch") {
            HandleLaunch(seq, args);
        } else if (command == "attach") {
            SendResponse(seq, "attach", json::object());
        } else if (command == "disconnect") {
            SendResponse(seq, "disconnect");
            m_running = false;
        } else if (command == "setBreakpoints") {
            HandleSetBreakpoints(seq, args);
        } else if (command == "continue") {
            json contBody;
            contBody["allThreadsContinued"] = true;
            SendResponse(seq, "continue", contBody);
            json evtBody;
            evtBody["threadId"] = 1;
            SendEvent("continued", evtBody);
        } else if (command == "next") {
            SendResponse(seq, "next");
            json stopBody;
            stopBody["reason"] = "step";
            stopBody["threadId"] = 1;
            SendEvent("stopped", stopBody);
        } else if (command == "stepIn") {
            SendResponse(seq, "stepIn");
            json stopBody;
            stopBody["reason"] = "step";
            stopBody["threadId"] = 1;
            SendEvent("stopped", stopBody);
        } else if (command == "stepOut") {
            SendResponse(seq, "stepOut");
            json stopBody;
            stopBody["reason"] = "step";
            stopBody["threadId"] = 1;
            SendEvent("stopped", stopBody);
        } else if (command == "pause") {
            SendResponse(seq, "pause");
            json stopBody;
            stopBody["reason"] = "pause";
            stopBody["threadId"] = 1;
            SendEvent("stopped", stopBody);
        } else if (command == "stackTrace") {
            HandleStackTrace(seq, args);
        } else if (command == "scopes") {
            HandleScopes(seq, args);
        } else if (command == "variables") {
            HandleVariables(seq, args);
        } else if (command == "evaluate") {
            SendResponse(seq, "evaluate", {{"result", "null"}, {"type", "null"}});
        } else if (command == "threads") {
            json threads = json::array();
            threads.push_back({{"id", 1}, {"name", "main"}});
            SendResponse(seq, "threads", {{"threads", threads}});
        } else {
            SendResponse(seq, command, json::object(), false);
        }
    }

    void HandleInitialize(int seq, const json& args) {
        json body;
        body["supportsConfigurationDoneRequest"] = true;
        body["supportsHitConditionalBreakpoints"] = false;
        body["supportsConditionalBreakpoints"] = false;
        body["supportsEvaluateForHovers"] = true;
        body["supportsStepBack"] = false;
        body["supportsSetVariable"] = false;
        body["supportsRestartRequest"] = false;
        body["supportsExceptionOptions"] = false;
        body["supportsValueFormattingOptions"] = true;
        body["supportsExceptionInfo"] = false;
        body["supportsDelayedStackTraceLoading"] = false;
        body["supportsLoadedSourcesRequest"] = false;
        body["supportsLogPoints"] = false;
        body["supportsTerminateThreadsRequest"] = false;
        body["supportsSetExpression"] = false;
        body["supportsTerminateRequest"] = true;
        body["supportsDataBreakpoints"] = false;
        body["supportsReadMemoryRequest"] = false;
        body["supportsWriteMemoryRequest"] = false;
        body["supportsDisassembleRequest"] = false;
        body["supportsCancelRequest"] = false;
        body["supportsBreakpointLocationsRequest"] = false;
        body["supportsClipboardContext"] = false;
        body["supportsSteppingGranularity"] = false;
        body["supportsInstructionBreakpoints"] = false;
        body["supportsExceptionFilterOptions"] = false;
        body["supportsSingleThreadExecutionRequests"] = false;
        
        SendResponse(seq, "initialize", body);
        
        // Send initialized event
        SendEvent("initialized");
        
        m_initialized = true;
    }

    void HandleLaunch(int seq, const json& args) {
        std::string program = args.value("program", "unknown");
        std::cerr << "Launching: " << program << "\n";
        
        SendResponse(seq, "launch");
        
        // Simulate stopped on entry
        if (args.value("stopOnEntry", false)) {
            SendEvent("stopped", {{"reason", "entry"}, {"threadId", 1}, {"description", "Paused on entry"}});
        }
    }

    void HandleSetBreakpoints(int seq, const json& args) {
        std::string sourcePath = args["source"].value("path", "");
        json breakpoints = json::array();
        
        if (args.contains("breakpoints")) {
            for (const auto& bp : args["breakpoints"]) {
                int line = bp.value("line", 0);
                
                Breakpoint breakpoint;
                breakpoint.id = m_nextBreakpointId++;
                breakpoint.file = sourcePath;
                breakpoint.line = line;
                breakpoint.verified = true;
                m_breakpoints.push_back(breakpoint);
                
                json bpJson;
                bpJson["id"] = breakpoint.id;
                bpJson["verified"] = true;
                bpJson["line"] = line;
                breakpoints.push_back(bpJson);
            }
        }
        
        SendResponse(seq, "setBreakpoints", {{"breakpoints", breakpoints}});
    }

    void HandleStackTrace(int seq, const json& args) {
        json frames = json::array();
        
        // Single dummy frame
        json frame;
        frame["id"] = 1;
        frame["name"] = "main";
        frame["line"] = 1;
        frame["column"] = 1;
        frames.push_back(frame);
        
        SendResponse(seq, "stackTrace", {{"stackFrames", frames}, {"totalFrames", 1}});
    }

    void HandleScopes(int seq, const json& args) {
        json scopes = json::array();
        
        json locals;
        locals["name"] = "Locals";
        locals["variablesReference"] = 1;
        locals["expensive"] = false;
        scopes.push_back(locals);
        
        json registers;
        registers["name"] = "Registers";
        registers["variablesReference"] = 2;
        registers["expensive"] = false;
        scopes.push_back(registers);
        
        SendResponse(seq, "scopes", {{"scopes", scopes}});
    }

    void HandleVariables(int seq, const json& args) {
        int ref = args.value("variablesReference", 0);
        json variables = json::array();
        
        if (ref == 2) {
            // Registers r0-r15
            for (int i = 0; i < 16; i++) {
                json var;
                var["name"] = "r" + std::to_string(i);
                var["value"] = "0x0000000000000000";
                var["type"] = "u64";
                var["variablesReference"] = 0;
                variables.push_back(var);
            }
        } else {
            // Empty locals
            json var;
            var["name"] = "(no locals)";
            var["value"] = "null";
            var["type"] = "null";
            var["variablesReference"] = 0;
            variables.push_back(var);
        }
        
        SendResponse(seq, "variables", {{"variables", variables}});
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
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--stdio") {
            useStdio = true;
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "RawrXD-Script DAP Server (minimal)\n";
            std::cout << "Usage: " << argv[0] << " [options]\n";
            std::cout << "Options:\n";
            std::cout << "  --stdio    Use stdin/stdout (default)\n";
            std::cout << "  --help, -h Show this help\n";
            return 0;
        }
    }
    
    MinimalDAPServer server;
    server.Run();
    
    return 0;
}
