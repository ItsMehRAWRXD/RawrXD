// RawrXDScriptDAPServer.cpp
// Standalone DAP server for RawrXD-Script
// Integrates with existing RawrXD IDE DAP infrastructure
// Build: cl /O2 /EHsc /std:c++20 /W4 /Fe:rxd-script-dap.exe RawrXDScriptDAPServer.cpp RawrXDScriptDAPAdapter.cpp

#include "RawrXDScriptDAPAdapter.hpp"
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>

// ============================================================================
// DAP Transport Layer (stdin/stdout)
// ============================================================================
class DAPTransport {
public:
    std::string ReadMessage() {
        char header[1024] = {};
        int pos = 0;
        int contentLen = -1;
        
        // Read headers
        while (true) {
            char c;
            if (fread(&c, 1, 1, stdin) != 1) return "";
            header[pos++] = c;
            if (pos >= 4 && memcmp(header + pos - 4, "\r\n\r\n", 4) == 0) break;
            if (pos >= 1023) break;
        }
        header[pos] = 0;
        
        // Parse Content-Length
        const char* cl = strstr(header, "Content-Length: ");
        if (cl) contentLen = atoi(cl + 16);
        if (contentLen <= 0) return "";
        
        std::string body;
        body.resize(contentLen);
        if (fread(&body[0], 1, contentLen, stdin) != (size_t)contentLen) return "";
        return body;
    }
    
    void WriteMessage(const std::string& body) {
        printf("Content-Length: %zu\r\n\r\n%s", body.size(), body.c_str());
        fflush(stdout);
    }
};

// ============================================================================
// Message Queue for Async Events
// ============================================================================
class MessageQueue {
public:
    void Push(const std::string& msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(msg);
    }
    
    bool Pop(std::string& msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty()) return false;
        msg = queue_.front();
        queue_.pop();
        return true;
    }
    
    bool Empty() {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }
    
private:
    std::queue<std::string> queue_;
    std::mutex mutex_;
};

// ============================================================================
// Request Parser
// ============================================================================
struct DAPRequest {
    int seq = 0;
    std::string type;      // "request" or other
    std::string command;
    std::string body;
    bool valid = false;
};

DAPRequest ParseRequest(const std::string& json) {
    DAPRequest req;
    req.body = json;
    
    // Parse seq
    const char* seqPos = strstr(json.c_str(), "\"seq\":");
    if (seqPos) req.seq = atoi(seqPos + 7);
    
    // Parse type
    const char* typePos = strstr(json.c_str(), "\"type\":\"");
    if (typePos) {
        typePos += 9;
        const char* end = strchr(typePos, '"');
        if (end) req.type = std::string(typePos, end - typePos);
    }
    
    // Parse command
    const char* cmdPos = strstr(json.c_str(), "\"command\":\"");
    if (cmdPos) {
        cmdPos += 12;
        const char* end = strchr(cmdPos, '"');
        if (end) req.command = std::string(cmdPos, end - cmdPos);
    }
    
    req.valid = !req.command.empty();
    return req;
}

// ============================================================================
// Main Server
// ============================================================================
int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);
    
    // Optional logging
    FILE* logFile = nullptr;
    if (argc > 1 && strcmp(argv[1], "--log") == 0) {
        fopen_s(&logFile, "rxd-script-dap.log", "w");
    }
    
    if (logFile) {
        fprintf(logFile, "RawrXD-Script DAP Server v1.0.0\n");
        fprintf(logFile, "JavaScript Engine Debugger - 10 Tiers Supported\n");
        fprintf(logFile, "==============================================\n\n");
        fflush(logFile);
    }
    
    DAPTransport transport;
    MessageQueue eventQueue;
    
    // Create adapter
    RawrXD::Script::Debugger::RawrXDScriptDAPAdapter adapter;
    
    // Set up event callback
    adapter.Initialize([&eventQueue](const std::string& eventType, const std::string& eventBody) {
        // Wrap event in DAP event envelope
        std::string event = "{\"type\":\"event\",\"event\":\"" + eventType + "\",\"body\":" + eventBody + "}";
        eventQueue.Push(event);
    });
    
    if (logFile) {
        fprintf(logFile, "Adapter initialized\n");
        fflush(logFile);
    }
    
    // Main loop
    bool running = true;
    int requestCount = 0;
    
    while (running) {
        // Check for events to send
        std::string event;
        while (eventQueue.Pop(event)) {
            transport.WriteMessage(event);
            if (logFile) {
                fprintf(logFile, "[EVENT] %s\n", event.c_str());
                fflush(logFile);
            }
        }
        
        // Read request (non-blocking would be better, but this works for now)
        std::string msg = transport.ReadMessage();
        if (msg.empty()) {
            Sleep(1);  // Prevent busy loop
            continue;
        }
        
        DAPRequest req = ParseRequest(msg);
        if (!req.valid) continue;
        
        requestCount++;
        if (logFile) {
            fprintf(logFile, "[REQ %d] %s: %s\n", requestCount, req.command.c_str(), msg.c_str());
            fflush(logFile);
        }
        
        // Dispatch command
        std::string response;
        
        if (req.command == "initialize") {
            response = adapter.HandleInitializeRequest(req.seq);
        }
        else if (req.command == "launch") {
            // Extract program from request
            const char* progPos = strstr(msg.c_str(), "\"program\":\"");
            std::string program;
            if (progPos) {
                progPos += 12;
                const char* end = strchr(progPos, '"');
                if (end) program = std::string(progPos, end - progPos);
            }
            response = adapter.HandleLaunchRequest(req.seq, program);
        }
        else if (req.command == "attach") {
            const char* pidPos = strstr(msg.c_str(), "\"processId\":");
            int pid = 0;
            if (pidPos) pid = atoi(pidPos + 13);
            response = adapter.HandleAttachRequest(req.seq, pid);
        }
        else if (req.command == "setBreakpoints") {
            // Extract file path
            const char* srcPos = strstr(msg.c_str(), "\"source\":{");
            std::string file;
            if (srcPos) {
                const char* pathPos = strstr(srcPos, "\"path\":\"");
                if (pathPos) {
                    pathPos += 9;
                    const char* end = strchr(pathPos, '"');
                    if (end) file = std::string(pathPos, end - pathPos);
                }
            }
            
            // Extract breakpoints
            std::vector<std::pair<uint32_t, uint32_t>> lines;
            const char* bpPos = strstr(msg.c_str(), "\"breakpoints\":[");
            if (bpPos) {
                bpPos += 16;
                while (true) {
                    const char* linePos = strstr(bpPos, "\"line\":");
                    if (!linePos) break;
                    uint32_t line = atoi(linePos + 8);
                    
                    uint32_t col = 0;
                    const char* colPos = strstr(linePos, "\"column\":");
                    if (colPos) col = atoi(colPos + 10);
                    
                    lines.push_back({line, col});
                    
                    bpPos = linePos + 8;
                    if (strstr(bpPos, "}") > strstr(bpPos, "{")) break;
                }
            }
            
            response = adapter.HandleSetBreakpointsRequest(req.seq, file, lines);
        }
        else if (req.command == "continue") {
            response = adapter.HandleContinueRequest(req.seq);
        }
        else if (req.command == "next") {
            response = adapter.HandleNextRequest(req.seq);
        }
        else if (req.command == "stepIn") {
            response = adapter.HandleStepInRequest(req.seq);
        }
        else if (req.command == "stepOut") {
            response = adapter.HandleStepOutRequest(req.seq);
        }
        else if (req.command == "pause") {
            response = adapter.HandlePauseRequest(req.seq);
        }
        else if (req.command == "stackTrace") {
            const char* threadPos = strstr(msg.c_str(), "\"threadId\":");
            uint32_t threadId = 1;
            if (threadPos) threadId = atoi(threadPos + 12);
            response = adapter.HandleStackTraceRequest(req.seq, threadId);
        }
        else if (req.command == "scopes") {
            const char* framePos = strstr(msg.c_str(), "\"frameId\":");
            uint32_t frameId = 0;
            if (framePos) frameId = atoi(framePos + 11);
            response = adapter.HandleScopesRequest(req.seq, frameId);
        }
        else if (req.command == "variables") {
            const char* refPos = strstr(msg.c_str(), "\"variablesReference\":");
            uint32_t ref = 0;
            if (refPos) ref = atoi(refPos + 23);
            response = adapter.HandleVariablesRequest(req.seq, ref);
        }
        else if (req.command == "evaluate") {
            const char* exprPos = strstr(msg.c_str(), "\"expression\":\"");
            std::string expr;
            if (exprPos) {
                exprPos += 16;
                const char* end = strchr(exprPos, '"');
                if (end) expr = std::string(exprPos, end - exprPos);
            }
            
            uint32_t frameId = 0;
            const char* framePos = strstr(msg.c_str(), "\"frameId\":");
            if (framePos) frameId = atoi(framePos + 11);
            
            response = adapter.HandleEvaluateRequest(req.seq, expr, frameId);
        }
        else if (req.command == "disconnect") {
            response = adapter.HandleDisconnectRequest(req.seq);
            running = false;
        }
        else if (req.command == "configurationDone") {
            // Simple acknowledgment
            response = "{\"type\":\"response\",\"request_seq\":" + std::to_string(req.seq) + 
                      ",\"success\":true,\"command\":\"configurationDone\"}";
        }
        else {
            // Unknown command - send error
            response = "{\"type\":\"response\",\"request_seq\":" + std::to_string(req.seq) + 
                      ",\"success\":false,\"command\":\"" + req.command + 
                      "\",\"message\":\"Unknown command\"}";
        }
        
        // Send response
        transport.WriteMessage(response);
        
        if (logFile) {
            fprintf(logFile, "[RESP] %s\n\n", response.c_str());
            fflush(logFile);
        }
    }
    
    if (logFile) {
        fprintf(logFile, "Server shutting down. Total requests: %d\n", requestCount);
        fclose(logFile);
    }
    
    return 0;
}
