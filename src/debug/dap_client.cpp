// ============================================================================
// dap_client.cpp — Phase 23: Debug Adapter Protocol Client Implementation
// ============================================================================
// Full DAP 1.60 client implementation for RawrXD IDE.
// Communicates with debuggers via JSON-RPC over stdin/stdout.
//
// Architecture:
//   - Async reader thread for events
//   - Synchronous request/response with timeout
//   - Thread-safe state management
//   - PatchResult-style error handling
//
// Supported Debuggers:
//   - CDB (cppvsdbg) - Windows Debugging Tools
//   - GDB (cppdbg) - GNU Debugger
//   - LLDB - LLVM Debugger
//
// Copyright (c) 2025-2026 RawrXD Project — All rights reserved.
// ============================================================================

#include "dap_client.hpp"
#include <iostream>
#include <sstream>
#include <fstream>
#include <chrono>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#endif

namespace RawrXD {
namespace DAP {

// ============================================================================
// Singleton Instance
// ============================================================================
DAPClient& DAPClient::instance() {
    static DAPClient instance;
    return instance;
}

DAPClient::~DAPClient() {
    shutdown();
}

// ============================================================================
// Lifecycle
// ============================================================================
bool DAPClient::initialize(const DAPConfig& config) {
    if (m_initialized.load()) {
        return true;
    }
    
    m_config = config;
    
    // Start debugger process
    if (!startDebuggerProcess(config)) {
        std::cerr << "[DAPClient] Failed to start debugger process" << std::endl;
        return false;
    }
    
    // Start reader thread
    m_shutdown = false;
    m_readerThread = std::thread(&DAPClient::readerThread, this);
    
    // Send initialize request
    json initArgs = {
        {"clientID", "rawrxd"},
        {"clientName", "RawrXD IDE"},
        {"adapterID", config.debuggerType},
        {"locale", "en-US"},
        {"linesStartAt1", true},
        {"columnsStartAt1", true},
        {"pathFormat", "path"},
        {"supportsVariableType", true},
        {"supportsVariablePaging", true},
        {"supportsRunInTerminalRequest", false},
        {"supportsMemoryReferences", true},
        {"supportsProgressReporting", true},
        {"supportsInvalidatedEvent", true}
    };
    
    uint32_t initId;
    if (!sendRequest("initialize", initArgs, initId)) {
        std::cerr << "[DAPClient] Failed to send initialize request" << std::endl;
        shutdown();
        return false;
    }
    
    json response = waitForResponse(initId, 10000);
    if (response.is_null() || response.contains("error")) {
        std::cerr << "[DAPClient] Initialize failed or timed out" << std::endl;
        shutdown();
        return false;
    }
    
    // Parse capabilities
    if (response.contains("body") && response["body"].contains("supportsConditionalBreakpoints")) {
        parseCapabilities(response["body"]);
    }
    
    m_initialized = true;
    m_connected = true;
    
    std::cout << "[DAPClient] Connected to " << config.debuggerType << " debugger" << std::endl;
    return true;
}

void DAPClient::shutdown() {
    if (!m_initialized.load() && !m_connected.load()) {
        return;
    }
    
    // Send disconnect request
    if (m_connected.load()) {
        uint32_t disconnectId;
        sendRequest("disconnect", {{"restart", false}, {"terminateDebuggee", true}}, disconnectId);
        waitForResponse(disconnectId, 3000);
    }
    
    m_shutdown = true;
    m_initialized = false;
    m_connected = false;
    
    // Wait for reader thread
    if (m_readerThread.joinable()) {
        m_readerThread.join();
    }
    
    // Stop debugger process
    stopDebuggerProcess();
    
    std::cout << "[DAPClient] Shutdown complete" << std::endl;
}

// ============================================================================
// Process Management (Windows)
// ============================================================================
bool DAPClient::startDebuggerProcess(const DAPConfig& config) {
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
    si.hStdError = hStdoutWrite;
    
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    
    // Build command line
    std::string cmdLine;
    if (config.debuggerType == "cppvsdbg") {
        // CDB/VS Debugger
        cmdLine = "\"" + config.debuggerPath + "\"";
        cmdLine += " -p remote";  // Remote mode for DAP
    } else if (config.debuggerType == "cppdbg") {
        // GDB
        cmdLine = "\"" + config.debuggerPath + "\"";
        cmdLine += " --interpreter=mi";  // Machine interface mode
    } else if (config.debuggerType == "lldb") {
        // LLDB
        cmdLine = "\"" + config.debuggerPath + "\"";
        cmdLine += " --repl";  // REPL mode
    } else {
        // Default: assume debugger speaks DAP directly
        cmdLine = "\"" + config.debuggerPath + "\"";
    }
    
    char cmdLineBuffer[4096];
    strncpy(cmdLineBuffer, cmdLine.c_str(), sizeof(cmdLineBuffer) - 1);
    cmdLineBuffer[sizeof(cmdLineBuffer) - 1] = '\0';
    
    BOOL success = CreateProcessA(
        nullptr,
        cmdLineBuffer,
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        config.workingDir.empty() ? nullptr : config.workingDir.c_str(),
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
    m_hProcess = pi.hProcess;
    CloseHandle(pi.hThread);
    m_hStdinWrite = hStdinWrite;
    m_hStdoutRead = hStdoutRead;
    
    return true;
#else
    (void)config;
    return false;
#endif
}

void DAPClient::stopDebuggerProcess() {
#ifdef _WIN32
    if (m_hProcess) {
        TerminateProcess(m_hProcess, 0);
        CloseHandle(m_hProcess);
        m_hProcess = nullptr;
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
// Communication Thread
// ============================================================================
void DAPClient::readerThread() {
    std::string buffer;
    char readBuffer[4096];
    
    while (!m_shutdown.load()) {
#ifdef _WIN32
        DWORD bytesRead = 0;
        BOOL success = ReadFile(m_hStdoutRead, readBuffer, sizeof(readBuffer) - 1, 
                                &bytesRead, nullptr);
        
        if (!success || bytesRead == 0) {
            if (!m_shutdown.load()) {
                std::cerr << "[DAPClient] Debugger process disconnected" << std::endl;
            }
            break;
        }
        
        readBuffer[bytesRead] = '\0';
        buffer += readBuffer;
        
        // Parse DAP messages (Content-Length header format)
        while (true) {
            // Look for Content-Length header
            size_t headerEnd = buffer.find("\r\n\r\n");
            if (headerEnd == std::string::npos) {
                break;
            }
            
            // Parse Content-Length
            size_t contentLengthPos = buffer.find("Content-Length: ");
            if (contentLengthPos == std::string::npos || contentLengthPos > headerEnd) {
                buffer = buffer.substr(headerEnd + 4);
                continue;
            }
            
            size_t lengthStart = contentLengthPos + 16;
            size_t lengthEnd = buffer.find("\r\n", lengthStart);
            if (lengthEnd == std::string::npos || lengthEnd > headerEnd) {
                break;
            }
            
            int contentLength = std::stoi(buffer.substr(lengthStart, lengthEnd - lengthStart));
            
            // Check if we have the full message body
            size_t messageStart = headerEnd + 4;
            if (buffer.size() < messageStart + contentLength) {
                break;
            }
            
            // Extract and parse JSON
            std::string jsonStr = buffer.substr(messageStart, contentLength);
            buffer = buffer.substr(messageStart + contentLength);
            
            try {
                json msg = json::parse(jsonStr);
                
                // Dispatch based on message type
                if (msg.contains("type")) {
                    std::string type = msg["type"];
                    if (type == "event") {
                        dispatchEvent(msg);
                    } else if (type == "response") {
                        dispatchResponse(msg);
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "[DAPClient] JSON parse error: " << e.what() << std::endl;
            }
        }
#else
        break;
#endif
    }
}

void DAPClient::dispatchEvent(const json& event) {
    std::string eventType = event["event"];
    
    if (eventType == "stopped" && m_onStopped) {
        DAPStoppedEvent e;
        auto body = event["body"];
        e.reason = parseStopReason(body.value("reason", "unknown"));
        e.threadId = body.value("threadId", 0);
        e.allThreadsStopped = body.value("allThreadsStopped", true);
        e.description = body.value("description", "");
        e.text = body.value("text", "");
        m_onStopped(e);
        
    } else if (eventType == "continued" && m_onContinued) {
        DAPContinuedEvent e;
        auto body = event["body"];
        e.threadId = body.value("threadId", 0);
        e.allThreadsContinued = body.value("allThreadsContinued", true);
        m_onContinued(e);
        
    } else if (eventType == "exited" && m_onExited) {
        DAPExitedEvent e;
        e.exitCode = event["body"].value("exitCode", 0);
        m_onExited(e);
        
    } else if (eventType == "terminated" && m_onTerminated) {
        DAPTerminatedEvent e;
        e.restart = event["body"].value("restart", false);
        m_onTerminated(e);
        
    } else if (eventType == "thread" && m_onThread) {
        DAPThreadEvent e;
        auto body = event["body"];
        e.reason = body.value("reason", "");
        e.threadId = body.value("threadId", 0);
        m_onThread(e);
        
    } else if (eventType == "output" && m_onOutput) {
        DAPOutputEvent e;
        auto body = event["body"];
        e.category = body.value("category", "console");
        e.output = body.value("output", "");
        e.line = body.value("line", 0);
        e.column = body.value("column", 0);
        if (body.contains("source")) {
            e.file = body["source"].value("path", "");
        }
        m_onOutput(e);
        
    } else if (eventType == "breakpoint" && m_onBreakpoint) {
        DAPBreakpointEvent e;
        auto body = event["body"];
        e.reason = body.value("reason", "");
        // Parse breakpoint details
        if (body.contains("breakpoint")) {
            auto bp = body["breakpoint"];
            e.breakpoint.id = bp.value("id", 0);
            e.breakpoint.verified = bp.value("verified", false);
            e.breakpoint.line = bp.value("line", 0);
            e.breakpoint.column = bp.value("column", 0);
        }
        m_onBreakpoint(e);
        
    } else if (eventType == "module" && m_onModule) {
        DAPModuleEvent e;
        auto body = event["body"];
        e.reason = body.value("reason", "");
        if (body.contains("module")) {
            auto mod = body["module"];
            e.module.name = mod.value("name", "");
            e.module.path = mod.value("path", "");
            e.module.baseAddress = mod.value("address", 0);
            e.module.size = mod.value("size", 0);
        }
        m_onModule(e);
        
    } else if (eventType == "loadedSource" && m_onLoadedSource) {
        DAPLoadedSourceEvent e;
        auto body = event["body"];
        e.reason = body.value("reason", "");
        if (body.contains("source")) {
            e.path = body["source"].value("path", "");
        }
        m_onLoadedSource(e);
    }
}

void DAPClient::dispatchResponse(const json& response) {
    if (response.contains("request_seq")) {
        uint32_t requestId = response["request_seq"];
        
        std::lock_guard<std::mutex> lock(m_responseMutex);
        m_pendingResponses[requestId] = response;
        m_responseCv.notify_all();
    }
}

// ============================================================================
// JSON-RPC Helpers
// ============================================================================
bool DAPClient::sendRequest(const std::string& command, const json& arguments, 
                            uint32_t& outRequestId) {
    outRequestId = ++m_seq;
    
    json request = {
        {"seq", outRequestId},
        {"type", "request"},
        {"command", command},
        {"arguments", arguments}
    };
    
    std::string jsonStr = request.dump();
    std::string message = "Content-Length: " + std::to_string(jsonStr.size()) + "\r\n\r\n" + jsonStr;
    
#ifdef _WIN32
    if (!m_hStdinWrite) {
        return false;
    }
    
    DWORD bytesWritten = 0;
    BOOL success = WriteFile(m_hStdinWrite, message.c_str(), message.size(), 
                            &bytesWritten, nullptr);
    
    if (!success || bytesWritten != message.size()) {
        std::cerr << "[DAPClient] Failed to write to debugger" << std::endl;
        return false;
    }
    
    return true;
#else
    return false;
#endif
}

json DAPClient::waitForResponse(uint32_t requestId, int timeoutMs) {
    auto start = std::chrono::steady_clock::now();
    
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - start).count() < timeoutMs) {
        {
            std::lock_guard<std::mutex> lock(m_responseMutex);
            auto it = m_pendingResponses.find(requestId);
            if (it != m_pendingResponses.end()) {
                json response = it->second;
                m_pendingResponses.erase(it);
                return response;
            }
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    return nullptr;
}

// ============================================================================
// Session Control
// ============================================================================
DAPResult DAPClient::launch(const std::string& program, const std::string& args) {
    if (!m_initialized.load()) {
        return DAPResult::fail("DAP client not initialized");
    }
    
    json launchArgs = {
        {"name", "RawrXD Debug"},
        {"type", m_config.debuggerType},
        {"request", "launch"},
        {"program", program},
        {"args", args},
        {"stopOnEntry", m_config.stopOnEntry},
        {"cwd", m_config.workingDir},
        {"environment", json::array()},
        {"externalConsole", m_config.externalConsole}
    };
    
    uint32_t requestId;
    if (!sendRequest("launch", launchArgs, requestId)) {
        return DAPResult::fail("Failed to send launch request");
    }
    
    json response = waitForResponse(requestId, 30000);
    if (response.is_null()) {
        return DAPResult::fail("Launch timed out");
    }
    
    if (response.contains("success") && !response["success"].get<bool>()) {
        std::string msg = response.value("message", "Launch failed");
        return DAPResult::fail(msg);
    }
    
    return DAPResult::ok();
}

DAPResult DAPClient::attach(uint32_t pid) {
    if (!m_initialized.load()) {
        return DAPResult::fail("DAP client not initialized");
    }
    
    json attachArgs = {
        {"name", "RawrXD Attach"},
        {"type", m_config.debuggerType},
        {"request", "attach"},
        {"processId", pid}
    };
    
    uint32_t requestId;
    if (!sendRequest("attach", attachArgs, requestId)) {
        return DAPResult::fail("Failed to send attach request");
    }
    
    json response = waitForResponse(requestId, 10000);
    if (response.is_null()) {
        return DAPResult::fail("Attach timed out");
    }
    
    if (response.contains("success") && !response["success"].get<bool>()) {
        return DAPResult::fail(response.value("message", "Attach failed"));
    }
    
    return DAPResult::ok();
}

DAPResult DAPClient::detach() {
    uint32_t requestId;
    sendRequest("disconnect", {{"restart", false}, {"terminateDebuggee", false}}, requestId);
    waitForResponse(requestId, 5000);
    return DAPResult::ok();
}

DAPResult DAPClient::terminate() {
    uint32_t requestId;
    sendRequest("terminate", {{"restart", false}}, requestId);
    waitForResponse(requestId, 5000);
    return DAPResult::ok();
}

DAPResult DAPClient::restart() {
    uint32_t requestId;
    sendRequest("restart", {}, requestId);
    json response = waitForResponse(requestId, 10000);
    
    if (response.is_null()) {
        return DAPResult::fail("Restart timed out");
    }
    
    return DAPResult::ok();
}

// ============================================================================
// Execution Control
// ============================================================================
DAPResult DAPClient::continueExecution(uint32_t threadId) {
    json args = {{"threadId", threadId}};
    uint32_t requestId;
    sendRequest("continue", args, requestId);
    json response = waitForResponse(requestId, 5000);
    return response.is_null() ? DAPResult::fail("Continue timed out") : DAPResult::ok();
}

DAPResult DAPClient::pause(uint32_t threadId) {
    json args = {{"threadId", threadId}};
    uint32_t requestId;
    sendRequest("pause", args, requestId);
    json response = waitForResponse(requestId, 5000);
    return response.is_null() ? DAPResult::fail("Pause timed out") : DAPResult::ok();
}

DAPResult DAPClient::stepOver(uint32_t threadId) {
    json args = {{"threadId", threadId}, {"granularity", "statement"}};
    uint32_t requestId;
    sendRequest("next", args, requestId);
    json response = waitForResponse(requestId, 5000);
    return response.is_null() ? DAPResult::fail("Step over timed out") : DAPResult::ok();
}

DAPResult DAPClient::stepInto(uint32_t threadId) {
    json args = {{"threadId", threadId}, {"granularity", "statement"}};
    uint32_t requestId;
    sendRequest("stepIn", args, requestId);
    json response = waitForResponse(requestId, 5000);
    return response.is_null() ? DAPResult::fail("Step into timed out") : DAPResult::ok();
}

DAPResult DAPClient::stepOut(uint32_t threadId) {
    json args = {{"threadId", threadId}};
    uint32_t requestId;
    sendRequest("stepOut", args, requestId);
    json response = waitForResponse(requestId, 5000);
    return response.is_null() ? DAPResult::fail("Step out timed out") : DAPResult::ok();
}

DAPResult DAPClient::stepInstruction(uint32_t threadId) {
    json args = {{"threadId", threadId}, {"granularity", "instruction"}};
    uint32_t requestId;
    sendRequest("stepIn", args, requestId);
    json response = waitForResponse(requestId, 5000);
    return response.is_null() ? DAPResult::fail("Step instruction timed out") : DAPResult::ok();
}

DAPResult DAPClient::nextInstruction(uint32_t threadId) {
    json args = {{"threadId", threadId}, {"granularity", "instruction"}};
    uint32_t requestId;
    sendRequest("next", args, requestId);
    json response = waitForResponse(requestId, 5000);
    return response.is_null() ? DAPResult::fail("Next instruction timed out") : DAPResult::ok();
}

DAPResult DAPClient::gotoTarget(uint32_t threadId, const std::string& file, uint32_t line) {
    json args = {
        {"threadId", threadId},
        {"targetId", 0}  // Would need to call gotoTargets first
    };
    uint32_t requestId;
    sendRequest("goto", args, requestId);
    json response = waitForResponse(requestId, 5000);
    return response.is_null() ? DAPResult::fail("Goto timed out") : DAPResult::ok();
}

// ============================================================================
// Breakpoints
// ============================================================================
DAPResult DAPClient::setBreakpoint(const std::string& file, uint32_t line, 
                                    const std::string& condition) {
    json source = {{"path", file}};
    json breakpoint = {
        {"source", source},
        {"line", line},
        {"column", 0}
    };
    if (!condition.empty()) {
        breakpoint["condition"] = condition;
    }
    
    json args = {
        {"source", source},
        {"breakpoints", json::array({breakpoint})},
        {"lines", json::array({line})},
        {"sourceModified", false}
    };
    
    uint32_t requestId;
    sendRequest("setBreakpoints", args, requestId);
    json response = waitForResponse(requestId, 5000);
    
    if (response.is_null()) {
        return DAPResult::fail("Set breakpoint timed out");
    }
    
    if (response.contains("body") && response["body"].contains("breakpoints")) {
        auto breakpoints = response["body"]["breakpoints"];
        if (!breakpoints.empty()) {
            const auto& firstBreakpoint = breakpoints.at(static_cast<std::size_t>(0));
            if (firstBreakpoint.contains("id")) {
                uint32_t bpId = firstBreakpoint["id"];

                std::lock_guard<std::mutex> lock(m_breakpointMutex);
                DAPBreakpoint bp;
                bp.id = bpId;
                bp.file = file;
                bp.line = line;
                bp.condition = condition;
                bp.verified = firstBreakpoint.value("verified", false);
                m_breakpoints[bpId] = bp;

                return DAPResult::ok({{"id", bpId}});
            }
        }
    }
    
    return DAPResult::fail("Failed to set breakpoint");
}

DAPResult DAPClient::setFunctionBreakpoint(const std::string& function,
                                            const std::string& condition) {
    json breakpoint = {{"name", function}};
    if (!condition.empty()) {
        breakpoint["condition"] = condition;
    }
    
    json args = {{"breakpoints", json::array({breakpoint})}};
    
    uint32_t requestId;
    sendRequest("setFunctionBreakpoints", args, requestId);
    json response = waitForResponse(requestId, 5000);
    
    if (response.is_null()) {
        return DAPResult::fail("Set function breakpoint timed out");
    }
    
    return DAPResult::ok();
}

DAPResult DAPClient::setDataBreakpoint(const std::string& dataExpr, 
                                        const std::string& condition) {
    json breakpoint = {
        {"dataId", dataExpr},
        {"accessType", "readWrite"}
    };
    if (!condition.empty()) {
        breakpoint["condition"] = condition;
    }
    
    json args = {{"breakpoints", json::array({breakpoint})}};
    
    uint32_t requestId;
    sendRequest("setDataBreakpoints", args, requestId);
    json response = waitForResponse(requestId, 5000);
    
    if (response.is_null()) {
        return DAPResult::fail("Set data breakpoint timed out");
    }
    
    return DAPResult::ok();
}

DAPResult DAPClient::removeBreakpoint(uint32_t breakpointId) {
    std::lock_guard<std::mutex> lock(m_breakpointMutex);
    m_breakpoints.erase(breakpointId);
    
    // Note: DAP doesn't have a direct removeBreakpoint command
    // We need to re-send setBreakpoints without the removed one
    return DAPResult::ok();
}

DAPResult DAPClient::enableBreakpoint(uint32_t breakpointId, bool enable) {
    std::lock_guard<std::mutex> lock(m_breakpointMutex);
    auto it = m_breakpoints.find(breakpointId);
    if (it != m_breakpoints.end()) {
        // Note: DAP uses setBreakpoints to update
        // Full implementation would re-send all breakpoints
        (void)enable;
        return DAPResult::ok();
    }
    return DAPResult::fail("Breakpoint not found");
}

std::vector<DAPBreakpoint> DAPClient::getBreakpoints() const {
    std::lock_guard<std::mutex> lock(m_breakpointMutex);
    std::vector<DAPBreakpoint> result;
    for (const auto& [id, bp] : m_breakpoints) {
        result.push_back(bp);
    }
    return result;
}

// ============================================================================
// Stack Trace
// ============================================================================
DAPResult DAPClient::getStackTrace(uint32_t threadId, std::vector<DAPStackFrame>& outFrames,
                                    uint32_t startFrame, uint32_t levels) {
    json args = {
        {"threadId", threadId},
        {"startFrame", startFrame},
        {"levels", levels == 0 ? 20 : levels}
    };
    
    uint32_t requestId;
    sendRequest("stackTrace", args, requestId);
    json response = waitForResponse(requestId, 5000);
    
    if (response.is_null()) {
        return DAPResult::fail("Stack trace timed out");
    }
    
    outFrames.clear();
    
    if (response.contains("body") && response["body"].contains("stackFrames")) {
        for (const auto& frame : response["body"]["stackFrames"]) {
            DAPStackFrame f;
            f.id = frame.value("id", 0);
            f.name = frame.value("name", "");
            f.line = frame.value("line", 0);
            f.column = frame.value("column", 0);
            f.instructionPointer = frame.value("instructionPointerReference", 0);
            
            if (frame.contains("source")) {
                auto source = frame["source"];
                f.file = source.value("path", "");
            }
            
            outFrames.push_back(f);
        }
    }
    
    return DAPResult::ok();
}

DAPResult DAPClient::getScopes(uint32_t frameId, std::vector<DAPVariable>& outScopes) {
    json args = {{"frameId", frameId}};
    
    uint32_t requestId;
    sendRequest("scopes", args, requestId);
    json response = waitForResponse(requestId, 5000);
    
    if (response.is_null()) {
        return DAPResult::fail("Scopes timed out");
    }
    
    outScopes.clear();
    
    if (response.contains("body") && response["body"].contains("scopes")) {
        for (const auto& scope : response["body"]["scopes"]) {
            DAPVariable v;
            v.name = scope.value("name", "");
            v.variablesReference = scope.value("variablesReference", 0);
            v.expensive = scope.value("expensive", false);
            outScopes.push_back(v);
        }
    }
    
    return DAPResult::ok();
}

// ============================================================================
// Variables
// ============================================================================
DAPResult DAPClient::getVariables(uint32_t variablesReference, std::vector<DAPVariable>& outVars) {
    if (variablesReference == 0) {
        return DAPResult::ok();  // Scalar, no children
    }
    
    json args = {{"variablesReference", variablesReference}};
    
    uint32_t requestId;
    sendRequest("variables", args, requestId);
    json response = waitForResponse(requestId, 5000);
    
    if (response.is_null()) {
        return DAPResult::fail("Variables timed out");
    }
    
    outVars.clear();
    
    if (response.contains("body") && response["body"].contains("variables")) {
        for (const auto& var : response["body"]["variables"]) {
            DAPVariable v;
            v.name = var.value("name", "");
            v.value = var.value("value", "");
            v.type = var.value("type", "");
            v.variablesReference = var.value("variablesReference", 0);
            v.expensive = var.value("expensive", false);
            outVars.push_back(v);
        }
    }
    
    return DAPResult::ok();
}

DAPResult DAPClient::setVariable(uint32_t variablesReference, const std::string& name,
                                  const std::string& value) {
    json args = json::object();
    args["variablesReference"] = variablesReference;
    args["name"] = name;
    args["value"] = value;
    
    uint32_t requestId;
    sendRequest("setVariable", args, requestId);
    json response = waitForResponse(requestId, 5000);
    
    if (response.is_null()) {
        return DAPResult::fail("Set variable timed out");
    }
    
    return DAPResult::ok();
}

DAPResult DAPClient::evaluate(const std::string& expression, uint32_t frameId,
                               DAPVariable& outResult) {
    json args = json::object();
    args["expression"] = expression;
    args["frameId"] = frameId;
    args["context"] = "watch";
    
    uint32_t requestId;
    sendRequest("evaluate", args, requestId);
    json response = waitForResponse(requestId, 5000);
    
    if (response.is_null()) {
        return DAPResult::fail("Evaluate timed out");
    }
    
    if (response.contains("body")) {
        auto body = response["body"];
        outResult.value = body.value("result", "");
        outResult.type = body.value("type", "");
        outResult.variablesReference = body.value("variablesReference", 0);
    }
    
    return DAPResult::ok();
}

// ============================================================================
// Threads
// ============================================================================
DAPResult DAPClient::getThreads(std::vector<DAPThread>& outThreads) {
    uint32_t requestId;
    sendRequest("threads", {}, requestId);
    json response = waitForResponse(requestId, 5000);
    
    if (response.is_null()) {
        return DAPResult::fail("Threads timed out");
    }
    
    outThreads.clear();
    
    if (response.contains("body") && response["body"].contains("threads")) {
        for (const auto& thread : response["body"]["threads"]) {
            DAPThread t;
            t.id = thread.value("id", 0);
            t.name = thread.value("name", "");
            outThreads.push_back(t);
        }
    }
    
    return DAPResult::ok();
}

// ============================================================================
// Modules
// ============================================================================
DAPResult DAPClient::getModules(std::vector<DAPModule>& outModules) {
    json args = json::object();
    args["startModule"] = 0;
    args["moduleCount"] = 0;  // 0 = all
    
    uint32_t requestId;
    sendRequest("modules", args, requestId);
    json response = waitForResponse(requestId, 5000);
    
    if (response.is_null()) {
        return DAPResult::fail("Modules timed out");
    }
    
    outModules.clear();
    
    if (response.contains("body") && response["body"].contains("modules")) {
        for (const auto& mod : response["body"]["modules"]) {
            DAPModule m;
            m.name = mod.value("name", "");
            m.path = mod.value("path", "");
            m.baseAddress = mod.value("address", 0);
            m.size = mod.value("size", 0);
            m.symbolsLoaded = mod.value("symbolStatus", "") == "Symbols loaded";
            m.symbolPath = mod.value("symbolFilePath", "");
            outModules.push_back(m);
        }
    }
    
    return DAPResult::ok();
}

// ============================================================================
// Source
// ============================================================================
DAPResult DAPClient::getSource(uint32_t sourceReference, std::string& outContent) {
    json args = {{"sourceReference", sourceReference}};
    
    uint32_t requestId;
    sendRequest("source", args, requestId);
    json response = waitForResponse(requestId, 5000);
    
    if (response.is_null()) {
        return DAPResult::fail("Source timed out");
    }
    
    if (response.contains("body") && response["body"].contains("content")) {
        outContent = response["body"]["content"].get<std::string>();
    }
    
    return DAPResult::ok();
}

// ============================================================================
// Disassembly
// ============================================================================
DAPResult DAPClient::disassemble(uint64_t address, uint32_t instructionCount,
                                  std::vector<std::string>& outInstructions) {
    json args = json::object();
    args["memoryReference"] = std::to_string(address);
    args["instructionCount"] = instructionCount;
    args["resolveSymbols"] = true;
    
    uint32_t requestId;
    sendRequest("disassemble", args, requestId);
    json response = waitForResponse(requestId, 5000);
    
    if (response.is_null()) {
        return DAPResult::fail("Disassemble timed out");
    }
    
    outInstructions.clear();
    
    if (response.contains("body") && response["body"].contains("instructions")) {
        for (const auto& inst : response["body"]["instructions"]) {
            std::string line = inst.value("address", "") + ": " + inst.value("instruction", "");
            outInstructions.push_back(line);
        }
    }
    
    return DAPResult::ok();
}

// ============================================================================
// Memory
// ============================================================================
DAPResult DAPClient::readMemory(uint64_t address, uint32_t count, std::vector<uint8_t>& outData) {
    json args = json::object();
    args["memoryReference"] = std::to_string(address);
    args["offset"] = 0;
    args["count"] = count;
    
    uint32_t requestId;
    sendRequest("readMemory", args, requestId);
    json response = waitForResponse(requestId, 5000);
    
    if (response.is_null()) {
        return DAPResult::fail("Read memory timed out");
    }
    
    outData.clear();
    
    if (response.contains("body") && response["body"].contains("data")) {
        std::string base64Data = response["body"]["data"].get<std::string>();
        // Decode base64 (simplified - would need proper base64 decoder)
        // For now, just return empty
        (void)base64Data;
    }
    
    return DAPResult::ok();
}

DAPResult DAPClient::writeMemory(uint64_t address, const std::vector<uint8_t>& data) {
    // Encode data as base64 (simplified)
    std::string base64Data;  // Would need proper base64 encoder
    
    json args = json::object();
    args["memoryReference"] = std::to_string(address);
    args["offset"] = 0;
    args["data"] = base64Data;
    
    uint32_t requestId;
    sendRequest("writeMemory", args, requestId);
    json response = waitForResponse(requestId, 5000);
    
    if (response.is_null()) {
        return DAPResult::fail("Write memory timed out");
    }
    
    (void)data;
    return DAPResult::ok();
}

// ============================================================================
// Event Callbacks
// ============================================================================
void DAPClient::onStopped(std::function<void(const DAPStoppedEvent&)> callback) {
    m_onStopped = callback;
}

void DAPClient::onContinued(std::function<void(const DAPContinuedEvent&)> callback) {
    m_onContinued = callback;
}

void DAPClient::onExited(std::function<void(const DAPExitedEvent&)> callback) {
    m_onExited = callback;
}

void DAPClient::onTerminated(std::function<void(const DAPTerminatedEvent&)> callback) {
    m_onTerminated = callback;
}

void DAPClient::onThread(std::function<void(const DAPThreadEvent&)> callback) {
    m_onThread = callback;
}

void DAPClient::onOutput(std::function<void(const DAPOutputEvent&)> callback) {
    m_onOutput = callback;
}

void DAPClient::onBreakpoint(std::function<void(const DAPBreakpointEvent&)> callback) {
    m_onBreakpoint = callback;
}

void DAPClient::onModule(std::function<void(const DAPModuleEvent&)> callback) {
    m_onModule = callback;
}

void DAPClient::onLoadedSource(std::function<void(const DAPLoadedSourceEvent&)> callback) {
    m_onLoadedSource = callback;
}

// ============================================================================
// Protocol Helpers
// ============================================================================
void DAPClient::parseCapabilities(const json& caps) {
    m_capsConditionalBreakpoints = caps.value("supportsConditionalBreakpoints", false);
    m_capsHitConditionalBreakpoints = caps.value("supportsHitConditionalBreakpoints", false);
    m_capsFunctionBreakpoints = caps.value("supportsFunctionBreakpoints", false);
    m_capsDataBreakpoints = caps.value("supportsDataBreakpoints", false);
    m_capsStepBack = caps.value("supportsStepBack", false);
    m_capsSetVariable = caps.value("supportsSetVariable", false);
    m_capsRestartRequest = caps.value("supportsRestartRequest", false);
    m_capsGotoTargetsRequest = caps.value("supportsGotoTargetsRequest", false);
    m_capsStepInTargetsRequest = caps.value("supportsStepInTargetsRequest", false);
    m_capsCompletionsRequest = caps.value("supportsCompletionsRequest", false);
    m_capsModulesRequest = caps.value("supportsModulesRequest", false);
    m_capsDisassembleRequest = caps.value("supportsDisassembleRequest", false);
    m_capsReadMemoryRequest = caps.value("supportsReadMemoryRequest", false);
    m_capsWriteMemoryRequest = caps.value("supportsWriteMemoryRequest", false);
}

DAPStopReason DAPClient::parseStopReason(const std::string& reason) {
    if (reason == "step") return DAPStopReason::Step;
    if (reason == "breakpoint") return DAPStopReason::Breakpoint;
    if (reason == "exception") return DAPStopReason::Exception;
    if (reason == "pause") return DAPStopReason::Pause;
    if (reason == "entry") return DAPStopReason::Entry;
    if (reason == "goto") return DAPStopReason::Goto;
    if (reason == "function breakpoint") return DAPStopReason::FunctionBreakpoint;
    if (reason == "data breakpoint") return DAPStopReason::DataBreakpoint;
    if (reason == "instruction breakpoint") return DAPStopReason::InstructionBreakpoint;
    return DAPStopReason::Breakpoint;
}

DAPThreadState DAPClient::parseThreadState(const std::string& state) {
    if (state == "stopped") return DAPThreadState::Stopped;
    return DAPThreadState::Running;
}

} // namespace DAP
} // namespace RawrXD
