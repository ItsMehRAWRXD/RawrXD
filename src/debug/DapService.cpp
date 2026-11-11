// ============================================================================
// Phase 24: Debug Adapter Service - Implementation
// ============================================================================

#include "DapService.hpp"
#include "nlohmann/json.hpp"
#include <windows.h>
#include <sstream>
#include <iomanip>
#include <map>
#include <set>

namespace RawrXD {
namespace Debug {

// ============================================================================
// PIMPL Implementation
// ============================================================================

class DapService::Impl {
public:
    Impl() : m_state(DapState::Disconnected), m_nextRequestId(1), m_initialized(false) {}
    
    ~Impl() {
        shutdown();
    }
    
    DapResult initialize(const LaunchConfig& config) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        if (m_initialized) {
            return DapResult::Fail("Service already initialized");
        }
        
        m_config = config;
        
        // Create debugger process with pipes
        if (!createDebuggerProcess()) {
            return DapResult::Fail("Failed to create debugger process");
        }
        
        // Start reader thread
        m_shutdown = false;
        m_readerThread = std::thread(&Impl::readerLoop, this);
        
        // Send initialize request
        nlohmann::json initArgs = nlohmann::json::object();
        initArgs["clientID"] = "rawrxd";
        initArgs["clientName"] = "RawrXD IDE";
        initArgs["adapterID"] = config.debuggerType.empty() ? "cppvsdbg" : config.debuggerType;
        initArgs["locale"] = "en-US";
        initArgs["linesStartAt1"] = true;
        initArgs["columnsStartAt1"] = true;
        initArgs["pathFormat"] = "path";
        initArgs["supportsVariableType"] = true;
        initArgs["supportsVariablePaging"] = true;
        initArgs["supportsRunInTerminalRequest"] = false;
        initArgs["supportsMemoryReferences"] = true;
        
        auto result = sendRequestInternal("initialize", initArgs, nullptr, 10000);
        if (!result.success) {
            shutdown();
            return DapResult::Fail("Initialize handshake failed: " + result.error);
        }
        
        m_initialized = true;
        setState(DapState::Initializing);
        
        return DapResult::Ok();
    }
    
    DapResult shutdown() {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_shutdown = true;
        }
        
        m_cv.notify_all();
        
        if (m_readerThread.joinable()) {
            m_readerThread.join();
        }
        
        closeHandles();
        
        std::lock_guard<std::mutex> lock(m_mutex);
        m_initialized = false;
        setState(DapState::Disconnected);
        
        return DapResult::Ok();
    }
    
    bool isInitialized() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_initialized;
    }
    
    DapState state() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_state;
    }
    
    DapResult launch() {
        nlohmann::json args = nlohmann::json::object();
        args["program"] = m_config.program;
        args["cwd"] = m_config.workingDirectory;
        args["stopOnEntry"] = m_config.stopOnEntry;
        
        if (!m_config.args.empty()) {
            args["args"] = m_config.args;
        }
        
        if (!m_config.env.empty()) {
            nlohmann::json envJson = nlohmann::json::object();
            for (const auto& e : m_config.env) {
                size_t pos = e.find('=');
                if (pos != std::string::npos) {
                    envJson[e.substr(0, pos)] = e.substr(pos + 1);
                }
            }
            args["env"] = envJson;
        }
        
        auto result = sendRequest("launch", args);
        if (result.success) {
            setState(DapState::Running);
        }
        return result;
    }
    
    DapResult attach(uint32_t processId) {
        nlohmann::json args = nlohmann::json::object();
        args["processId"] = processId;
        
        auto result = sendRequest("attach", args);
        if (result.success) {
            setState(DapState::Running);
        }
        return result;
    }
    
    DapResult continueExecution(uint32_t threadId) {
        nlohmann::json args = nlohmann::json::object();
        if (threadId != 0) {
            args["threadId"] = threadId;
        }
        
        auto result = sendRequest("continue", args);
        if (result.success) {
            setState(DapState::Running);
        }
        return result;
    }
    
    DapResult pause() {
        return sendRequest("pause", nlohmann::json::object());
    }
    
    DapResult stepOver(uint32_t threadId) {
        nlohmann::json args = nlohmann::json::object();
        args["threadId"] = threadId;
        args["granularity"] = "statement";
        return sendRequest("next", args);
    }
    
    DapResult stepInto(uint32_t threadId) {
        nlohmann::json args = nlohmann::json::object();
        args["threadId"] = threadId;
        args["granularity"] = "statement";
        return sendRequest("stepIn", args);
    }
    
    DapResult stepOut(uint32_t threadId) {
        nlohmann::json args = nlohmann::json::object();
        args["threadId"] = threadId;
        return sendRequest("stepOut", args);
    }
    
    DapResult restart() {
        return sendRequest("restart", nlohmann::json::object());
    }
    
    DapResult terminate() {
        nlohmann::json args = nlohmann::json::object();
        args["restart"] = false;
        
        auto result = sendRequest("terminate", args);
        setState(DapState::Stopped);
        return result;
    }
    
    DapResult detach() {
        auto result = sendRequest("disconnect", nlohmann::json::object());
        setState(DapState::Disconnected);
        return result;
    }
    
    DapResult setBreakpoint(const std::string& source, uint32_t line, 
                            const std::string& condition,
                            Breakpoint* outBp) {
        nlohmann::json sourceJson = nlohmann::json::object();
        sourceJson["path"] = source;
        
        nlohmann::json bpJson = nlohmann::json::object();
        bpJson["line"] = line;
        if (!condition.empty()) {
            bpJson["condition"] = condition;
        }
        
        nlohmann::json args = nlohmann::json::object();
        args["source"] = sourceJson;
        args["breakpoints"] = nlohmann::json::array({bpJson});
        
        return sendRequest("setBreakpoints", args);
    }
    
    DapResult setFunctionBreakpoint(const std::string& function, Breakpoint* outBp) {
        nlohmann::json bpJson = nlohmann::json::object();
        bpJson["name"] = function;
        
        nlohmann::json args = nlohmann::json::object();
        args["breakpoints"] = nlohmann::json::array({bpJson});
        
        return sendRequest("setFunctionBreakpoints", args);
    }
    
    DapResult removeBreakpoint(uint32_t breakpointId) {
        return DapResult::Ok();
    }
    
    DapResult removeBreakpoints(const std::string& source) {
        nlohmann::json sourceJson = nlohmann::json::object();
        sourceJson["path"] = source;
        
        nlohmann::json args = nlohmann::json::object();
        args["source"] = sourceJson;
        args["breakpoints"] = nlohmann::json::array();
        
        return sendRequest("setBreakpoints", args);
    }
    
    DapResult removeAllBreakpoints() {
        return DapResult::Ok();
    }
    
    DapResult requestStackTrace(uint32_t threadId, uint32_t startFrame, uint32_t levels) {
        nlohmann::json args = nlohmann::json::object();
        args["threadId"] = threadId;
        if (startFrame != 0) {
            args["startFrame"] = startFrame;
        }
        if (levels != 0) {
            args["levels"] = levels;
        }
        
        return sendRequest("stackTrace", args);
    }
    
    DapResult requestVariables(uint32_t variablesReference) {
        nlohmann::json args = nlohmann::json::object();
        args["variablesReference"] = variablesReference;
        
        return sendRequest("variables", args);
    }
    
    DapResult evaluate(const std::string& expression, uint32_t frameId, Variable* outResult) {
        nlohmann::json args = nlohmann::json::object();
        args["expression"] = expression;
        args["frameId"] = frameId;
        args["context"] = "watch";
        
        return sendRequest("evaluate", args);
    }
    
    DapResult setVariable(uint32_t variablesReference, const std::string& name, const std::string& value) {
        nlohmann::json args = nlohmann::json::object();
        args["variablesReference"] = variablesReference;
        args["name"] = name;
        args["value"] = value;
        
        return sendRequest("setVariable", args);
    }
    
    DapResult requestThreads() {
        return sendRequest("threads", nlohmann::json::object());
    }
    
    void setCallbacks(const Callbacks& callbacks) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_callbacks = callbacks;
    }
    
    DapResult sendRawRequest(const std::string& command, const nlohmann::json& args,
                             nlohmann::json* outResponse, uint32_t timeoutMs) {
        return sendRequestInternal(command, args, outResponse, timeoutMs);
    }
    
    std::string lastError() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_lastError;
    }
    
    bool hasPendingRequest() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return !m_pendingRequests.empty();
    }
    
    bool waitForIdle(uint32_t timeoutMs) {
        std::unique_lock<std::mutex> lock(m_mutex);
        return m_cv.wait_for(lock, std::chrono::milliseconds(timeoutMs), [this]() {
            return m_pendingRequests.empty();
        });
    }

private:
    bool createDebuggerProcess() {
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = nullptr;
        
        HANDLE hStdInRead, hStdInWrite;
        HANDLE hStdOutRead, hStdOutWrite;
        
        if (!CreatePipe(&hStdInRead, &hStdInWrite, &sa, 0)) return false;
        if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0)) {
            CloseHandle(hStdInRead);
            CloseHandle(hStdInWrite);
            return false;
        }
        
        SetHandleInformation(hStdInWrite, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0);
        
        std::string debuggerExe = m_config.debuggerPath;
        if (debuggerExe.empty()) {
            debuggerExe = "cdb.exe";
        }
        
        STARTUPINFOA si = {};
        si.cb = sizeof(STARTUPINFOA);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = hStdInRead;
        si.hStdOutput = hStdOutWrite;
        si.hStdError = hStdOutWrite;
        
        PROCESS_INFORMATION pi = {};
        
        std::string cmdLine = "\"" + debuggerExe + "\" --interpreter=vscode";
        
        BOOL success = CreateProcessA(
            nullptr,
            const_cast<char*>(cmdLine.c_str()),
            nullptr,
            nullptr,
            TRUE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &si,
            &pi
        );
        
        CloseHandle(hStdInRead);
        CloseHandle(hStdOutWrite);
        
        if (!success) {
            CloseHandle(hStdInWrite);
            CloseHandle(hStdOutRead);
            return false;
        }
        
        m_hProcess = pi.hProcess;
        m_hThread = pi.hThread;
        m_hStdIn = hStdInWrite;
        m_hStdOut = hStdOutRead;
        
        return true;
    }
    
    void closeHandles() {
        if (m_hStdIn) { CloseHandle(m_hStdIn); m_hStdIn = nullptr; }
        if (m_hStdOut) { CloseHandle(m_hStdOut); m_hStdOut = nullptr; }
        if (m_hProcess) { CloseHandle(m_hProcess); m_hProcess = nullptr; }
        if (m_hThread) { CloseHandle(m_hThread); m_hThread = nullptr; }
    }
    
    DapResult sendRequest(const std::string& command, const nlohmann::json& args) {
        return sendRequestInternal(command, args, nullptr, 5000);
    }
    
    DapResult sendRequestInternal(const std::string& command, const nlohmann::json& args,
                                   nlohmann::json* outResponse, uint32_t timeoutMs) {
        uint32_t requestId = m_nextRequestId++;
        
        nlohmann::json request = nlohmann::json::object();
        request["seq"] = requestId;
        request["type"] = "request";
        request["command"] = command;
        request["arguments"] = args;
        
        std::string jsonStr = request.dump();
        std::string message = "Content-Length: " + std::to_string(jsonStr.length()) + "\r\n\r\n" + jsonStr;
        
        DWORD written;
        if (!WriteFile(m_hStdIn, message.c_str(), static_cast<DWORD>(message.length()), &written, nullptr)) {
            return DapResult::Fail("Failed to write to debugger stdin");
        }
        
        if (outResponse) {
            auto response = waitForResponse(requestId, timeoutMs);
            if (response.is_null()) {
                return DapResult::Fail("Request timed out");
            }
            *outResponse = response;
        }
        
        return DapResult::Ok();
    }
    
    nlohmann::json waitForResponse(uint32_t requestId, uint32_t timeoutMs) {
        auto start = std::chrono::steady_clock::now();
        
        while (std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now() - start).count() < timeoutMs) {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                auto it = m_pendingResponses.find(requestId);
                if (it != m_pendingResponses.end()) {
                    nlohmann::json response = it->second;
                    m_pendingResponses.erase(it);
                    return response;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        return nlohmann::json();
    }
    
    void readerLoop() {
        std::string buffer;
        char readBuf[4096];
        DWORD bytesRead;
        
        while (!m_shutdown) {
            if (!ReadFile(m_hStdOut, readBuf, sizeof(readBuf) - 1, &bytesRead, nullptr)) {
                if (m_shutdown) break;
                
                DWORD error = GetLastError();
                if (error == ERROR_BROKEN_PIPE) {
                    notifyError("Debugger pipe broken (process exited)", true);
                    break;
                }
                
                notifyError("ReadFile failed: " + std::to_string(error), false);
                continue;
            }
            
            readBuf[bytesRead] = '\0';
            buffer += readBuf;
            
            processBuffer(buffer);
        }
    }
    
    void processBuffer(std::string& buffer) {
        while (true) {
            size_t headerEnd = buffer.find("\r\n\r\n");
            if (headerEnd == std::string::npos) break;
            
            size_t clPos = buffer.find("Content-Length: ");
            if (clPos == std::string::npos) {
                buffer = buffer.substr(headerEnd + 4);
                continue;
            }
            
            size_t clEnd = buffer.find("\r\n", clPos);
            if (clEnd == std::string::npos) break;
            
            std::string lenStr = buffer.substr(clPos + 16, clEnd - clPos - 16);
            size_t contentLength = std::stoul(lenStr);
            
            size_t messageStart = headerEnd + 4;
            if (buffer.length() < messageStart + contentLength) {
                break;
            }
            
            std::string jsonStr = buffer.substr(messageStart, contentLength);
            buffer = buffer.substr(messageStart + contentLength);
            
            try {
                nlohmann::json message = nlohmann::json::parse(jsonStr);
                handleMessage(message);
            } catch (const std::exception& e) {
                notifyError("JSON parse error: " + std::string(e.what()), false);
            }
        }
    }
    
    void handleMessage(const nlohmann::json& message) {
        std::string type = message.value("type", "");
        
        if (type == "response") {
            handleResponse(message);
        } else if (type == "event") {
            handleEvent(message);
        }
    }
    
    void handleResponse(const nlohmann::json& response) {
        uint32_t requestId = response.value("request_seq", 0);
        
        std::lock_guard<std::mutex> lock(m_mutex);
        m_pendingResponses[requestId] = response;
        m_cv.notify_all();
    }
    
    void handleEvent(const nlohmann::json& event) {
        std::string eventType = event.value("event", "");
        auto body = event.value("body", nlohmann::json::object());
        
        if (eventType == "initialized") {
            setState(DapState::Initializing);
        } else if (eventType == "stopped") {
            setState(DapState::Paused);
            
            std::string reason = body.value("reason", "unknown");
            uint32_t threadId = body.value("threadId", 0);
            std::string description = body.value("description", "");
            
            if (m_callbacks.onStopped) {
                m_callbacks.onStopped(reason, threadId, description);
            }
            
            if (m_callbacks.onStackTrace && threadId != 0) {
                requestStackTrace(threadId, 0, 0);
            }
            
        } else if (eventType == "continued") {
            setState(DapState::Running);
            
            uint32_t threadId = body.value("threadId", 0);
            if (m_callbacks.onContinued) {
                m_callbacks.onContinued(threadId);
            }
            
        } else if (eventType == "terminated") {
            setState(DapState::Stopped);
            
            if (m_callbacks.onTerminated) {
                m_callbacks.onTerminated();
            }
            
        } else if (eventType == "output") {
            std::string category = body.value("category", "console");
            std::string output = body.value("output", "");
            
            OutputChannel channel = OutputChannel::Console;
            if (category == "stdout") channel = OutputChannel::Stdout;
            else if (category == "stderr") channel = OutputChannel::Stderr;
            else if (category == "telemetry") channel = OutputChannel::Telemetry;
            
            if (m_callbacks.onOutput) {
                m_callbacks.onOutput(channel, output);
            }
            
        } else if (eventType == "breakpoint") {
            auto bp = body.value("breakpoint", nlohmann::json::object());
            Breakpoint breakpoint;
            breakpoint.id = bp.value("id", 0);
            breakpoint.verified = bp.value("verified", false);
            breakpoint.line = bp.value("line", 0);
            
            auto src = bp.value("source", nlohmann::json::object());
            breakpoint.source = src.value("path", "");
            
            if (m_callbacks.onBreakpointSet) {
                m_callbacks.onBreakpointSet(breakpoint);
            }
        }
    }
    
    void setState(DapState newState) {
        DapState oldState;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            oldState = m_state;
            m_state = newState;
        }
        
        if (oldState != newState && m_callbacks.onStateChanged) {
            m_callbacks.onStateChanged(oldState, newState);
        }
    }
    
    void notifyError(const std::string& error, bool fatal) {
        m_lastError = error;
        
        if (m_callbacks.onError) {
            m_callbacks.onError(error, fatal);
        }
        
        if (fatal) {
            setState(DapState::Disconnected);
        }
    }
    
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    
    LaunchConfig m_config;
    Callbacks m_callbacks;
    
    std::atomic<DapState> m_state;
    std::atomic<bool> m_initialized;
    std::atomic<bool> m_shutdown;
    std::atomic<uint32_t> m_nextRequestId;
    
    HANDLE m_hProcess = nullptr;
    HANDLE m_hThread = nullptr;
    HANDLE m_hStdIn = nullptr;
    HANDLE m_hStdOut = nullptr;
    
    std::thread m_readerThread;
    
    std::map<uint32_t, nlohmann::json> m_pendingResponses;
    std::set<uint32_t> m_pendingRequests;
    
    std::string m_lastError;
};

// ============================================================================
// DapService Public Interface
// ============================================================================

DapService& DapService::instance() {
    static DapService instance;
    return instance;
}

DapService::DapService() : m_impl(std::make_unique<Impl>()) {}
DapService::~DapService() = default;

DapResult DapService::initialize(const LaunchConfig& config) { return m_impl->initialize(config); }
DapResult DapService::shutdown() { return m_impl->shutdown(); }
bool DapService::isInitialized() const { return m_impl->isInitialized(); }
DapState DapService::state() const { return m_impl->state(); }

DapResult DapService::launch() { return m_impl->launch(); }
DapResult DapService::attach(uint32_t processId) { return m_impl->attach(processId); }
DapResult DapService::continueExecution(uint32_t threadId) { return m_impl->continueExecution(threadId); }
DapResult DapService::pause() { return m_impl->pause(); }
DapResult DapService::stepOver(uint32_t threadId) { return m_impl->stepOver(threadId); }
DapResult DapService::stepInto(uint32_t threadId) { return m_impl->stepInto(threadId); }
DapResult DapService::stepOut(uint32_t threadId) { return m_impl->stepOut(threadId); }
DapResult DapService::restart() { return m_impl->restart(); }
DapResult DapService::terminate() { return m_impl->terminate(); }
DapResult DapService::detach() { return m_impl->detach(); }

DapResult DapService::setBreakpoint(const std::string& source, uint32_t line, 
                                     const std::string& condition, Breakpoint* outBp) {
    return m_impl->setBreakpoint(source, line, condition, outBp);
}
DapResult DapService::setFunctionBreakpoint(const std::string& function, Breakpoint* outBp) {
    return m_impl->setFunctionBreakpoint(function, outBp);
}
DapResult DapService::removeBreakpoint(uint32_t breakpointId) { return m_impl->removeBreakpoint(breakpointId); }
DapResult DapService::removeBreakpoints(const std::string& source) { return m_impl->removeBreakpoints(source); }
DapResult DapService::removeAllBreakpoints() { return m_impl->removeAllBreakpoints(); }

DapResult DapService::requestStackTrace(uint32_t threadId, uint32_t startFrame, uint32_t levels) {
    return m_impl->requestStackTrace(threadId, startFrame, levels);
}
DapResult DapService::requestVariables(uint32_t variablesReference) { return m_impl->requestVariables(variablesReference); }
DapResult DapService::evaluate(const std::string& expression, uint32_t frameId, Variable* outResult) {
    return m_impl->evaluate(expression, frameId, outResult);
}
DapResult DapService::setVariable(uint32_t variablesReference, const std::string& name, const std::string& value) {
    return m_impl->setVariable(variablesReference, name, value);
}
DapResult DapService::requestThreads() { return m_impl->requestThreads(); }

void DapService::setCallbacks(const Callbacks& callbacks) { m_impl->setCallbacks(callbacks); }

DapResult DapService::sendRawRequest(const std::string& command, const nlohmann::json& args,
                                       nlohmann::json* outResponse, uint32_t timeoutMs) {
    return m_impl->sendRawRequest(command, args, outResponse, timeoutMs);
}

std::string DapService::lastError() const { return m_impl->lastError(); }
bool DapService::hasPendingRequest() const { return m_impl->hasPendingRequest(); }
bool DapService::waitForIdle(uint32_t timeoutMs) { return m_impl->waitForIdle(timeoutMs); }

// ============================================================================
// Utility Functions
// ============================================================================

const char* StateToString(DapState state) {
    switch (state) {
        case DapState::Disconnected: return "Disconnected";
        case DapState::Initializing: return "Initializing";
        case DapState::Running: return "Running";
        case DapState::Paused: return "Paused";
        case DapState::Stopped: return "Stopped";
        default: return "Unknown";
    }
}

DapState StringToState(const std::string& str) {
    if (str == "Disconnected") return DapState::Disconnected;
    if (str == "Initializing") return DapState::Initializing;
    if (str == "Running") return DapState::Running;
    if (str == "Paused") return DapState::Paused;
    if (str == "Stopped") return DapState::Stopped;
    return DapState::Disconnected;
}

} // namespace Debug
} // namespace RawrXD
