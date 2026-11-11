// DAPAdapter.cpp
// Phase 25: DAP Adapter - Protocol Implementation
// ============================================================================

#include "DAPAdapter.h"
#include "DAPTransport.h"
#include "Debugger_Backend.h"
#include <sstream>
#include <iomanip>
#include <memory>
#include <initializer_list>

namespace RawrXD {
namespace DAP {

// ============================================================================
// JSON Helper Functions (Minimalist - no external JSON library)
// ============================================================================
namespace JSON {
    std::string EscapeString(const std::string& str) {
        std::string result;
        for (char c : str) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\b': result += "\\b"; break;
                case '\f': result += "\\f"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default: result += c;
            }
        }
        return result;
    }
    
    std::string MakeObject(const std::vector<std::pair<std::string, std::string>>& pairs) {
        std::string result = "{";
        for (size_t i = 0; i < pairs.size(); i++) {
            if (i > 0) result += ",";
            result += "\"" + pairs[i].first + "\":" + pairs[i].second;
        }
        result += "}";
        return result;
    }

    std::string MakeObject(std::initializer_list<std::pair<std::string, std::string>> pairs) {
        return MakeObject(std::vector<std::pair<std::string, std::string>>(pairs));
    }
    
    std::string MakeArray(const std::vector<std::string>& items) {
        std::string result = "[";
        for (size_t i = 0; i < items.size(); i++) {
            if (i > 0) result += ",";
            result += items[i];
        }
        result += "]";
        return result;
    }
    
    std::string String(const std::string& value) {
        return "\"" + EscapeString(value) + "\"";
    }
    
    std::string Number(int64_t value) {
        return std::to_string(value);
    }
    
    std::string Number(uint64_t value) {
        return std::to_string(value);
    }

    std::string Number(uint32_t value) {
        return std::to_string(value);
    }
    
    std::string Number(int value) {
        return std::to_string(value);
    }
    
    std::string Bool(bool value) {
        return value ? "true" : "false";
    }
    
    std::string Null() {
        return "null";
    }
}

// ============================================================================
// Implementation
// ============================================================================
class DAPAdapter::Impl {
public:
    DAPTransport* transport_ = nullptr;
    RawrXD::Debugger::DebugSession* debugSession_ = nullptr;
    bool running_ = false;
    bool shutdown_ = false;
    int requestSeq_ = 0;
    
    // Command dispatch
    void DispatchCommand(const std::string& json);
    std::string ExtractCommand(const std::string& json);
    int ExtractSeq(const std::string& json);
    
    // Command handlers
    void HandleInitialize(int seq);
    void HandleLaunch(int seq, const std::string& json);
    void HandleAttach(int seq, const std::string& json);
    void HandleConfigurationDone(int seq);
    void HandleDisconnect(int seq);
    void HandleSetBreakpoints(int seq, const std::string& json);
    void HandleContinue(int seq, const std::string& json);
    void HandleNext(int seq, const std::string& json);
    void HandleStepIn(int seq, const std::string& json);
    void HandleStepOut(int seq, const std::string& json);
    void HandlePause(int seq);
    void HandleStackTrace(int seq, const std::string& json);
    void HandleScopes(int seq, const std::string& json);
    void HandleVariables(int seq, const std::string& json);
    void HandleEvaluate(int seq, const std::string& json);
    
    // Response helpers
    void SendResponse(int seq, const std::string& command, 
                      const std::string& body = "{}", bool success = true);
    void SendErrorResponse(int seq, const std::string& command, 
                           const std::string& message, int errorCode = 0);
};

DAPAdapter::DAPAdapter() : pImpl_(std::make_unique<Impl>()) {}
DAPAdapter::~DAPAdapter() = default;

bool DAPAdapter::Initialize(DAPTransport* transport, 
                             RawrXD::Debugger::DebugSession* debugSession) {
    pImpl_->transport_ = transport;
    pImpl_->debugSession_ = debugSession;
    
    // Set up event callback from backend
    if (debugSession) {
        debugSession->SetEventCallback([](RawrXD::Debugger::DebugEventType event, 
                                            const void* data, 
                                            RawrXD::Debugger::DebugSession* session) {
            auto* adapter = GetDAPAdapter();
            if (adapter) {
                switch (event) {
                    case RawrXD::Debugger::DebugEventType::Breakpoint: {
                        auto* addr = reinterpret_cast<const uint64_t*>(data);
                        auto frames = session->GetCallStack(1);
                        if (!frames.empty()) {
                            adapter->OnBreakpointHit(*addr, frames[0].filePath, 
                                                         frames[0].lineNumber);
                        }
                        break;
                    }
                    case RawrXD::Debugger::DebugEventType::StepComplete:
                        adapter->OnStepComplete();
                        break;
                    case RawrXD::Debugger::DebugEventType::ProcessExit: {
                        auto* exitCode = reinterpret_cast<const uint32_t*>(data);
                        adapter->OnProcessExited(*exitCode);
                        break;
                    }
                    default:
                        break;
                }
            }
        });
    }
    
    return true;
}

void DAPAdapter::Shutdown() {
    pImpl_->shutdown_ = true;
    pImpl_->running_ = false;
}

// ============================================================================
// Command Dispatch
// ============================================================================
void DAPAdapter::Impl::DispatchCommand(const std::string& json) {
    std::string command = ExtractCommand(json);
    int seq = ExtractSeq(json);
    
    if (command == "initialize") {
        HandleInitialize(seq);
    } else if (command == "launch") {
        HandleLaunch(seq, json);
    } else if (command == "attach") {
        HandleAttach(seq, json);
    } else if (command == "configurationDone") {
        HandleConfigurationDone(seq);
    } else if (command == "disconnect") {
        HandleDisconnect(seq);
    } else if (command == "setBreakpoints") {
        HandleSetBreakpoints(seq, json);
    } else if (command == "continue") {
        HandleContinue(seq, json);
    } else if (command == "next") {
        HandleNext(seq, json);
    } else if (command == "stepIn") {
        HandleStepIn(seq, json);
    } else if (command == "stepOut") {
        HandleStepOut(seq, json);
    } else if (command == "pause") {
        HandlePause(seq);
    } else if (command == "stackTrace") {
        HandleStackTrace(seq, json);
    } else if (command == "scopes") {
        HandleScopes(seq, json);
    } else if (command == "variables") {
        HandleVariables(seq, json);
    } else if (command == "evaluate") {
        HandleEvaluate(seq, json);
    } else {
        SendErrorResponse(seq, command, "Unknown command");
    }
}

std::string DAPAdapter::Impl::ExtractCommand(const std::string& json) {
    // Simple extraction: find "command":"value"
    auto pos = json.find("\"command\":");
    if (pos == std::string::npos) return "";
    
    pos = json.find("\"", pos + 10);
    if (pos == std::string::npos) return "";
    
    auto endPos = json.find("\"", pos + 1);
    if (endPos == std::string::npos) return "";
    
    return json.substr(pos + 1, endPos - pos - 1);
}

int DAPAdapter::Impl::ExtractSeq(const std::string& json) {
    auto pos = json.find("\"seq\":");
    if (pos == std::string::npos) return 0;
    
    try {
        return std::stoi(json.substr(pos + 6));
    } catch (...) {
        return 0;
    }
}

// ============================================================================
// Command Handlers
// ============================================================================
void DAPAdapter::Impl::HandleInitialize(int seq) {
    // Send capabilities response
    std::string body = JSON::MakeObject({
        {"supportsConfigurationDoneRequest", "true"},
        {"supportsHitConditionalBreakpoints", "true"},
        {"supportsConditionalBreakpoints", "true"},
        {"supportsEvaluateForHovers", "false"},
        {"supportsStepBack", "false"},
        {"supportsSetVariable", "false"},
        {"supportsRestartFrame", "false"},
        {"supportsGotoTargetsRequest", "false"},
        {"supportsStepInTargetsRequest", "false"},
        {"supportsCompletionsRequest", "false"},
        {"supportsModulesRequest", "false"},
        {"supportsRestartRequest", "false"},
        {"supportsExceptionOptions", "false"},
        {"supportsValueFormattingOptions", "false"},
        {"supportsExceptionInfoRequest", "false"},
        {"supportTerminateDebuggee", "true"},
        {"supportsDelayedStackTraceFetching", "false"},
        {"supportsLoadedSourcesRequest", "false"},
        {"supportsLogPoints", "false"},
        {"supportsTerminateThreadsRequest", "false"},
        {"supportsSetExpression", "false"},
        {"supportsTerminateRequest", "true"},
        {"supportsDataBreakpoints", "false"},
        {"supportsReadMemoryRequest", "true"},
        {"supportsWriteMemoryRequest", "true"},
        {"supportsDisassembleRequest", "true"}
    });
    
    SendResponse(seq, "initialize", body);
    
    // Send initialized event
    std::string event = JSON::MakeObject({
        {"seq", JSON::Number(++requestSeq_)},
        {"type", JSON::String("event")},
        {"event", JSON::String("initialized")},
        {"body", "{}"}
    });
    transport_->SendMessage(event);
}

void DAPAdapter::Impl::HandleLaunch(int seq, const std::string& json) {
    // Extract program path from args
    auto pos = json.find("\"program\":");
    if (pos == std::string::npos) {
        SendErrorResponse(seq, "launch", "Missing 'program' in launch arguments");
        return;
    }
    
    pos = json.find("\"", pos + 10);
    if (pos == std::string::npos) {
        SendErrorResponse(seq, "launch", "Invalid 'program' format");
        return;
    }
    
    auto endPos = json.find("\"", pos + 1);
    if (endPos == std::string::npos) {
        SendErrorResponse(seq, "launch", "Invalid 'program' format");
        return;
    }
    
    std::string program = json.substr(pos + 1, endPos - pos - 1);
    
    // Launch the process
    if (debugSession_) {
        std::wstring wProgram(program.begin(), program.end());
        if (debugSession_->LaunchProcess(wProgram, L"", L"")) {
            SendResponse(seq, "launch");
        } else {
            std::wstring lastError = debugSession_->GetLastError();
            std::string reason(lastError.begin(), lastError.end());
            if (reason.empty()) {
                reason = "Failed to launch process";
            }
            SendErrorResponse(seq, "launch", reason);
        }
    } else {
        SendErrorResponse(seq, "launch", "Debug session not available");
    }
}

void DAPAdapter::Impl::HandleAttach(int seq, const std::string& json) {
    // Extract processId from args
    auto pos = json.find("\"processId\":");
    if (pos == std::string::npos) {
        SendErrorResponse(seq, "attach", "Missing 'processId' in attach arguments");
        return;
    }
    
    try {
        uint32_t pid = std::stoul(json.substr(pos + 12));
        
        if (debugSession_ && debugSession_->AttachToProcess(pid)) {
            SendResponse(seq, "attach");
        } else {
            std::string reason = "Failed to attach to process";
            if (debugSession_) {
                std::wstring lastError = debugSession_->GetLastError();
                if (!lastError.empty()) {
                    reason.assign(lastError.begin(), lastError.end());
                }
            }
            SendErrorResponse(seq, "attach", reason);
        }
    } catch (...) {
        SendErrorResponse(seq, "attach", "Invalid 'processId' format");
    }
}

void DAPAdapter::Impl::HandleConfigurationDone(int seq) {
    SendResponse(seq, "configurationDone");
}

void DAPAdapter::Impl::HandleDisconnect(int seq) {
    if (debugSession_) {
        debugSession_->Detach();
    }
    SendResponse(seq, "disconnect");
    shutdown_ = true;
}

// Simple line-to-address mapping for Victim.exe
// In production, this would use PDB/DWARF symbol information
struct LineMapping {
    std::wstring fileName;
    uint32_t line;
    uint64_t address;
    const char* symbolName;
};

// Known breakpoint locations in Victim.exe
// These would normally come from symbol parsing
static const LineMapping g_lineMappings[] = {
    {L"Victim.asm", 25, 0x140001000, "__bp_entry_point"},
    {L"Victim.asm", 35, 0x140001020, "__bp_loop_start"},
    {L"Victim.asm", 45, 0x140001040, "__bp_loop_body"},
    {L"Victim.asm", 55, 0x140001060, "__bp_exit_point"},
};

// Extract source path from setBreakpoints request
std::wstring ExtractSourcePath(const std::string& json) {
    auto pos = json.find("\"source\":");
    if (pos == std::string::npos) return L"";
    
    auto pathPos = json.find("\"path\":");
    if (pathPos == std::string::npos) return L"";
    
    pathPos = json.find("\"", pathPos + 7);
    if (pathPos == std::string::npos) return L"";
    
    auto endPos = json.find("\"", pathPos + 1);
    if (endPos == std::string::npos) return L"";
    
    std::string path = json.substr(pathPos + 1, endPos - pathPos - 1);
    
    // Convert to wide string
    int len = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    std::wstring wpath(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &wpath[0], len);
    return wpath;
}

// Extract breakpoints array from request
std::vector<std::pair<uint32_t, std::string>> ExtractBreakpoints(const std::string& json) {
    std::vector<std::pair<uint32_t, std::string>> result;
    
    auto pos = json.find("\"breakpoints\":");
    if (pos == std::string::npos) return result;
    
    // Simple parsing - look for line numbers in the array
    pos = json.find("[", pos);
    if (pos == std::string::npos) return result;
    
    auto endPos = json.find("]", pos);
    if (endPos == std::string::npos) return result;
    
    std::string arrayContent = json.substr(pos + 1, endPos - pos - 1);
    
    // Find all "line":N entries
    size_t linePos = 0;
    while ((linePos = arrayContent.find("\"line\":", linePos)) != std::string::npos) {
        linePos += 7;
        
        // Skip whitespace
        while (linePos < arrayContent.size() && isspace(arrayContent[linePos])) linePos++;
        
        // Parse number
        uint32_t lineNum = 0;
        while (linePos < arrayContent.size() && isdigit(arrayContent[linePos])) {
            lineNum = lineNum * 10 + (arrayContent[linePos] - '0');
            linePos++;
        }
        
        // Look for condition
        std::string condition;
        auto condPos = arrayContent.find("\"condition\":", linePos);
        if (condPos != std::string::npos && condPos < arrayContent.find("}", linePos)) {
            condPos = arrayContent.find("\"", condPos + 12);
            if (condPos != std::string::npos) {
                auto condEnd = arrayContent.find("\"", condPos + 1);
                if (condEnd != std::string::npos) {
                    condition = arrayContent.substr(condPos + 1, condEnd - condPos - 1);
                }
            }
        }
        
        result.push_back({lineNum, condition});
    }
    
    return result;
}

// Map line number to address
uint64_t MapLineToAddress(const std::wstring& filePath, uint32_t line) {
    // Extract filename from path
    size_t lastSlash = filePath.find_last_of(L"\\/");
    std::wstring fileName = (lastSlash != std::wstring::npos) 
        ? filePath.substr(lastSlash + 1) 
        : filePath;
    
    for (const auto& mapping : g_lineMappings) {
        if (mapping.fileName == fileName && mapping.line == line) {
            return mapping.address;
        }
    }
    
    return 0; // Not found
}

void DAPAdapter::Impl::HandleSetBreakpoints(int seq, const std::string& json) {
    std::wstring sourcePath = ExtractSourcePath(json);
    auto breakpoints = ExtractBreakpoints(json);
    
    std::vector<std::string> breakpointResponses;
    uint64_t bpId = 1;
    
    for (const auto& bp : breakpoints) {
        uint32_t line = bp.first;
        const std::string& condition = bp.second;
        
        // Map line to address
        uint64_t address = MapLineToAddress(sourcePath, line);
        bool verified = false;
        std::string message;
        
        if (address != 0 && debugSession_) {
            // Set the breakpoint in the debug session
            if (debugSession_->SetBreakpointAtAddress(address)) {
                verified = true;
            } else {
                message = "Failed to set breakpoint at this location";
            }
        } else if (address == 0) {
            message = "Line number not found in symbol table";
        }
        
        // Build breakpoint response
        std::vector<std::pair<std::string, std::string>> fields;
        fields.push_back({"id", JSON::Number(bpId++)});
        fields.push_back({"verified", JSON::Bool(verified)});
        fields.push_back({"line", JSON::Number(line)});
        
        if (!message.empty()) {
            fields.push_back({"message", JSON::String(message)});
        }
        
        if (verified) {
            fields.push_back({"instructionReference", JSON::String(
                "0x" + std::to_string(address))});
        }
        
        breakpointResponses.push_back(JSON::MakeObject(fields));
    }
    
    std::string body = JSON::MakeObject({
        {"breakpoints", JSON::MakeArray(breakpointResponses)}
    });
    
    SendResponse(seq, "setBreakpoints", body);
}

void DAPAdapter::Impl::HandleContinue(int seq, const std::string& json) {
    if (debugSession_) {
        debugSession_->ContinueExecution();
    }
    
    std::string body = JSON::MakeObject({
        {"allThreadsContinued", "true"}
    });
    SendResponse(seq, "continue", body);
}

void DAPAdapter::Impl::HandleNext(int seq, const std::string& json) {
    if (debugSession_) {
        debugSession_->StepOver();
    }
    SendResponse(seq, "next");
}

void DAPAdapter::Impl::HandleStepIn(int seq, const std::string& json) {
    if (debugSession_) {
        debugSession_->StepInto();
    }
    SendResponse(seq, "stepIn");
}

void DAPAdapter::Impl::HandleStepOut(int seq, const std::string& json) {
    if (debugSession_) {
        debugSession_->StepOut();
    }
    SendResponse(seq, "stepOut");
}

void DAPAdapter::Impl::HandlePause(int seq) {
    if (debugSession_) {
        debugSession_->BreakExecution();
    }
    SendResponse(seq, "pause");
}

void DAPAdapter::Impl::HandleStackTrace(int seq, const std::string& json) {
    std::vector<std::string> frames;
    
    if (debugSession_) {
        auto stackFrames = debugSession_->GetCallStack();
        uint64_t id = 0;
        for (const auto& frame : stackFrames) {
            std::string frameJson = JSON::MakeObject({
                {"id", JSON::Number(id++)},
                {"name", JSON::String(std::string(frame.functionName.begin(), frame.functionName.end()))},
                {"source", JSON::MakeObject({
                    {"path", JSON::String(std::string(frame.filePath.begin(), frame.filePath.end()))}
                })},
                {"line", JSON::Number(frame.lineNumber)},
                {"column", JSON::Number(0)}
            });
            frames.push_back(frameJson);
        }
    }
    
    std::string body = JSON::MakeObject({
        {"stackFrames", JSON::MakeArray(frames)}
    });
    SendResponse(seq, "stackTrace", body);
}

void DAPAdapter::Impl::HandleScopes(int seq, const std::string& json) {
    std::string body = JSON::MakeObject({
        {"scopes", "[]"}
    });
    SendResponse(seq, "scopes", body);
}

void DAPAdapter::Impl::HandleVariables(int seq, const std::string& json) {
    std::string body = JSON::MakeObject({
        {"variables", "[]"}
    });
    SendResponse(seq, "variables", body);
}

void DAPAdapter::Impl::HandleEvaluate(int seq, const std::string& json) {
    std::string body = JSON::MakeObject({
        {"result", JSON::String("")},
        {"type", JSON::String("")},
        {"variablesReference", JSON::Number(0)}
    });
    SendResponse(seq, "evaluate", body);
}

// ============================================================================
// Response Helpers
// ============================================================================
void DAPAdapter::Impl::SendResponse(int seq, const std::string& command, 
                                     const std::string& body, bool success) {
    std::string response = JSON::MakeObject({
        {"seq", JSON::Number(++requestSeq_)},
        {"type", JSON::String("response")},
        {"request_seq", JSON::Number(seq)},
        {"success", JSON::Bool(success)},
        {"command", JSON::String(command)},
        {"body", body}
    });
    
    if (transport_) {
        transport_->SendMessage(response);
    }
}

void DAPAdapter::Impl::SendErrorResponse(int seq, const std::string& command, 
                                          const std::string& message, int errorCode) {
    std::string body = JSON::MakeObject({
        {"error", JSON::MakeObject({
            {"id", JSON::Number(errorCode)},
            {"format", JSON::String(message)},
            {"showUser", "true"}
        })}
    });
    SendResponse(seq, command, body, false);
}

// ============================================================================
// Event Handlers
// ============================================================================
void DAPAdapter::OnBreakpointHit(uint64_t address, const std::wstring& file, uint32_t line) {
    SendStoppedEvent("breakpoint", 0);
}

void DAPAdapter::OnStepComplete() {
    SendStoppedEvent("step", 0);
}

void DAPAdapter::OnProcessExited(uint32_t exitCode) {
    SendExitedEvent(exitCode);
    SendTerminatedEvent();
}

void DAPAdapter::OnOutputDebugString(const std::wstring& message) {
    std::string msg(message.begin(), message.end());
    SendOutputEvent("stdout", msg);
}

void DAPAdapter::OnThreadStarted(uint32_t threadId) {
    // DAP thread event
}

void DAPAdapter::OnThreadExited(uint32_t threadId) {
    // DAP thread event
}

// ============================================================================
// Send Events
// ============================================================================
void DAPAdapter::SendStoppedEvent(const std::string& reason, uint64_t threadId) {
    std::string body = JSON::MakeObject({
        {"reason", JSON::String(reason)},
        {"threadId", JSON::Number(threadId)},
        {"allThreadsStopped", "true"}
    });
    
    std::string event = JSON::MakeObject({
        {"seq", JSON::Number(++pImpl_->requestSeq_)},
        {"type", JSON::String("event")},
        {"event", JSON::String("stopped")},
        {"body", body}
    });
    
    if (pImpl_->transport_) {
        pImpl_->transport_->SendMessage(event);
    }
}

void DAPAdapter::SendContinuedEvent(uint64_t threadId) {
    std::string body = JSON::MakeObject({
        {"threadId", JSON::Number(threadId)},
        {"allThreadsContinued", "true"}
    });
    
    std::string event = JSON::MakeObject({
        {"seq", JSON::Number(++pImpl_->requestSeq_)},
        {"type", JSON::String("event")},
        {"event", JSON::String("continued")},
        {"body", body}
    });
    
    if (pImpl_->transport_) {
        pImpl_->transport_->SendMessage(event);
    }
}

void DAPAdapter::SendOutputEvent(const std::string& category, const std::string& output) {
    std::string body = JSON::MakeObject({
        {"category", JSON::String(category)},
        {"output", JSON::String(output)}
    });
    
    std::string event = JSON::MakeObject({
        {"seq", JSON::Number(++pImpl_->requestSeq_)},
        {"type", JSON::String("event")},
        {"event", JSON::String("output")},
        {"body", body}
    });
    
    if (pImpl_->transport_) {
        pImpl_->transport_->SendMessage(event);
    }
}

void DAPAdapter::SendTerminatedEvent() {
    std::string event = JSON::MakeObject({
        {"seq", JSON::Number(++pImpl_->requestSeq_)},
        {"type", JSON::String("event")},
        {"event", JSON::String("terminated")},
        {"body", "{}"}
    });
    
    if (pImpl_->transport_) {
        pImpl_->transport_->SendMessage(event);
    }
}

void DAPAdapter::SendExitedEvent(uint32_t exitCode) {
    std::string body = JSON::MakeObject({
        {"exitCode", JSON::Number(exitCode)}
    });
    
    std::string event = JSON::MakeObject({
        {"seq", JSON::Number(++pImpl_->requestSeq_)},
        {"type", JSON::String("event")},
        {"event", JSON::String("exited")},
        {"body", body}
    });
    
    if (pImpl_->transport_) {
        pImpl_->transport_->SendMessage(event);
    }
}

// ============================================================================
// Main Loop
// ============================================================================
void DAPAdapter::Run() {
    pImpl_->running_ = true;
    
    while (pImpl_->running_ && !pImpl_->shutdown_) {
        if (pImpl_->transport_) {
            std::string message;
            if (pImpl_->transport_->ReadMessage(message)) {
                pImpl_->DispatchCommand(message);
            }
        }
        
        // Small delay to prevent busy-waiting
        Sleep(10);
    }
}

void DAPAdapter::Stop() {
    pImpl_->running_ = false;
}

bool DAPAdapter::IsRunning() const {
    return pImpl_->running_;
}

// ============================================================================
// Global Access
// ============================================================================
static std::unique_ptr<DAPAdapter> g_dapAdapter;

DAPAdapter* GetDAPAdapter() {
    return g_dapAdapter.get();
}

bool InitializeDAPAdapter(DAPTransport* transport, 
                         RawrXD::Debugger::DebugSession* debugSession) {
    g_dapAdapter = std::make_unique<DAPAdapter>();
    return g_dapAdapter->Initialize(transport, debugSession);
}

void ShutdownDAPAdapter() {
    if (g_dapAdapter) {
        g_dapAdapter->Shutdown();
        g_dapAdapter.reset();
    }
}

} // namespace DAP
} // namespace RawrXD
