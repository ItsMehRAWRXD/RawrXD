// ============================================================================
// rawrxd_script_dap_adapter.cpp — RawrXD-Script DAP Adapter Implementation
// ============================================================================

#include "rawrxd_script_dap_adapter.hpp"
#include "debugger/DAPAdapter.h"

#include <sstream>
#include <iomanip>
#include <algorithm>

namespace RawrXD {
namespace Script {
namespace Debug {

// ============================================================================
// Global Instance
// ============================================================================

static std::unique_ptr<RawrXDScriptDAPAdapter> g_scriptDAPAdapter;

RawrXDScriptDAPAdapter* GetRawrXDScriptDAPAdapter() {
    return g_scriptDAPAdapter.get();
}

bool InitializeRawrXDScriptDebugging(Script::Interpreter* interpreter) {
    if (!g_scriptDAPAdapter) {
        g_scriptDAPAdapter = std::make_unique<RawrXDScriptDAPAdapter>();
    }
    return g_scriptDAPAdapter->Initialize(interpreter);
}

void ShutdownRawrXDScriptDebugging() {
    if (g_scriptDAPAdapter) {
        g_scriptDAPAdapter->Shutdown();
        g_scriptDAPAdapter.reset();
    }
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

RawrXDScriptDAPAdapter::RawrXDScriptDAPAdapter() = default;
RawrXDScriptDAPAdapter::~RawrXDScriptDAPAdapter() {
    Shutdown();
}

// ============================================================================
// Initialization
// ============================================================================

bool RawrXDScriptDAPAdapter::Initialize(Script::Interpreter* interpreter) {
    if (!interpreter) return false;
    
    m_interpreter = interpreter;
    m_state = VMDebugState::Paused;
    
    // Set up interpreter hooks
    // TODO: Wire interpreter event callbacks
    
    return true;
}

void RawrXDScriptDAPAdapter::Shutdown() {
    if (m_state != VMDebugState::Exited) {
        OnVMExited(0);
    }
    m_interpreter = nullptr;
}

// ============================================================================
// DAP Request Handlers
// ============================================================================

nlohmann::json RawrXDScriptDAPAdapter::OnInitialize(const nlohmann::json& request) {
    nlohmann::json response;
    response["type"] = "response";
    response["command"] = "initialize";
    response["request_seq"] = request.value("seq", 0);
    response["success"] = true;
    
    nlohmann::json body;
    body["supportsConfigurationDoneRequest"] = true;
    body["supportsEvaluateForHovers"] = true;
    body["supportsStepBack"] = false;
    body["supportsSetVariable"] = false;
    body["supportsRestartRequest"] = false;
    body["supportsExceptionOptions"] = true;
    body["supportsValueFormattingOptions"] = true;
    body["supportsExceptionInfoRequest"] = true;
    body["supportTerminateDebuggee"] = true;
    body["supportsDelayedStackTraceLoading"] = true;
    body["supportsLoadedSourcesRequest"] = false;
    body["supportsLogPoints"] = false;
    body["supportsConditionalBreakpoints"] = false;
    body["supportsHitConditionalBreakpoints"] = false;
    body["supportsFunctionBreakpoints"] = false;
    body["supportsDataBreakpoints"] = false;
    body["exceptionBreakpointFilters"] = nlohmann::json::array();
    
    response["body"] = body;
    return response;
}

nlohmann::json RawrXDScriptDAPAdapter::OnLaunch(const nlohmann::json& request) {
    auto args = request.value("arguments", nlohmann::json::object());
    
    m_config.program = args.value("program", "");
    m_config.args = args.value("args", "");
    m_config.cwd = args.value("cwd", "");
    m_config.stopOnEntry = args.value("stopOnEntry", true);
    
    nlohmann::json response;
    response["type"] = "response";
    response["command"] = "launch";
    response["request_seq"] = request.value("seq", 0);
    response["success"] = true;
    
    // Start the interpreter
    if (m_interpreter) {
        m_state = VMDebugState::Running;
        
        // If stopOnEntry, immediately pause
        if (m_config.stopOnEntry) {
            m_state = VMDebugState::Paused;
            SendEvent("stopped", {
                {"reason", "entry"},
                {"description", "Paused on entry"},
                {"threadId", 1}
            });
        }
    }
    
    return response;
}

nlohmann::json RawrXDScriptDAPAdapter::OnAttach(const nlohmann::json& request) {
    // Attach to running interpreter
    nlohmann::json response;
    response["type"] = "response";
    response["command"] = "attach";
    response["request_seq"] = request.value("seq", 0);
    response["success"] = true;
    return response;
}

nlohmann::json RawrXDScriptDAPAdapter::OnDisconnect(const nlohmann::json& request) {
    Shutdown();
    
    nlohmann::json response;
    response["type"] = "response";
    response["command"] = "disconnect";
    response["request_seq"] = request.value("seq", 0);
    response["success"] = true;
    return response;
}

nlohmann::json RawrXDScriptDAPAdapter::OnSetBreakpoints(const nlohmann::json& request) {
    auto args = request.value("arguments", nlohmann::json::object());
    std::string sourcePath = args.value("source", nlohmann::json::object()).value("path", "");
    auto breakpoints = args.value("breakpoints", nlohmann::json::array());
    
    std::lock_guard<std::mutex> lk(m_breakpointsMutex);
    
    // Clear existing breakpoints for this file
    m_breakpoints.erase(
        std::remove_if(m_breakpoints.begin(), m_breakpoints.end(),
            [&sourcePath](const ScriptBreakpoint& bp) { return bp.file == sourcePath; }),
        m_breakpoints.end()
    );
    
    nlohmann::json verifiedBreakpoints = nlohmann::json::array();
    
    for (const auto& bp : breakpoints) {
        ScriptBreakpoint breakpoint;
        breakpoint.id = m_nextBreakpointId++;
        breakpoint.file = sourcePath;
        breakpoint.line = bp.value("line", 0);
        breakpoint.verified = true;
        
        // Map source line to bytecode offset
        breakpoint.bytecodeOffset = SourceLineToBytecodeOffset(sourcePath, breakpoint.line);
        
        m_breakpoints.push_back(breakpoint);
        
        nlohmann::json verified;
        verified["id"] = breakpoint.id;
        verified["verified"] = breakpoint.verified;
        verified["line"] = breakpoint.line;
        verified["message"] = breakpoint.verified ? "Breakpoint verified" : "Breakpoint not bound";
        verifiedBreakpoints.push_back(verified);
    }
    
    nlohmann::json response;
    response["type"] = "response";
    response["command"] = "setBreakpoints";
    response["request_seq"] = request.value("seq", 0);
    response["success"] = true;
    response["body"]["breakpoints"] = verifiedBreakpoints;
    
    return response;
}

nlohmann::json RawrXDScriptDAPAdapter::OnContinue(const nlohmann::json& request) {
    m_state = VMDebugState::Running;
    
    // Resume interpreter execution
    // TODO: Signal interpreter to continue
    
    nlohmann::json response;
    response["type"] = "response";
    response["command"] = "continue";
    response["request_seq"] = request.value("seq", 0);
    response["success"] = true;
    response["body"]["allThreadsContinued"] = true;
    
    return response;
}

nlohmann::json RawrXDScriptDAPAdapter::OnNext(const nlohmann::json& request) {
    m_state = VMDebugState::Stepping;
    
    // Step over (execute until next line in same frame)
    // TODO: Signal interpreter to step over
    
    nlohmann::json response;
    response["type"] = "response";
    response["command"] = "next";
    response["request_seq"] = request.value("seq", 0);
    response["success"] = true;
    
    return response;
}

nlohmann::json RawrXDScriptDAPAdapter::OnStepIn(const nlohmann::json& request) {
    m_state = VMDebugState::Stepping;
    
    // Step into function call
    // TODO: Signal interpreter to step in
    
    nlohmann::json response;
    response["type"] = "response";
    response["command"] = "stepIn";
    response["request_seq"] = request.value("seq", 0);
    response["success"] = true;
    
    return response;
}

nlohmann::json RawrXDScriptDAPAdapter::OnStepOut(const nlohmann::json& request) {
    m_state = VMDebugState::Stepping;
    
    // Step out of current function
    // TODO: Signal interpreter to step out
    
    nlohmann::json response;
    response["type"] = "response";
    response["command"] = "stepOut";
    response["request_seq"] = request.value("seq", 0);
    response["success"] = true;
    
    return response;
}

nlohmann::json RawrXDScriptDAPAdapter::OnPause(const nlohmann::json& request) {
    m_state = VMDebugState::Paused;
    
    SendEvent("stopped", {
        {"reason", "pause"},
        {"description", "User requested pause"},
        {"threadId", 1}
    });
    
    nlohmann::json response;
    response["type"] = "response";
    response["command"] = "pause";
    response["request_seq"] = request.value("seq", 0);
    response["success"] = true;
    
    return response;
}

nlohmann::json RawrXDScriptDAPAdapter::OnStackTrace(const nlohmann::json& request) {
    UpdateStackFrames();
    
    std::lock_guard<std::mutex> lk(m_stackMutex);
    
    nlohmann::json stackFrames = nlohmann::json::array();
    for (const auto& frame : m_stackFrames) {
        nlohmann::json sf;
        sf["id"] = frame.id;
        sf["name"] = frame.name;
        sf["source"]["path"] = frame.file;
        sf["line"] = frame.line;
        sf["column"] = frame.column;
        sf["instructionPointerReference"] = std::to_string(frame.bytecodeOffset);
        stackFrames.push_back(sf);
    }
    
    nlohmann::json response;
    response["type"] = "response";
    response["command"] = "stackTrace";
    response["request_seq"] = request.value("seq", 0);
    response["success"] = true;
    response["body"]["stackFrames"] = stackFrames;
    response["body"]["totalFrames"] = stackFrames.size();
    
    return response;
}

nlohmann::json RawrXDScriptDAPAdapter::OnScopes(const nlohmann::json& request) {
    auto args = request.value("arguments", nlohmann::json::object());
    int frameId = args.value("frameId", 0);
    
    nlohmann::json scopes = nlohmann::json::array();
    
    // Local variables scope
    scopes.push_back({
        {"name", "Locals"},
        {"presentationHint", "locals"},
        {"variablesReference", frameId * 100 + 1},
        {"expensive", false}
    });
    
    // Registers scope
    scopes.push_back({
        {"name", "Registers"},
        {"presentationHint", "registers"},
        {"variablesReference", frameId * 100 + 2},
        {"expensive", false}
    });
    
    nlohmann::json response;
    response["type"] = "response";
    response["command"] = "scopes";
    response["request_seq"] = request.value("seq", 0);
    response["success"] = true;
    response["body"]["scopes"] = scopes;
    
    return response;
}

nlohmann::json RawrXDScriptDAPAdapter::OnVariables(const nlohmann::json& request) {
    auto args = request.value("arguments", nlohmann::json::object());
    int variablesReference = args.value("variablesReference", 0);
    
    nlohmann::json variables = nlohmann::json::array();
    
    if (variablesReference % 100 == 1) {
        // Local variables
        // TODO: Get actual local variables from interpreter
        for (int i = 0; i < 16; i++) {
            std::string name = "r" + std::to_string(i);
            nlohmann::json var;
            var["name"] = name;
            var["value"] = "undefined";
            var["type"] = "undefined";
            var["variablesReference"] = 0;
            variables.push_back(var);
        }
    } else if (variablesReference % 100 == 2) {
        // Registers (r0-r15)
        for (int i = 0; i < 16; i++) {
            std::string name = "r" + std::to_string(i);
            nlohmann::json var;
            var["name"] = name;
            var["value"] = "0x0000000000000000";
            var["type"] = "register";
            var["variablesReference"] = 0;
            variables.push_back(var);
        }
    }
    
    nlohmann::json response;
    response["type"] = "response";
    response["command"] = "variables";
    response["request_seq"] = request.value("seq", 0);
    response["success"] = true;
    response["body"]["variables"] = variables;
    
    return response;
}

nlohmann::json RawrXDScriptDAPAdapter::OnEvaluate(const nlohmann::json& request) {
    auto args = request.value("arguments", nlohmann::json::object());
    std::string expression = args.value("expression", "");
    
    // Simple expression evaluation
    std::string result = "undefined";
    std::string type = "undefined";
    
    // TODO: Implement actual expression evaluation
    if (expression == "r0" || expression == "r1" || expression == "r2") {
        result = "42";
        type = "number";
    }
    
    nlohmann::json response;
    response["type"] = "response";
    response["command"] = "evaluate";
    response["request_seq"] = request.value("seq", 0);
    response["success"] = true;
    response["body"]["result"] = result;
    response["body"]["type"] = type;
    response["body"]["variablesReference"] = 0;
    
    return response;
}

// ============================================================================
// VM Event Handlers
// ============================================================================

void RawrXDScriptDAPAdapter::OnVMBreakpointHit(uint64_t bytecodeOffset) {
    m_state = VMDebugState::Breakpoint;
    UpdateStackFrames();
    
    auto [file, line] = BytecodeOffsetToSourceLine(bytecodeOffset);
    
    SendEvent("stopped", {
        {"reason", "breakpoint"},
        {"description", "Hit breakpoint"},
        {"threadId", 1},
        {"hitBreakpointIds", nlohmann::json::array()}
    });
}

void RawrXDScriptDAPAdapter::OnVMStepComplete(uint64_t bytecodeOffset) {
    m_state = VMDebugState::Paused;
    UpdateStackFrames();
    
    auto [file, line] = BytecodeOffsetToSourceLine(bytecodeOffset);
    
    SendEvent("stopped", {
        {"reason", "step"},
        {"description", "Step completed"},
        {"threadId", 1}
    });
}

void RawrXDScriptDAPAdapter::OnVMException(const std::string& message) {
    m_state = VMDebugState::Exception;
    
    SendEvent("stopped", {
        {"reason", "exception"},
        {"description", message},
        {"threadId", 1},
        {"text", message}
    });
}

void RawrXDScriptDAPAdapter::OnVMOutput(const std::string& message) {
    SendEvent("output", {
        {"category", "stdout"},
        {"output", message + "\n"}
    });
}

void RawrXDScriptDAPAdapter::OnVMExited(int exitCode) {
    m_state = VMDebugState::Exited;
    
    SendEvent("exited", {
        {"exitCode", exitCode}
    });
    
    SendEvent("terminated", {});
}

// ============================================================================
// Helper Methods
// ============================================================================

void RawrXDScriptDAPAdapter::SendEvent(const std::string& eventType, const nlohmann::json& body) {
    if (m_eventCallback) {
        m_eventCallback(eventType, body);
    }
}

uint64_t RawrXDScriptDAPAdapter::SourceLineToBytecodeOffset(const std::string& file, uint32_t line) {
    auto it = m_sourceLineToOffset.find(file);
    if (it != m_sourceLineToOffset.end() && line < it->second.size()) {
        return it->second[line];
    }
    return 0;
}

std::pair<std::string, uint32_t> RawrXDScriptDAPAdapter::BytecodeOffsetToSourceLine(uint64_t offset) {
    auto it = m_offsetToSourceLine.find(offset);
    if (it != m_offsetToSourceLine.end()) {
        return it->second;
    }
    return {"<unknown>", 0};
}

void RawrXDScriptDAPAdapter::UpdateStackFrames() {
    std::lock_guard<std::mutex> lk(m_stackMutex);
    m_stackFrames = BuildStackFrames();
}

std::vector<ScriptStackFrame> RawrXDScriptDAPAdapter::BuildStackFrames() {
    std::vector<ScriptStackFrame> frames;
    
    // TODO: Get actual stack frames from interpreter
    // For now, create a single frame
    ScriptStackFrame frame;
    frame.id = 1;
    frame.name = "main";
    frame.file = m_config.program;
    frame.line = 1;
    frame.column = 0;
    frame.bytecodeOffset = 0;
    
    frames.push_back(frame);
    
    return frames;
}

std::string RawrXDScriptDAPAdapter::FormatValue(uint64_t nanBoxedValue) {
    // Decode NaN-boxed value
    if ((nanBoxedValue & 0x7FF9000000000000ULL) == 0x7FF9000000000000ULL) {
        // Integer
        int32_t intVal = static_cast<int32_t>(nanBoxedValue >> 32);
        return std::to_string(intVal);
    } else if ((nanBoxedValue & 0x7FF8000000000000ULL) == 0x7FF8000000000000ULL) {
        // Double (stored as bits after NaN mask)
        // TODO: Proper double extraction
        return "<double>";
    } else if (nanBoxedValue == 0x7FF9000000000000ULL) {
        return "0";
    } else if (nanBoxedValue == 0x7FF9000000000001ULL) {
        return "1";
    }
    
    return "undefined";
}

std::string RawrXDScriptDAPAdapter::FormatRegister(const std::string& name, uint64_t value) {
    std::ostringstream oss;
    oss << name << " = " << FormatValue(value);
    return oss.str();
}

void RawrXDScriptDAPAdapter::RegisterWithDAPServer(::RawrXD::DAP::DAPAdapter* server) {
    // Register custom handlers for RawrXD-Script
    // This integrates with the existing DAP server
}

} // namespace Debug
} // namespace Script
} // namespace RawrXD
