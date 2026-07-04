// RawrXDScriptDAPAdapter.cpp
// Debug Adapter Protocol implementation for RawrXD-Script JavaScript Engine
// ============================================================================

#include "RawrXDScriptDAPAdapter.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace RawrXD {
namespace Script {
namespace Debugger {

// ============================================================================
// JSON Helpers Implementation
// ============================================================================
namespace JSON {

std::string Escape(const std::string& s) {
    std::string r;
    for (char c : s) {
        switch (c) {
            case '"': r += "\\\""; break;
            case '\\': r += "\\\\"; break;
            case '\b': r += "\\b"; break;
            case '\f': r += "\\f"; break;
            case '\n': r += "\\n"; break;
            case '\r': r += "\\r"; break;
            case '\t': r += "\\t"; break;
            default: r += c;
        }
    }
    return r;
}

std::string String(const std::string& s) { return "\"" + Escape(s) + "\""; }
std::string Number(int n) { return std::to_string(n); }
std::string Number(uint32_t n) { return std::to_string(n); }
std::string Number(uint64_t n) { return std::to_string(n); }
std::string Bool(bool b) { return b ? "true" : "false"; }
std::string Null() { return "null"; }

std::string Object(const std::vector<std::pair<std::string,std::string>>& pairs) {
    std::string r = "{";
    for (size_t i = 0; i < pairs.size(); ++i) {
        if (i) r += ",";
        r += "\"" + pairs[i].first + "\":" + pairs[i].second;
    }
    r += "}";
    return r;
}

std::string Array(const std::vector<std::string>& items) {
    std::string r = "[";
    for (size_t i = 0; i < items.size(); ++i) {
        if (i) r += ",";
        r += items[i];
    }
    r += "]";
    return r;
}

} // namespace JSON

// ============================================================================
// Opcode Definitions
// ============================================================================
namespace Opcodes {

const char* GetMnemonic(uint8_t opcode) {
    switch (opcode) {
        case OP_LOAD_CONST: return "LOAD_CONST";
        case OP_LOAD_INT: return "LOAD_INT";
        case OP_LOAD_STRING: return "LOAD_STRING";
        case OP_LOAD_NULL: return "LOAD_NULL";
        case OP_LOAD_BOOL: return "LOAD_BOOL";
        case OP_LOAD_ZERO: return "LOAD_ZERO";
        case OP_LOAD_ONE: return "LOAD_ONE";
        case OP_ADD: return "ADD";
        case OP_SUB: return "SUB";
        case OP_MUL: return "MUL";
        case OP_DIV: return "DIV";
        case OP_MOD: return "MOD";
        case OP_NEG: return "NEG";
        case OP_INC: return "INC";
        case OP_DEC: return "DEC";
        case OP_BIT_AND: return "BIT_AND";
        case OP_BIT_OR: return "BIT_OR";
        case OP_BIT_XOR: return "BIT_XOR";
        case OP_BIT_NOT: return "BIT_NOT";
        case OP_SHL: return "SHL";
        case OP_SHR: return "SHR";
        case OP_SHR_U: return "SHR_U";
        case OP_EQ: return "EQ";
        case OP_NEQ: return "NEQ";
        case OP_LT: return "LT";
        case OP_LTE: return "LTE";
        case OP_GT: return "GT";
        case OP_GTE: return "GTE";
        case OP_STRICT_EQ: return "STRICT_EQ";
        case OP_STRICT_NEQ: return "STRICT_NEQ";
        case OP_JMP: return "JMP";
        case OP_JMP_COND: return "JMP_COND";
        case OP_JMP_NOT_COND: return "JMP_NOT_COND";
        case OP_CALL: return "CALL";
        case OP_RETURN: return "RETURN";
        case OP_GET_PROP: return "GET_PROP";
        case OP_SET_PROP: return "SET_PROP";
        case OP_GET_ELEM: return "GET_ELEM";
        case OP_SET_ELEM: return "SET_ELEM";
        case OP_CREATE_OBJECT: return "CREATE_OBJECT";
        case OP_CREATE_ARRAY: return "CREATE_ARRAY";
        case OP_NOP: return "NOP";
        case OP_DEBUG_BREAK: return "DEBUG_BREAK";
        case OP_DEBUG_LOG: return "DEBUG_LOG";
        default: return "UNKNOWN";
    }
}

const char* GetDescription(uint8_t opcode) {
    switch (opcode) {
        case OP_LOAD_CONST: return "Load constant from pool";
        case OP_LOAD_INT: return "Load immediate integer";
        case OP_LOAD_STRING: return "Load string from table";
        case OP_LOAD_NULL: return "Load null value";
        case OP_LOAD_BOOL: return "Load boolean value";
        case OP_LOAD_ZERO: return "Load integer 0";
        case OP_LOAD_ONE: return "Load integer 1";
        case OP_ADD: return "Add two values";
        case OP_SUB: return "Subtract two values";
        case OP_MUL: return "Multiply two values";
        case OP_DIV: return "Divide two values";
        case OP_MOD: return "Modulo operation";
        case OP_NEG: return "Negate value";
        case OP_INC: return "Increment by 1";
        case OP_DEC: return "Decrement by 1";
        case OP_EQ: return "Loose equality comparison";
        case OP_NEQ: return "Loose inequality comparison";
        case OP_LT: return "Less than comparison";
        case OP_LTE: return "Less than or equal comparison";
        case OP_GT: return "Greater than comparison";
        case OP_GTE: return "Greater than or equal comparison";
        case OP_STRICT_EQ: return "Strict equality comparison";
        case OP_STRICT_NEQ: return "Strict inequality comparison";
        case OP_JMP: return "Unconditional jump";
        case OP_JMP_COND: return "Conditional jump (truthy)";
        case OP_JMP_NOT_COND: return "Conditional jump (falsy)";
        case OP_CALL: return "Function call";
        case OP_RETURN: return "Return from function";
        case OP_GET_PROP: return "Get object property";
        case OP_SET_PROP: return "Set object property";
        case OP_GET_ELEM: return "Get array element";
        case OP_SET_ELEM: return "Set array element";
        case OP_CREATE_OBJECT: return "Create empty object";
        case OP_CREATE_ARRAY: return "Create empty array";
        case OP_NOP: return "No operation";
        case OP_DEBUG_BREAK: return "Breakpoint";
        case OP_DEBUG_LOG: return "Debug log";
        default: return "Unknown opcode";
    }
}

} // namespace Opcodes

// ============================================================================
// Implementation Class
// ============================================================================
class RawrXDScriptDAPAdapter::Impl {
public:
    EventCallback eventCallback_;
    void* vmContext_ = nullptr;
    
    // State
    std::atomic<bool> running_{false};
    std::atomic<bool> shutdown_{false};
    std::atomic<bool> paused_{false};
    VMCommand pendingCommand_ = VMCommand::Continue;
    
    // Breakpoints
    std::map<uint32_t, ScriptBreakpoint> breakpoints_;
    uint32_t nextBreakpointId_ = 1;
    mutable std::mutex breakpointMutex_;
    
    // Source maps
    std::map<std::string, std::vector<SourceMapEntry>> sourceMaps_;
    mutable std::mutex sourceMapMutex_;
    
    // VM state cache
    VMRegisterState cachedState_;
    mutable std::mutex stateMutex_;
    
    // Call stack
    std::vector<ScriptStackFrame> callStack_;
    mutable std::mutex stackMutex_;
    
    // Variable scopes
    std::map<VariableScope, std::vector<ScriptVariable>> variables_;
    mutable std::mutex varMutex_;
    
    // Helpers
    uint32_t ResolveLineToBytecode(const std::string& file, uint32_t line);
    SourceMapEntry* FindSourceMapEntry(uint32_t bytecodeOffset);
    void UpdateCachedState();
};

// ============================================================================
// Constructor / Destructor
// ============================================================================
RawrXDScriptDAPAdapter::RawrXDScriptDAPAdapter() : pImpl_(std::make_unique<Impl>()) {}
RawrXDScriptDAPAdapter::~RawrXDScriptDAPAdapter() = default;

// ============================================================================
// Initialization
// ============================================================================
bool RawrXDScriptDAPAdapter::Initialize(EventCallback eventCallback) {
    pImpl_->eventCallback_ = eventCallback;
    pImpl_->running_ = true;
    return true;
}

void RawrXDScriptDAPAdapter::Shutdown() {
    pImpl_->shutdown_ = true;
    pImpl_->running_ = false;
}

// ============================================================================
// Source Map Management
// ============================================================================
void RawrXDScriptDAPAdapter::LoadSourceMap(const std::string& file, 
                                              const std::vector<SourceMapEntry>& entries) {
    std::lock_guard<std::mutex> lock(pImpl_->sourceMapMutex_);
    pImpl_->sourceMaps_[file] = entries;
}

void RawrXDScriptDAPAdapter::ClearSourceMap() {
    std::lock_guard<std::mutex> lock(pImpl_->sourceMapMutex_);
    pImpl_->sourceMaps_.clear();
}

// ============================================================================
// Breakpoint Management
// ============================================================================
uint32_t RawrXDScriptDAPAdapter::SetBreakpoint(const std::string& file, uint32_t line, uint32_t column) {
    std::lock_guard<std::mutex> lock(pImpl_->breakpointMutex_);
    
    ScriptBreakpoint bp;
    bp.id = pImpl_->nextBreakpointId_++;
    bp.file = file;
    bp.line = line;
    bp.column = column;
    bp.bytecodeOffset = pImpl_->ResolveLineToBytecode(file, line);
    bp.verified = (bp.bytecodeOffset != 0xFFFFFFFF);
    bp.enabled = true;
    
    pImpl_->breakpoints_[bp.id] = bp;
    return bp.id;
}

bool RawrXDScriptDAPAdapter::RemoveBreakpoint(uint32_t breakpointId) {
    std::lock_guard<std::mutex> lock(pImpl_->breakpointMutex_);
    auto it = pImpl_->breakpoints_.find(breakpointId);
    if (it != pImpl_->breakpoints_.end()) {
        pImpl_->breakpoints_.erase(it);
        return true;
    }
    return false;
}

void RawrXDScriptDAPAdapter::ClearAllBreakpoints() {
    std::lock_guard<std::mutex> lock(pImpl_->breakpointMutex_);
    pImpl_->breakpoints_.clear();
}

std::vector<ScriptBreakpoint> RawrXDScriptDAPAdapter::GetBreakpoints() const {
    std::lock_guard<std::mutex> lock(pImpl_->breakpointMutex_);
    std::vector<ScriptBreakpoint> result;
    for (const auto& pair : pImpl_->breakpoints_) {
        result.push_back(pair.second);
    }
    return result;
}

// ============================================================================
// VM Control
// ============================================================================
void RawrXDScriptDAPAdapter::AttachToVM(void* vmContext) {
    pImpl_->vmContext_ = vmContext;
}

void RawrXDScriptDAPAdapter::DetachFromVM() {
    pImpl_->vmContext_ = nullptr;
}

void RawrXDScriptDAPAdapter::SendCommand(VMCommand cmd) {
    pImpl_->pendingCommand_ = cmd;
    pImpl_->paused_ = false;
}

// ============================================================================
// State Queries
// ============================================================================
VMRegisterState RawrXDScriptDAPAdapter::GetRegisterState() const {
    std::lock_guard<std::mutex> lock(pImpl_->stateMutex_);
    return pImpl_->cachedState_;
}

std::vector<ScriptStackFrame> RawrXDScriptDAPAdapter::GetCallStack() const {
    std::lock_guard<std::mutex> lock(pImpl_->stackMutex_);
    return pImpl_->callStack_;
}

std::vector<ScriptVariable> RawrXDScriptDAPAdapter::GetVariables(VariableScope scope) const {
    std::lock_guard<std::mutex> lock(pImpl_->varMutex_);
    auto it = pImpl_->variables_.find(scope);
    if (it != pImpl_->variables_.end()) {
        return it->second;
    }
    return {};
}

std::vector<ScriptVariable> RawrXDScriptDAPAdapter::GetRegisters() const {
    std::vector<ScriptVariable> regs;
    std::lock_guard<std::mutex> lock(pImpl_->stateMutex_);
    
    for (int i = 0; i < 16; ++i) {
        ScriptVariable var;
        var.name = "r" + std::to_string(i);
        var.type = "NaN-boxed";
        
        uint64_t val = pImpl_->cachedState_.r[i];
        std::stringstream ss;
        ss << "0x" << std::hex << std::setfill('0') << std::setw(16) << val;
        
        // Decode NaN-boxed value
        if ((val & 0x7FF9000000000000ULL) == 0x7FF9000000000000ULL) {
            int32_t intVal = static_cast<int32_t>(val >> 32);
            ss << " (int: " << intVal << ")";
        } else if ((val & 0x7FF8000000000000ULL) == 0x7FF8000000000000ULL) {
            double dblVal = *reinterpret_cast<double*>(&val);
            ss << " (double: " << dblVal << ")";
        }
        
        var.value = ss.str();
        var.scope = VariableScope::Register;
        var.registerIndex = i;
        regs.push_back(var);
    }
    
    return regs;
}

BytecodeInstruction RawrXDScriptDAPAdapter::DisassembleAtPC() const {
    BytecodeInstruction inst;
    std::lock_guard<std::mutex> lock(pImpl_->stateMutex_);
    
    uint64_t pc = pImpl_->cachedState_.pc;
    if (pImpl_->vmContext_ && pc < 0x10000) {
        // Read bytecode from VM context
        uint8_t* code = static_cast<uint8_t*>(pImpl_->vmContext_);
        inst.opcode = code[pc];
        inst.dest = code[pc + 1] & 0x0F;
        inst.srcA = (code[pc + 2] >> 4) & 0x0F;
        inst.srcB = code[pc + 2] & 0x0F;
        inst.offset = static_cast<uint32_t>(pc);
        inst.mnemonic = Opcodes::GetMnemonic(inst.opcode);
        inst.description = Opcodes::GetDescription(inst.opcode);
    }
    
    return inst;
}

// ============================================================================
// Execution Events
// ============================================================================
void RawrXDScriptDAPAdapter::OnBreakpointHit(uint32_t bytecodeOffset) {
    pImpl_->paused_ = true;
    pImpl_->UpdateCachedState();
    
    if (pImpl_->eventCallback_) {
        pImpl_->eventCallback_("stopped", GenerateStoppedEvent("breakpoint", 1));
    }
}

void RawrXDScriptDAPAdapter::OnStepComplete(uint32_t bytecodeOffset) {
    pImpl_->paused_ = true;
    pImpl_->UpdateCachedState();
    
    if (pImpl_->eventCallback_) {
        pImpl_->eventCallback_("stopped", GenerateStoppedEvent("step", 1));
    }
}

void RawrXDScriptDAPAdapter::OnException(const std::string& message) {
    pImpl_->paused_ = true;
    
    if (pImpl_->eventCallback_) {
        std::string body = JSON::Object({
            {"reason", JSON::String("exception")},
            {"threadId", JSON::Number(1)},
            {"text", JSON::String(message)}
        });
        pImpl_->eventCallback_("stopped", body);
    }
}

void RawrXDScriptDAPAdapter::OnVMTerminated() {
    if (pImpl_->eventCallback_) {
        pImpl_->eventCallback_("terminated", GenerateTerminatedEvent());
    }
}

// ============================================================================
// DAP Request Handlers
// ============================================================================
std::string RawrXDScriptDAPAdapter::HandleInitializeRequest(int seq) {
    std::string body = JSON::Object({
        {"supportsConfigurationDoneRequest", JSON::Bool(true)},
        {"supportsHitConditionalBreakpoints", JSON::Bool(false)},
        {"supportsConditionalBreakpoints", JSON::Bool(false)},
        {"supportsEvaluateForHovers", JSON::Bool(true)},
        {"supportsStepBack", JSON::Bool(false)},
        {"supportsSetVariable", JSON::Bool(false)},
        {"supportsRestartFrame", JSON::Bool(false)},
        {"supportsGotoTargetsRequest", JSON::Bool(false)},
        {"supportsStepInTargetsRequest", JSON::Bool(false)},
        {"supportsCompletionsRequest", JSON::Bool(true)},
        {"supportsModulesRequest", JSON::Bool(false)},
        {"supportsRestartRequest", JSON::Bool(false)},
        {"supportsExceptionOptions", JSON::Bool(false)},
        {"supportsValueFormattingOptions", JSON::Bool(true)},
        {"supportsExceptionInfoRequest", JSON::Bool(true)},
        {"supportTerminateDebuggee", JSON::Bool(true)},
        {"supportsDelayedStackTraceLoading", JSON::Bool(false)},
        {"supportsLoadedSourcesRequest", JSON::Bool(false)},
        {"supportsLogPoints", JSON::Bool(false)},
        {"supportsTerminateThreadsRequest", JSON::Bool(false)},
        {"supportsSetExpression", JSON::Bool(false)},
        {"supportsTerminateRequest", JSON::Bool(true)},
        {"supportsDataBreakpoints", JSON::Bool(false)},
        {"supportsReadMemoryRequest", JSON::Bool(true)},
        {"supportsWriteMemoryRequest", JSON::Bool(false)},
        {"supportsDisassembleRequest", JSON::Bool(true)},
        {"supportsCancelRequest", JSON::Bool(false)},
        {"supportsBreakpointLocationsRequest", JSON::Bool(true)},
        {"supportsClipboardContext", JSON::Bool(false)},
        {"supportsSteppingGranularity", JSON::Bool(false)},
        {"supportsInstructionBreakpoints", JSON::Bool(false)},
        {"supportsExceptionFilterOptions", JSON::Bool(false)},
        {"supportsSingleThreadExecutionRequests", JSON::Bool(false)}
    });
    
    return JSON::Object({
        {"type", JSON::String("response")},
        {"request_seq", JSON::Number(seq)},
        {"success", JSON::Bool(true)},
        {"command", JSON::String("initialize")},
        {"body", body}
    });
}

std::string RawrXDScriptDAPAdapter::HandleLaunchRequest(int seq, const std::string& program) {
    // Launch the RawrXD-Script VM with the specified program
    if (pImpl_->eventCallback_) {
        pImpl_->eventCallback_("initialized", "{}");
    }
    
    return JSON::Object({
        {"type", JSON::String("response")},
        {"request_seq", JSON::Number(seq)},
        {"success", JSON::Bool(true)},
        {"command", JSON::String("launch")}
    });
}

std::string RawrXDScriptDAPAdapter::HandleAttachRequest(int seq, int processId) {
    return JSON::Object({
        {"type", JSON::String("response")},
        {"request_seq", JSON::Number(seq)},
        {"success", JSON::Bool(true)},
        {"command", JSON::String("attach")}
    });
}

std::string RawrXDScriptDAPAdapter::HandleSetBreakpointsRequest(int seq, const std::string& file,
    const std::vector<std::pair<uint32_t,uint32_t>>& lines) {
    
    std::vector<std::string> breakpointResponses;
    
    for (const auto& lineCol : lines) {
        uint32_t bpId = SetBreakpoint(file, lineCol.first, lineCol.second);
        auto bp = GetBreakpoints();
        
        for (const auto& b : bp) {
            if (b.id == bpId) {
                breakpointResponses.push_back(JSON::Object({
                    {"id", JSON::Number(b.id)},
                    {"verified", JSON::Bool(b.verified)},
                    {"line", JSON::Number(b.line)},
                    {"column", JSON::Number(b.column)}
                }));
                break;
            }
        }
    }
    
    std::string body = JSON::Object({
        {"breakpoints", JSON::Array(breakpointResponses)}
    });
    
    return JSON::Object({
        {"type", JSON::String("response")},
        {"request_seq", JSON::Number(seq)},
        {"success", JSON::Bool(true)},
        {"command", JSON::String("setBreakpoints")},
        {"body", body}
    });
}

std::string RawrXDScriptDAPAdapter::HandleContinueRequest(int seq) {
    SendCommand(VMCommand::Continue);
    
    std::string body = JSON::Object({
        {"allThreadsContinued", JSON::Bool(true)}
    });
    
    return JSON::Object({
        {"type", JSON::String("response")},
        {"request_seq", JSON::Number(seq)},
        {"success", JSON::Bool(true)},
        {"command", JSON::String("continue")},
        {"body", body}
    });
}

std::string RawrXDScriptDAPAdapter::HandleNextRequest(int seq) {
    SendCommand(VMCommand::StepOver);
    
    return JSON::Object({
        {"type", JSON::String("response")},
        {"request_seq", JSON::Number(seq)},
        {"success", JSON::Bool(true)},
        {"command", JSON::String("next")}
    });
}

std::string RawrXDScriptDAPAdapter::HandleStepInRequest(int seq) {
    SendCommand(VMCommand::StepIn);
    
    return JSON::Object({
        {"type", JSON::String("response")},
        {"request_seq", JSON::Number(seq)},
        {"success", JSON::Bool(true)},
        {"command", JSON::String("stepIn")}
    });
}

std::string RawrXDScriptDAPAdapter::HandleStepOutRequest(int seq) {
    SendCommand(VMCommand::StepOut);
    
    return JSON::Object({
        {"type", JSON::String("response")},
        {"request_seq", JSON::Number(seq)},
        {"success", JSON::Bool(true)},
        {"command", JSON::String("stepOut")}
    });
}

std::string RawrXDScriptDAPAdapter::HandlePauseRequest(int seq) {
    SendCommand(VMCommand::Pause);
    
    return JSON::Object({
        {"type", JSON::String("response")},
        {"request_seq", JSON::Number(seq)},
        {"success", JSON::Bool(true)},
        {"command", JSON::String("pause")}
    });
}

std::string RawrXDScriptDAPAdapter::HandleStackTraceRequest(int seq, uint32_t threadId) {
    auto frames = GetCallStack();
    std::vector<std::string> frameResponses;
    
    uint32_t frameId = 0;
    for (const auto& frame : frames) {
        frameResponses.push_back(JSON::Object({
            {"id", JSON::Number(frameId++)},
            {"name", JSON::String(frame.name)},
            {"source", JSON::Object({
                {"name", JSON::String(frame.file)},
                {"path", JSON::String(frame.file)}
            })},
            {"line", JSON::Number(frame.line)},
            {"column", JSON::Number(frame.column)}
        }));
    }
    
    std::string body = JSON::Object({
        {"stackFrames", JSON::Array(frameResponses)},
        {"totalFrames", JSON::Number(static_cast<int>(frames.size()))}
    });
    
    return JSON::Object({
        {"type", JSON::String("response")},
        {"request_seq", JSON::Number(seq)},
        {"success", JSON::Bool(true)},
        {"command", JSON::String("stackTrace")},
        {"body", body}
    });
}

std::string RawrXDScriptDAPAdapter::HandleScopesRequest(int seq, uint32_t frameId) {
    std::vector<std::string> scopes;
    
    scopes.push_back(JSON::Object({
        {"name", JSON::String("Registers")},
        {"presentationHint", JSON::String("registers")},
        {"variablesReference", JSON::Number(1)},
        {"expensive", JSON::Bool(false)}
    }));
    
    scopes.push_back(JSON::Object({
        {"name", JSON::String("Locals")},
        {"presentationHint", JSON::String("locals")},
        {"variablesReference", JSON::Number(2)},
        {"expensive", JSON::Bool(false)}
    }));
    
    scopes.push_back(JSON::Object({
        {"name", JSON::String("Globals")},
        {"presentationHint", JSON::String("globals")},
        {"variablesReference", JSON::Number(3)},
        {"expensive", JSON::Bool(false)}
    }));
    
    std::string body = JSON::Object({
        {"scopes", JSON::Array(scopes)}
    });
    
    return JSON::Object({
        {"type", JSON::String("response")},
        {"request_seq", JSON::Number(seq)},
        {"success", JSON::Bool(true)},
        {"command", JSON::String("scopes")},
        {"body", body}
    });
}

std::string RawrXDScriptDAPAdapter::HandleVariablesRequest(int seq, uint32_t variablesReference) {
    std::vector<std::string> varResponses;
    
    if (variablesReference == 1) {
        // Registers
        auto regs = GetRegisters();
        for (const auto& reg : regs) {
            varResponses.push_back(JSON::Object({
                {"name", JSON::String(reg.name)},
                {"value", JSON::String(reg.value)},
                {"type", JSON::String(reg.type)},
                {"variablesReference", JSON::Number(0)}
            }));
        }
    } else if (variablesReference == 2) {
        // Locals
        auto locals = GetVariables(VariableScope::Local);
        for (const auto& var : locals) {
            varResponses.push_back(JSON::Object({
                {"name", JSON::String(var.name)},
                {"value", JSON::String(var.value)},
                {"type", JSON::String(var.type)},
                {"variablesReference", JSON::Number(0)}
            }));
        }
    } else if (variablesReference == 3) {
        // Globals
        auto globals = GetVariables(VariableScope::Global);
        for (const auto& var : globals) {
            varResponses.push_back(JSON::Object({
                {"name", JSON::String(var.name)},
                {"value", JSON::String(var.value)},
                {"type", JSON::String(var.type)},
                {"variablesReference", JSON::Number(0)}
            }));
        }
    }
    
    std::string body = JSON::Object({
        {"variables", JSON::Array(varResponses)}
    });
    
    return JSON::Object({
        {"type", JSON::String("response")},
        {"request_seq", JSON::Number(seq)},
        {"success", JSON::Bool(true)},
        {"command", JSON::String("variables")},
        {"body", body}
    });
}

std::string RawrXDScriptDAPAdapter::HandleEvaluateRequest(int seq, const std::string& expression, uint32_t frameId) {
    // Simple expression evaluation - just return the expression as a value for now
    // In a full implementation, this would parse and evaluate the expression
    
    std::string body = JSON::Object({
        {"result", JSON::String("Expression: " + expression)},
        {"type", JSON::String("string")},
        {"variablesReference", JSON::Number(0)}
    });
    
    return JSON::Object({
        {"type", JSON::String("response")},
        {"request_seq", JSON::Number(seq)},
        {"success", JSON::Bool(true)},
        {"command", JSON::String("evaluate")},
        {"body", body}
    });
}

std::string RawrXDScriptDAPAdapter::HandleDisconnectRequest(int seq) {
    SendCommand(VMCommand::Stop);
    Shutdown();
    
    return JSON::Object({
        {"type", JSON::String("response")},
        {"request_seq", JSON::Number(seq)},
        {"success", JSON::Bool(true)},
        {"command", JSON::String("disconnect")}
    });
}

// ============================================================================
// Event Generators
// ============================================================================
std::string RawrXDScriptDAPAdapter::GenerateStoppedEvent(const std::string& reason, uint32_t threadId) {
    return JSON::Object({
        {"type", JSON::String("event")},
        {"event", JSON::String("stopped")},
        {"body", JSON::Object({
            {"reason", JSON::String(reason)},
            {"threadId", JSON::Number(threadId)},
            {"allThreadsStopped", JSON::Bool(true)}
        })}
    });
}

std::string RawrXDScriptDAPAdapter::GenerateContinuedEvent(uint32_t threadId) {
    return JSON::Object({
        {"type", JSON::String("event")},
        {"event", JSON::String("continued")},
        {"body", JSON::Object({
            {"threadId", JSON::Number(threadId)},
            {"allThreadsContinued", JSON::Bool(true)}
        })}
    });
}

std::string RawrXDScriptDAPAdapter::GenerateTerminatedEvent() {
    return JSON::Object({
        {"type", JSON::String("event")},
        {"event", JSON::String("terminated")},
        {"body", JSON::Object({})}
    });
}

std::string RawrXDScriptDAPAdapter::GenerateOutputEvent(const std::string& category, const std::string& output) {
    return JSON::Object({
        {"type", JSON::String("event")},
        {"event", JSON::String("output")},
        {"body", JSON::Object({
            {"category", JSON::String(category)},
            {"output", JSON::String(output)}
        })}
    });
}

// ============================================================================
// Implementation Helpers
// ============================================================================
uint32_t RawrXDScriptDAPAdapter::Impl::ResolveLineToBytecode(const std::string& file, uint32_t line) {
    std::lock_guard<std::mutex> lock(sourceMapMutex_);
    auto it = sourceMaps_.find(file);
    if (it != sourceMaps_.end()) {
        for (const auto& entry : it->second) {
            if (entry.line == line) {
                return entry.bytecodeOffset;
            }
        }
    }
    return 0xFFFFFFFF; // Not found
}

SourceMapEntry* RawrXDScriptDAPAdapter::Impl::FindSourceMapEntry(uint32_t bytecodeOffset) {
    std::lock_guard<std::mutex> lock(sourceMapMutex_);
    for (auto& pair : sourceMaps_) {
        for (auto& entry : pair.second) {
            if (entry.bytecodeOffset == bytecodeOffset) {
                return &entry;
            }
        }
    }
    return nullptr;
}

void RawrXDScriptDAPAdapter::Impl::UpdateCachedState() {
    // This would read from actual VM state
    // For now, just mark as updated
    std::lock_guard<std::mutex> lock(stateMutex_);
    cachedState_.running = running_;
}

} // namespace Debugger
} // namespace Script
} // namespace RawrXD
