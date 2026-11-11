// RawrXDScriptDAPAdapter.hpp
// Debug Adapter Protocol integration for RawrXD-Script JavaScript Engine
// Integrates with existing DAPAdapter.h infrastructure
// Build: cl /O2 /EHsc /std:c++20 /W4 /Fe:rxd-script-dap.exe RawrXDScriptDAPAdapter.cpp

#pragma once

#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <mutex>
#include <atomic>
#include <cstdint>

// Forward declarations for existing DAP infrastructure
namespace RawrXD {
namespace DAP {
    class DAPAdapter;
    struct DAPBreakpoint;
}
namespace Debugger {
    class DebugSession;
}
}

namespace RawrXD {
namespace Script {
namespace Debugger {

// ============================================================================
// VM Debug State - Mirrors interpreter.asm register file
// ============================================================================
struct VMRegisterState {
    uint64_t r[16];           // r0-r15 from interpreter.asm
    uint64_t pc;             // Program counter (bytecode offset)
    uint64_t sp;             // Stack pointer
    uint64_t fp;             // Frame pointer
    uint64_t flags;          // Status flags
    bool running;            // VM execution state
    uint32_t currentLine;    // Source line mapping
    std::string currentFile; // Source file
};

// ============================================================================
// Bytecode Instruction Info
// ============================================================================
struct BytecodeInstruction {
    uint8_t opcode;
    uint8_t dest;
    uint8_t srcA;
    uint8_t srcB;
    uint32_t offset;
    std::string mnemonic;
    std::string description;
};

// ============================================================================
// Source Map Entry - Maps bytecode offset to source location
// ============================================================================
struct SourceMapEntry {
    uint32_t bytecodeOffset;
    uint32_t line;
    uint32_t column;
    std::string file;
};

// ============================================================================
// Breakpoint State
// ============================================================================
struct ScriptBreakpoint {
    uint32_t id;
    uint32_t line;
    uint32_t column;
    std::string file;
    uint32_t bytecodeOffset;  // Resolved address
    bool verified;
    bool enabled;
};

// ============================================================================
// Call Stack Frame
// ============================================================================
struct ScriptStackFrame {
    uint32_t id;
    std::string name;           // Function name
    std::string file;
    uint32_t line;
    uint32_t column;
    uint64_t returnAddress;     // For stepping
    uint32_t registerBase;      // Register window base
};

// ============================================================================
// Variable Scope
// ============================================================================
enum class VariableScope {
    Local,      // Function locals
    Closure,    // Captured variables
    Global,     // Global scope
    Register    // VM registers r0-r15
};

struct ScriptVariable {
    std::string name;
    std::string type;
    std::string value;
    VariableScope scope;
    uint32_t registerIndex;  // If in register
};

// ============================================================================
// VM Control Commands
// ============================================================================
enum class VMCommand {
    Continue,   // Resume execution
    StepOver,   // Step to next line (don't enter calls)
    StepIn,     // Step into function call
    StepOut,    // Step out of current function
    Pause,      // Break at next instruction
    Stop        // Terminate
};

// ============================================================================
// RawrXD-Script DAP Adapter
// ============================================================================
class RawrXDScriptDAPAdapter {
public:
    using EventCallback = std::function<void(const std::string& eventType,
                                               const std::string& eventBody)>;

    RawrXDScriptDAPAdapter();
    ~RawrXDScriptDAPAdapter();

    // Initialization
    bool Initialize(EventCallback eventCallback);
    void Shutdown();

    // Source map management
    void LoadSourceMap(const std::string& file, const std::vector<SourceMapEntry>& entries);
    void ClearSourceMap();

    // Breakpoint management
    uint32_t SetBreakpoint(const std::string& file, uint32_t line, uint32_t column = 0);
    bool RemoveBreakpoint(uint32_t breakpointId);
    void ClearAllBreakpoints();
    std::vector<ScriptBreakpoint> GetBreakpoints() const;

    // VM control
    void AttachToVM(void* vmContext);  // vmContext = pointer to interpreter state
    void DetachFromVM();
    void SendCommand(VMCommand cmd);

    // State queries
    VMRegisterState GetRegisterState() const;
    std::vector<ScriptStackFrame> GetCallStack() const;
    std::vector<ScriptVariable> GetVariables(VariableScope scope) const;
    std::vector<ScriptVariable> GetRegisters() const;
    BytecodeInstruction DisassembleAtPC() const;

    // Execution events (called by VM)
    void OnBreakpointHit(uint32_t bytecodeOffset);
    void OnStepComplete(uint32_t bytecodeOffset);
    void OnException(const std::string& message);
    void OnVMTerminated();

    // DAP Protocol handlers
    std::string HandleInitializeRequest(int seq);
    std::string HandleLaunchRequest(int seq, const std::string& program);
    std::string HandleAttachRequest(int seq, int processId);
    std::string HandleSetBreakpointsRequest(int seq, const std::string& file,
                                             const std::vector<std::pair<uint32_t,uint32_t>>& lines);
    std::string HandleContinueRequest(int seq);
    std::string HandleNextRequest(int seq);
    std::string HandleStepInRequest(int seq);
    std::string HandleStepOutRequest(int seq);
    std::string HandlePauseRequest(int seq);
    std::string HandleStackTraceRequest(int seq, uint32_t threadId);
    std::string HandleScopesRequest(int seq, uint32_t frameId);
    std::string HandleVariablesRequest(int seq, uint32_t variablesReference);
    std::string HandleEvaluateRequest(int seq, const std::string& expression, uint32_t frameId);
    std::string HandleDisconnectRequest(int seq);

    // Event generators
    std::string GenerateStoppedEvent(const std::string& reason, uint32_t threadId);
    std::string GenerateContinuedEvent(uint32_t threadId);
    std::string GenerateTerminatedEvent();
    std::string GenerateOutputEvent(const std::string& category, const std::string& output);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

// ============================================================================
// Opcode Definitions (match interpreter.asm)
// ============================================================================
namespace Opcodes {
    constexpr uint8_t OP_LOAD_CONST   = 0x00;
    constexpr uint8_t OP_LOAD_INT     = 0x01;
    constexpr uint8_t OP_LOAD_STRING  = 0x02;
    constexpr uint8_t OP_LOAD_NULL    = 0x03;
    constexpr uint8_t OP_LOAD_BOOL    = 0x04;
    constexpr uint8_t OP_LOAD_ZERO    = 0x05;
    constexpr uint8_t OP_LOAD_ONE     = 0x06;

    constexpr uint8_t OP_ADD          = 0x20;
    constexpr uint8_t OP_SUB          = 0x21;
    constexpr uint8_t OP_MUL          = 0x22;
    constexpr uint8_t OP_DIV          = 0x23;
    constexpr uint8_t OP_MOD          = 0x24;
    constexpr uint8_t OP_NEG          = 0x25;
    constexpr uint8_t OP_INC          = 0x26;
    constexpr uint8_t OP_DEC          = 0x27;

    constexpr uint8_t OP_BIT_AND      = 0x30;
    constexpr uint8_t OP_BIT_OR      = 0x31;
    constexpr uint8_t OP_BIT_XOR     = 0x32;
    constexpr uint8_t OP_BIT_NOT     = 0x33;
    constexpr uint8_t OP_SHL          = 0x34;
    constexpr uint8_t OP_SHR          = 0x35;
    constexpr uint8_t OP_SHR_U        = 0x36;

    constexpr uint8_t OP_EQ           = 0x40;
    constexpr uint8_t OP_NEQ          = 0x41;
    constexpr uint8_t OP_LT           = 0x42;
    constexpr uint8_t OP_LTE          = 0x43;
    constexpr uint8_t OP_GT           = 0x44;
    constexpr uint8_t OP_GTE          = 0x45;
    constexpr uint8_t OP_STRICT_EQ    = 0x46;
    constexpr uint8_t OP_STRICT_NEQ   = 0x47;

    constexpr uint8_t OP_JMP          = 0x50;
    constexpr uint8_t OP_JMP_COND     = 0x51;
    constexpr uint8_t OP_JMP_NOT_COND = 0x52;
    constexpr uint8_t OP_CALL         = 0x53;
    constexpr uint8_t OP_RETURN       = 0x54;

    constexpr uint8_t OP_GET_PROP      = 0x60;
    constexpr uint8_t OP_SET_PROP      = 0x61;
    constexpr uint8_t OP_GET_ELEM      = 0x62;
    constexpr uint8_t OP_SET_ELEM      = 0x63;
    constexpr uint8_t OP_CREATE_OBJECT = 0x64;
    constexpr uint8_t OP_CREATE_ARRAY  = 0x65;

    constexpr uint8_t OP_NOP          = 0xF0;
    constexpr uint8_t OP_DEBUG_BREAK   = 0xF1;
    constexpr uint8_t OP_DEBUG_LOG     = 0xF2;

    const char* GetMnemonic(uint8_t opcode);
    const char* GetDescription(uint8_t opcode);
}

// ============================================================================
// JSON Helpers
// ============================================================================
namespace JSON {
    std::string Escape(const std::string& s);
    std::string String(const std::string& s);
    std::string Number(int n);
    std::string Number(uint32_t n);
    std::string Number(uint64_t n);
    std::string Bool(bool b);
    std::string Null();
    std::string Object(const std::vector<std::pair<std::string,std::string>>& pairs);
    std::string Array(const std::vector<std::string>& items);
}

} // namespace Debugger
} // namespace Script
} // namespace RawrXD
