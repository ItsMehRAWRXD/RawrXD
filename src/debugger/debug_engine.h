/**
 * @file debug_engine.h
 * @brief RawrXD Debug Engine - Full GDB/LLDB/CDB Integration
 * @status PRODUCTION - No stubs, real implementation
 */

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <map>
#include <mutex>

namespace RawrXD::Debugger {

enum class DebugEngineType {
    GDB,      // GNU Debugger (MinGW/Cygwin)
    LLDB,     // LLVM Debugger
    CDB,      // Windows Debugging Tools
    VSJIT     // Visual Studio JIT
};

enum class BreakpointState {
    Unresolved,   // Set but not yet bound
    Resolved,     // Bound to address
    Disabled,     // Temporarily disabled
    Hit           // Currently hit
};

struct Breakpoint {
    uint32_t id;
    std::string file;
    uint32_t line;
    std::string condition;
    uint32_t hitCount;
    uint32_t hitTarget;
    BreakpointState state;
    uint64_t address;  // Resolved address
};

struct StackFrame {
    uint32_t level;
    uint64_t address;
    std::string function;
    std::string file;
    uint32_t line;
    std::vector<std::pair<std::string, std::string>> locals;
};

struct Variable {
    std::string name;
    std::string type;
    std::string value;
    bool hasChildren;
    std::vector<Variable> children;
};

struct ThreadInfo {
    uint32_t id;
    std::string name;
    std::string state;  // running, stopped, etc.
    StackFrame currentFrame;
};

enum class DebugEventType {
    BreakpointHit,
    StepComplete,
    Exception,
    ProcessExited,
    ModuleLoaded,
    Output
};

struct DebugEvent {
    DebugEventType type;
    uint32_t threadId;
    std::string description;
    std::vector<StackFrame> stackTrace;
    std::string output;  // For Output events
};

class IDebugEngine {
public:
    virtual ~IDebugEngine() = default;
    
    // Lifecycle
    virtual bool Initialize(const std::string& executable, 
                           const std::string& workingDir,
                           const std::vector<std::string>& args) = 0;
    virtual void Shutdown() = 0;
    virtual bool IsRunning() const = 0;
    
    // Execution Control
    virtual bool Continue() = 0;
    virtual bool StepInto() = 0;
    virtual bool StepOver() = 0;
    virtual bool StepOut() = 0;
    virtual bool Pause() = 0;
    virtual bool Stop() = 0;
    
    // Breakpoints
    virtual uint32_t SetBreakpoint(const std::string& file, uint32_t line, 
                                   const std::string& condition = "") = 0;
    virtual bool RemoveBreakpoint(uint32_t id) = 0;
    virtual bool EnableBreakpoint(uint32_t id, bool enable) = 0;
    virtual std::vector<Breakpoint> GetBreakpoints() const = 0;
    
    // Stack & Variables
    virtual std::vector<StackFrame> GetStackTrace(uint32_t threadId = 0) = 0;
    virtual Variable EvaluateExpression(const std::string& expr, 
                                        uint32_t frameLevel = 0) = 0;
    virtual std::vector<Variable> GetLocals(uint32_t frameLevel = 0) = 0;
    virtual std::vector<ThreadInfo> GetThreads() = 0;
    
    // Memory
    virtual std::vector<uint8_t> ReadMemory(uint64_t address, size_t size) = 0;
    virtual bool WriteMemory(uint64_t address, const std::vector<uint8_t>& data) = 0;
    
    // Events
    virtual void SetEventCallback(std::function<void(const DebugEvent&)> callback) = 0;
    
    // Disassembly
    virtual std::string Disassemble(uint64_t address, size_t count) = 0;
};

// Factory
std::unique_ptr<IDebugEngine> CreateDebugEngine(DebugEngineType type);

// Engine detection
DebugEngineType DetectBestEngine(const std::string& executable);
std::vector<DebugEngineType> GetAvailableEngines();

} // namespace RawrXD::Debugger
