// ============================================================================
// InteractiveDebugger.hpp - Full Interactive Debugger Integration
// Breakpoints, step, call stack, variables, memory, disassembly
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace Sovereign {

struct DebugBreakpoint {
    uint64_t id;
    std::string file;
    int line;
    uint64_t address;
    std::string condition;
    std::string logMessage;
    bool enabled;
    bool isLogpoint;
    uint64_t hitCount;
};

struct DebugStackFrame {
    int id;
    std::string function;
    std::string file;
    int line;
    uint64_t address;
    std::vector<std::pair<std::string, std::string>> locals;
    std::vector<std::pair<std::string, std::string>> arguments;
};

struct DebugVariable {
    std::string name;
    std::string value;
    std::string type;
    bool isPointer;
    uint64_t address;
    std::vector<DebugVariable> children;
};

struct DebugThread {
    uint64_t id;
    std::string name;
    bool isRunning;
    std::vector<DebugStackFrame> stackTrace;
};

class InteractiveDebugger {
public:
    InteractiveDebugger();
    ~InteractiveDebugger();

    bool Initialize();
    void Shutdown();

    // Process control
    bool Launch(const std::string& executable, const std::vector<std::string>& args);
    bool Attach(uint64_t pid);
    bool Detach();
    bool Terminate();
    bool IsAttached() const { return attached_; }

    // Execution control
    bool Continue();
    bool StepOver();
    bool StepInto();
    bool StepOut();
    bool Pause();
    bool RunToCursor(const std::string& file, int line);
    bool RunToFunction(const std::string& function);

    // Breakpoints
    uint64_t SetBreakpoint(const std::string& file, int line, const std::string& condition = "");
    uint64_t SetLogpoint(const std::string& file, int line, const std::string& message);
    bool RemoveBreakpoint(uint64_t id);
    bool EnableBreakpoint(uint64_t id);
    bool DisableBreakpoint(uint64_t id);
    std::vector<DebugBreakpoint> GetBreakpoints() const;

    // Stack & variables
    std::vector<DebugStackFrame> GetStackTrace(int maxDepth = 64);
    std::vector<DebugVariable> GetLocals();
    std::vector<DebugVariable> GetArguments();
    DebugVariable GetVariable(const std::string& name);
    bool SetVariable(const std::string& name, const std::string& value);

    // Memory
    std::vector<uint8_t> ReadMemory(uint64_t address, size_t size);
    bool WriteMemory(uint64_t address, const std::vector<uint8_t>& data);

    // Threads
    std::vector<DebugThread> GetThreads();
    bool SwitchToThread(uint64_t threadId);

    // Disassembly
    std::vector<std::pair<uint64_t, std::string>> Disassemble(uint64_t address, size_t count);
    std::vector<std::pair<uint64_t, std::string>> DisassembleFunction(const std::string& function);

    // Callbacks
    void OnBreakpointHit(std::function<void(const DebugBreakpoint&)> callback);
    void OnException(std::function<void(const std::string&, uint64_t)> callback);
    void OnProcessExit(std::function<void(int)> callback);
    void OnThreadCreated(std::function<void(uint64_t)> callback);

    struct DebuggerStats {
        uint64_t totalBreakpoints;
        uint64_t totalSteps;
        uint64_t totalExceptions;
        uint64_t totalMemoryReads;
        uint64_t totalMemoryWrites;
    };
    DebuggerStats GetStats() const { return stats_; }

private:
    bool attached_ = false;
    uint64_t pid_ = 0;
    void* processHandle_ = nullptr;
    void* threadHandle_ = nullptr;
    std::unordered_map<uint64_t, DebugBreakpoint> breakpoints_;
    uint64_t nextBreakpointId_ = 1;
    DebuggerStats stats_;
    
    std::function<void(const DebugBreakpoint&)> breakpointCallback_;
    std::function<void(const std::string&, uint64_t)> exceptionCallback_;
    std::function<void(int)> exitCallback_;
    std::function<void(uint64_t)> threadCreatedCallback_;
    
    mutable std::mutex mutex_;
};

} // namespace Sovereign
