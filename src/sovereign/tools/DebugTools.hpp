// ============================================================================
// DebugTools.hpp - Debugger Integration Tools
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <cstdint>

namespace Sovereign {

// Breakpoint
struct Breakpoint {
    uint64_t id;
    std::string file;
    int line;
    std::string condition;
    bool enabled;
    bool isLogpoint;
    std::string logMessage;
    uint64_t hitCount;
};

// Stack frame
struct StackFrame {
    int id;
    std::string function;
    std::string file;
    int line;
    uint64_t address;
    std::vector<std::pair<std::string, std::string>> locals;
};

// Variable
struct DebugVariable {
    std::string name;
    std::string value;
    std::string type;
    bool isPointer;
    uint64_t address;
    std::vector<DebugVariable> children;
};

// Memory region
struct MemoryRegion {
    uint64_t start;
    uint64_t end;
    std::string protection;
    std::string state;
    std::string type;
    std::string module;
};

// Debugger tools
class DebugTools {
public:
    DebugTools();
    ~DebugTools();

    // Process control
    bool Attach(uint64_t pid);
    bool Detach();
    bool Launch(const std::string& executable, const std::vector<std::string>& args);
    bool Terminate();
    bool IsAttached() const;
    uint64_t GetPID() const { return pid_; }

    // Execution control
    bool Continue();
    bool StepOver();
    bool StepInto();
    bool StepOut();
    bool Pause();
    bool RunToLine(const std::string& file, int line);
    bool RunToFunction(const std::string& function);

    // Breakpoints
    uint64_t SetBreakpoint(const std::string& file, int line, const std::string& condition = "");
    uint64_t SetLogpoint(const std::string& file, int line, const std::string& message);
    bool RemoveBreakpoint(uint64_t id);
    bool EnableBreakpoint(uint64_t id);
    bool DisableBreakpoint(uint64_t id);
    std::vector<Breakpoint> GetBreakpoints() const;

    // Stack trace
    std::vector<StackFrame> GetStackTrace(int maxDepth = 64);
    StackFrame GetCurrentFrame() const;

    // Variables
    DebugVariable GetVariable(const std::string& name);
    std::vector<DebugVariable> GetLocals();
    bool SetVariable(const std::string& name, const std::string& value);

    // Memory
    std::vector<uint8_t> ReadMemory(uint64_t address, size_t size);
    bool WriteMemory(uint64_t address, const std::vector<uint8_t>& data);
    std::vector<MemoryRegion> GetMemoryMap();

    // Registers
    std::vector<std::pair<std::string, uint64_t>> GetRegisters();
    uint64_t GetRegister(const std::string& name);

    // Disassembly
    std::vector<std::pair<uint64_t, std::string>> Disassemble(uint64_t address, size_t count);
    std::vector<std::pair<uint64_t, std::string>> DisassembleFunction(const std::string& function);

    // Exception handling
    bool CatchException(const std::string& type);
    bool IgnoreException(const std::string& type);

    // Callbacks
    void OnBreakpoint(std::function<void(const Breakpoint&)> callback);
    void OnException(std::function<void(const std::string&, uint64_t)> callback);
    void OnProcessExit(std::function<void(int)> callback);

    // Threads
    std::vector<uint64_t> GetThreads();
    bool SwitchToThread(uint64_t threadId);

private:
    uint64_t pid_ = 0;
    bool attached_ = false;
    
    // Callbacks
    std::function<void(const Breakpoint&)> breakpointCallback_;
    std::function<void(const std::string&, uint64_t)> exceptionCallback_;
    std::function<void(int)> exitCallback_;
};

} // namespace Sovereign
