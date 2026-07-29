// ============================================================================
// DebuggerCore.h - Production Native Debugger
// ============================================================================
// Features: Breakpoints, stepping, call stack, variables, memory inspection
// ============================================================================

#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <functional>
#include <unordered_map>
#include <memory>
#include <mutex>

namespace RawrXD {
namespace Debugger {

// Forward declarations
struct Breakpoint;
struct StackFrame;
struct Variable;
struct ThreadInfo;
struct ModuleInfo;

// Debug event types
enum class DebugEventType {
    None,
    ProcessCreated,
    ProcessExited,
    ThreadCreated,
    ThreadExited,
    ModuleLoaded,
    ModuleUnloaded,
    BreakpointHit,
    StepComplete,
    Exception,
    OutputDebugString,
    ProcessSuspended,
    ProcessResumed
};

// Breakpoint structure
struct Breakpoint {
    uint64_t address = 0;
    std::string file;
    int line = 0;
    std::string condition;
    bool enabled = true;
    bool temporary = false;
    uint8_t originalByte = 0;
    std::string id;
};

// Stack frame
struct StackFrame {
    uint64_t address = 0;
    uint64_t returnAddress = 0;
    uint64_t framePointer = 0;
    uint64_t stackPointer = 0;
    std::string module;
    std::string function;
    std::string file;
    int line = 0;
    int frameIndex = 0;
    std::vector<Variable> parameters;
    std::vector<Variable> locals;
};

// Variable information
struct Variable {
    std::string name;
    std::string type;
    std::string value;
    uint64_t address = 0;
    int size = 0;
    bool isPointer = false;
    bool isReference = false;
    std::vector<Variable> children;
    int parentId = -1;
    int id = 0;
};

// Thread information
struct ThreadInfo {
    uint32_t id = 0;
    uint32_t tid = 0;
    std::string name;
    uint64_t instructionPointer = 0;
    uint64_t stackPointer = 0;
    bool suspended = false;
    std::string state;
};

// Module information
struct ModuleInfo {
    uint64_t baseAddress = 0;
    uint64_t size = 0;
    std::string name;
    std::string path;
    std::string version;
    bool symbolsLoaded = false;
    std::string pdbPath;
};

// Memory region
struct MemoryRegion {
    uint64_t baseAddress = 0;
    uint64_t size = 0;
    uint32_t state = 0;
    uint32_t protect = 0;
    uint32_t type = 0;
    std::string description;
};

// Exception information
struct ExceptionInfo {
    uint32_t code = 0;
    uint64_t address = 0;
    std::string description;
    bool firstChance = true;
    std::vector<uint64_t> parameters;
};

// Debug event
struct DebugEvent {
    DebugEventType type = DebugEventType::None;
    uint32_t processId = 0;
    uint32_t threadId = 0;
    union {
        struct {
            uint64_t entryPoint;
            uint64_t baseAddress;
        } processCreated;
        struct {
            uint32_t exitCode;
        } processExited;
        struct {
            uint64_t startAddress;
            uint64_t localBase;
        } threadCreated;
        struct {
            uint64_t baseAddress;
        } moduleLoaded;
        struct {
            Breakpoint* breakpoint;
            uint64_t address;
        } breakpointHit;
        struct {
            ExceptionInfo info;
        } exception;
        struct {
            std::string message;
        } outputString;
    } data;
};

// Callback types
using DebugEventCallback = std::function<void(const DebugEvent& event)>;
using BreakpointCallback = std::function<void(const Breakpoint& bp)>;
using StepCallback = std::function<void()>;
using OutputCallback = std::function<void(const std::string& output)>;

// ============================================================================
// DebuggerCore - Production Native Debugger
// ============================================================================

class DebuggerCore {
public:
    DebuggerCore();
    ~DebuggerCore();

    // Initialize
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return m_initialized; }

    // Process control
    bool LaunchProcess(const std::string& executable, const std::string& arguments,
                       const std::string& workingDir);
    bool AttachProcess(uint32_t pid);
    bool DetachProcess();
    bool TerminateProcess();
    bool IsProcessRunning() const;
    bool IsProcessSuspended() const;

    // Execution control
    bool Continue();
    bool StepInto();
    bool StepOver();
    bool StepOut();
    bool Break();
    bool RunToCursor(const std::string& file, int line);
    bool RunToAddress(uint64_t address);

    // Breakpoints
    std::string SetBreakpoint(const std::string& file, int line);
    std::string SetBreakpoint(uint64_t address);
    std::string SetConditionalBreakpoint(const std::string& file, int line,
                                         const std::string& condition);
    bool RemoveBreakpoint(const std::string& id);
    bool EnableBreakpoint(const std::string& id, bool enable);
    bool ToggleBreakpoint(const std::string& id);
    std::vector<Breakpoint> GetBreakpoints() const;
    bool HasBreakpointAt(const std::string& file, int line) const;
    bool HasBreakpointAt(uint64_t address) const;
    void ClearAllBreakpoints();

    // Stack trace
    std::vector<StackFrame> GetCallStack(uint32_t threadId = 0);
    StackFrame GetCurrentFrame() const;
    bool SelectFrame(int frameIndex);
    int GetSelectedFrame() const { return m_selectedFrame; }

    // Variables
    std::vector<Variable> GetLocalVariables(int frameIndex = -1);
    std::vector<Variable> GetParameters(int frameIndex = -1);
    std::vector<Variable> GetGlobalVariables();
    std::vector<Variable> GetWatchVariables();
    Variable EvaluateExpression(const std::string& expression, int frameIndex = -1);
    bool SetVariableValue(const std::string& name, const std::string& value,
                          int frameIndex = -1);
    bool AddWatch(const std::string& expression);
    bool RemoveWatch(const std::string& expression);
    void ClearWatches();

    // Memory
    std::vector<uint8_t> ReadMemory(uint64_t address, size_t size);
    bool WriteMemory(uint64_t address, const std::vector<uint8_t>& data);
    std::vector<MemoryRegion> GetMemoryRegions();
    bool IsMemoryReadable(uint64_t address, size_t size);
    bool IsMemoryWritable(uint64_t address, size_t size);

    // Threads
    std::vector<ThreadInfo> GetThreads();
    bool SuspendThread(uint32_t threadId);
    bool ResumeThread(uint32_t threadId);
    bool SetActiveThread(uint32_t threadId);
    uint32_t GetActiveThread() const { return m_activeThread; }

    // Modules
    std::vector<ModuleInfo> GetLoadedModules();
    ModuleInfo GetModuleInfo(const std::string& name);
    uint64_t ResolveSymbol(const std::string& symbol);
    std::string GetSymbolName(uint64_t address);

    // Registers
    std::unordered_map<std::string, uint64_t> GetRegisters(uint32_t threadId = 0);
    bool SetRegister(const std::string& name, uint64_t value, uint32_t threadId = 0);

    // Source mapping
    bool LoadSourceMapping(const std::string& pdbPath);
    bool MapSourceToAddress(const std::string& file, int line, uint64_t& address);
    bool MapAddressToSource(uint64_t address, std::string& file, int& line);

    // Callbacks
    void SetDebugEventCallback(DebugEventCallback callback);
    void SetBreakpointCallback(BreakpointCallback callback);
    void SetStepCallback(StepCallback callback);
    void SetOutputCallback(OutputCallback callback);

    // C API
    static void* Create();
    static void Destroy(void* instance);
    static int Launch(void* instance, const char* executable, const char* arguments);
    static int Attach(void* instance, uint32_t pid);
    static int Detach(void* instance);
    static int Continue(void* instance);
    static int StepInto(void* instance);
    static int StepOver(void* instance);
    static int StepOut(void* instance);
    static int Break(void* instance);
    static const char* SetBreakpointFile(void* instance, const char* file, int line);
    static int RemoveBreakpoint(void* instance, const char* id);
    static int GetCallStack(void* instance, char* buffer, int bufferSize);
    static int GetLocalVariables(void* instance, char* buffer, int bufferSize);
    static int ReadMemory(void* instance, uint64_t address, void* buffer, int size);
    static int WriteMemory(void* instance, uint64_t address, const void* buffer, int size);

private:
    bool m_initialized = false;
    bool m_attached = false;
    bool m_suspended = false;
    uint32_t m_processId = 0;
    uint32_t m_activeThread = 0;
    int m_selectedFrame = 0;
    HANDLE m_hProcess = nullptr;
    HANDLE m_debugThread = nullptr;
    std::string m_executable;

    // Breakpoints
    std::unordered_map<std::string, Breakpoint> m_breakpoints;
    mutable std::mutex m_breakpointMutex;
    int m_nextBreakpointId = 1;

    // Watches
    std::vector<std::string> m_watches;
    mutable std::mutex m_watchMutex;

    // Callbacks
    DebugEventCallback m_eventCallback;
    BreakpointCallback m_breakpointCallback;
    StepCallback m_stepCallback;
    OutputCallback m_outputCallback;

    // Debug loop
    static DWORD WINAPI DebugThreadProc(LPVOID param);
    void DebugLoop();
    void HandleDebugEvent(const DEBUG_EVENT& event);
    void HandleBreakpoint(uint32_t threadId, uint64_t address);
    void HandleSingleStep(uint32_t threadId);
    void HandleException(uint32_t threadId, const EXCEPTION_DEBUG_INFO& info);

    // Breakpoint management
    bool InstallBreakpoint(Breakpoint& bp);
    bool RemoveBreakpointInternal(const std::string& id);
    bool DisableBreakpoint(Breakpoint& bp);

    // Stepping
    bool SetSingleStep(uint32_t threadId, bool enable);
    bool StepInternal(uint32_t threadId, bool stepOver);

    // Stack walking
    std::vector<StackFrame> WalkStack(uint32_t threadId);

    // Symbol handling
    bool LoadSymbols(const std::string& modulePath);
    void UnloadSymbols(const std::string& modulePath);

    // Utility
    std::string GenerateBreakpointId();
    uint64_t GetInstructionPointer(uint32_t threadId);
    bool SetInstructionPointer(uint32_t threadId, uint64_t address);
    bool SuspendProcess();
    bool ResumeProcess();
    std::string EscapeJson(const std::string& str);
};

// ============================================================================
// C API
// ============================================================================

extern "C" {
    void* Debugger_Create();
    void Debugger_Destroy(void* instance);
    int Debugger_Initialize(void* instance);
    int Debugger_Launch(void* instance, const char* executable, const char* arguments);
    int Debugger_Attach(void* instance, uint32_t pid);
    int Debugger_Detach(void* instance);
    int Debugger_Terminate(void* instance);
    int Debugger_Continue(void* instance);
    int Debugger_StepInto(void* instance);
    int Debugger_StepOver(void* instance);
    int Debugger_StepOut(void* instance);
    int Debugger_Break(void* instance);
    const char* Debugger_SetBreakpointFile(void* instance, const char* file, int line);
    const char* Debugger_SetBreakpointAddress(void* instance, uint64_t address);
    int Debugger_RemoveBreakpoint(void* instance, const char* id);
    int Debugger_EnableBreakpoint(void* instance, const char* id, int enable);
    int Debugger_GetCallStack(void* instance, char* buffer, int bufferSize);
    int Debugger_GetLocalVariables(void* instance, char* buffer, int bufferSize);
    int Debugger_ReadMemory(void* instance, uint64_t address, void* buffer, int size);
    int Debugger_WriteMemory(void* instance, uint64_t address, const void* buffer, int size);
    int Debugger_GetThreads(void* instance, char* buffer, int bufferSize);
    int Debugger_GetModules(void* instance, char* buffer, int bufferSize);
    int Debugger_SuspendThread(void* instance, uint32_t threadId);
    int Debugger_ResumeThread(void* instance, uint32_t threadId);
    int Debugger_IsRunning(void* instance);
    int Debugger_IsSuspended(void* instance);
}

} // namespace Debugger
} // namespace RawrXD
