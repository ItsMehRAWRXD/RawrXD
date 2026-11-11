//=============================================================================
// RawrXD Debug Backend v1.0
// Professional Windows Debugger Backend
// Uses DbgHelp, StackWalk64, proper symbol resolution
//=============================================================================
#pragma once

#include <windows.h>
#include <dbghelp.h>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <map>
#include <mutex>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "kernel32.lib")

namespace RawrXD {
namespace Debug {

//=============================================================================
// Forward Declarations
//=============================================================================
class DebugBackend;
class DebugSession;
struct Breakpoint;
struct StackFrame;
struct DebugEvent;

//=============================================================================
// Types
//=============================================================================
enum class DebugEventType {
    ProcessCreated,
    ProcessExited,
    ThreadCreated,
    ThreadExited,
    BreakpointHit,
    SingleStep,
    AccessViolation,
    Exception,
    OutputDebugString,
    LoadDll,
    UnloadDll
};

enum class StepType {
    Into,       // Step into function calls
    Over,       // Step over function calls
    Out         // Step out of current function
};

struct RegisterContext {
    uint64_t rax, rcx, rdx, rbx;
    uint64_t rsp, rbp, rsi, rdi;
    uint64_t r8, r9, r10, r11;
    uint64_t r12, r13, r14, r15;
    uint64_t rip;
    uint32_t eflags;
    uint16_t cs, ds, es, fs, gs, ss;
    
    // Debug registers
    uint64_t dr0, dr1, dr2, dr3, dr6, dr7;
};

struct StackFrame {
    uint64_t instructionPointer;
    uint64_t stackPointer;
    uint64_t framePointer;
    
    // Symbol info
    std::string functionName;
    std::string moduleName;
    std::string sourceFile;
    uint32_t sourceLine;
    uint32_t sourceColumn;
    
    // Raw addresses for fallback
    uint64_t moduleBase;
    uint64_t functionOffset;
};

struct Breakpoint {
    uint64_t address;
    uint8_t originalByte;
    bool active;
    bool temporary;  // For step-over
    std::string condition;  // Future: conditional breakpoints
};

struct DebugEvent {
    DebugEventType type;
    uint32_t processId;
    uint32_t threadId;
    
    // Exception info
    uint64_t exceptionCode;
    uint64_t exceptionAddress;
    std::string exceptionMessage;
    
    // Exit info
    uint64_t exitCode;
    
    // DLL info
    std::string dllPath;
    uint64_t dllBaseAddress;
    
    // Debug string
    std::string debugMessage;
    
    // Context at event time
    RegisterContext registers;
    std::vector<StackFrame> callStack;
    
    DebugEvent() : type(DebugEventType::Exception), processId(0), threadId(0),
                   exceptionCode(0), exceptionAddress(0), exitCode(0),
                   dllBaseAddress(0) {}
};

struct MemoryRegion {
    uint64_t baseAddress;
    size_t size;
    uint32_t protection;
    std::string state;  // COMMIT, RESERVE, FREE
    std::string type;   // PRIVATE, IMAGE, MAPPED
};

struct ModuleInfo {
    uint64_t baseAddress;
    uint64_t size;
    std::string name;
    std::string path;
    bool symbolsLoaded;
    std::string pdbPath;
};

//=============================================================================
// Debug Session
// Represents a single debugging session (attach or launch)
//=============================================================================
class DebugSession : public std::enable_shared_from_this<DebugSession> {
public:
    DebugSession();
    ~DebugSession();
    
    // Session control
    bool LaunchProcess(const wchar_t* executable, const wchar_t* arguments = nullptr,
                      const wchar_t* workingDirectory = nullptr);
    bool AttachProcess(uint32_t processId);
    bool DetachProcess();
    bool TerminateProcess(uint32_t exitCode = 0);
    
    // Execution control
    bool ContinueExecution();
    bool BreakExecution();
    bool StepInto();
    bool StepOver();
    bool StepOut();
    
    // Breakpoints
    bool SetBreakpoint(uint64_t address);
    bool RemoveBreakpoint(uint64_t address);
    bool RemoveBreakpointByIndex(size_t index);
    void ClearAllBreakpoints();
    std::vector<Breakpoint> GetBreakpoints();
    
    // Memory access
    bool ReadMemory(uint64_t address, void* buffer, size_t size, size_t* bytesRead = nullptr);
    bool WriteMemory(uint64_t address, const void* buffer, size_t size, size_t* bytesWritten = nullptr);
    std::vector<MemoryRegion> QueryMemoryRegions();
    bool ProtectMemory(uint64_t address, size_t size, uint32_t protection);
    
    // Register access
    bool GetRegisters(RegisterContext& context);
    bool SetRegisters(const RegisterContext& context);
    bool GetThreadContext(uint32_t threadId, RegisterContext& context);
    bool SetThreadContext(uint32_t threadId, const RegisterContext& context);
    
    // Stack walking
    std::vector<StackFrame> GetCallStack(uint32_t threadId = 0);
    std::vector<StackFrame> GetCallStack(const RegisterContext& context);
    
    // Symbol resolution
    bool ResolveSymbol(uint64_t address, std::string& symbolName, std::string& moduleName);
    bool ResolveSourceLocation(uint64_t address, std::string& file, uint32_t& line, uint32_t& column);
    uint64_t ResolveSymbolName(const std::string& symbolName);
    
    // Module enumeration
    std::vector<ModuleInfo> GetLoadedModules();
    bool LoadSymbols(const std::string& modulePath);
    bool LoadSymbols(uint64_t baseAddress);
    
    // Event handling
    using EventCallback = std::function<void(const DebugEvent&)>;
    void SetEventCallback(EventCallback callback);
    
    // State queries
    bool IsActive() const { return m_active; }
    bool IsRunning() const { return m_running; }
    bool IsAttached() const { return m_attached; }
    uint32_t GetProcessId() const { return m_processId; }
    uint32_t GetMainThreadId() const { return m_mainThreadId; }
    HANDLE GetProcessHandle() const { return m_hProcess; }
    
    // Internal (called by DebugBackend)
    void ProcessDebugEvent(const DEBUG_EVENT& event);
    
private:
    // Session state
    bool m_active = false;
    bool m_running = false;
    bool m_attached = false;
    bool m_detached = false;
    
    // Process info
    uint32_t m_processId = 0;
    uint32_t m_mainThreadId = 0;
    HANDLE m_hProcess = nullptr;
    HANDLE m_hMainThread = nullptr;
    
    // Symbol handling
    bool m_symbolsInitialized = false;
    std::map<uint64_t, ModuleInfo> m_modules;
    
    // Breakpoints
    std::map<uint64_t, Breakpoint> m_breakpoints;
    std::mutex m_breakpointMutex;
    uint64_t m_stepOverBreakpoint = 0;
    
    // Event callback
    EventCallback m_eventCallback;
    
    // Internal helpers
    bool InitializeSymbols();
    void CleanupSymbols();
    bool EnableBreakpoint(uint64_t address);
    bool DisableBreakpoint(uint64_t address);
    bool HandleBreakpointEvent(const DEBUG_EVENT& event);
    bool HandleSingleStepEvent(const DEBUG_EVENT& event);
    bool SetSingleStepFlag(uint32_t threadId, bool enable);
    bool ComputeStepOverAddress(uint64_t currentRip, uint64_t& nextAddress);
    
    // Stack walking helpers
    BOOL CALLBACK ResolveSymbolCallback(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext);
};

//=============================================================================
// Debug Backend
// Singleton manager for all debugging sessions
//=============================================================================
class DebugBackend {
public:
    static DebugBackend& Instance();
    
    // Session management
    std::shared_ptr<DebugSession> CreateSession();
    void DestroySession(std::shared_ptr<DebugSession> session);
    std::vector<std::shared_ptr<DebugSession>> GetActiveSessions();
    
    // Global settings
    void SetSymbolPath(const std::wstring& path);
    std::wstring GetSymbolPath() const;
    
    // Utility functions
    static std::string GetLastErrorString();
    static bool EnableDebugPrivilege();
    
private:
    DebugBackend();
    ~DebugBackend();
    
    std::vector<std::weak_ptr<DebugSession>> m_sessions;
    std::mutex m_sessionsMutex;
    std::wstring m_symbolPath;
};

//=============================================================================
// Utility Functions
//=============================================================================
namespace Utils {
    std::string WideToUtf8(const std::wstring& wide);
    std::wstring Utf8ToWide(const std::string& utf8);
    std::string FormatAddress(uint64_t address);
    std::string FormatBytes(const uint8_t* data, size_t size);
    bool IsExecutableAddress(uint64_t address, HANDLE hProcess);
}

} // namespace Debug
} // namespace RawrXD
