/*===========================================================================
 * DebuggerService.h
 * RawrXD IDE Debugger Service Layer
 * 
 * Bridge between SovereignCDB_Engine and IDE UI
 * Thread-safe event bridge with SPSC ring buffer
 *===========================================================================*/

#ifndef DEBUGGER_SERVICE_H
#define DEBUGGER_SERVICE_H

#include <windows.h>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <map>

// Forward declaration
struct CDB_DebugEvent;
struct CDB_ThreadContext;

namespace RawrXD {

/*===========================================================================
 * TYPES
 *===========================================================================*/

enum class DebugState {
    Idle,           // No active debug session
    Launching,      // Process starting
    Running,        // Process executing
    Paused,         // Breakpoint/exception hit
    Stepping,       // Single-step in progress
    Terminated      // Process ended
};

enum class DebugEventType {
    None,
    ProcessStarted,
    ProcessExited,
    ThreadCreated,
    ThreadExited,
    BreakpointHit,
    ExceptionRaised,
    ModuleLoaded,
    ModuleUnloaded,
    OutputDebugString
};

struct DebugEvent {
    DebugEventType      type;
    uint32_t            processId;
    uint32_t            threadId;
    uint64_t            timestamp;
    uint64_t            address;        // For breakpoints/exceptions
    uint32_t            exceptionCode;  // For exceptions
    std::string         description;
    
    DebugEvent() : type(DebugEventType::None), processId(0), threadId(0),
                   timestamp(0), address(0), exceptionCode(0) {}
};

struct BreakpointInfo {
    uint32_t            id;
    uint64_t            address;
    std::string         filePath;
    int                 lineNumber;
    std::string         symbolName;
    bool                enabled;
    bool                resolved;         // Address resolved from symbol?
    
    BreakpointInfo() : id(0), address(0), lineNumber(0), 
                       enabled(true), resolved(false) {}
};

struct RegisterSet {
    uint64_t            rax, rbx, rcx, rdx;
    uint64_t            rsi, rdi, rbp, rsp;
    uint64_t            r8, r9, r10, r11;
    uint64_t            r12, r13, r14, r15;
    uint64_t            rip;
    uint32_t            eflags;
    
    RegisterSet() : rax(0), rbx(0), rcx(0), rdx(0),
                    rsi(0), rdi(0), rbp(0), rsp(0),
                    r8(0), r9(0), r10(0), r11(0),
                    r12(0), r13(0), r14(0), r15(0),
                    rip(0), eflags(0) {}
};

struct MemoryRange {
    uint64_t            baseAddress;
    std::vector<uint8_t> data;
    bool                valid;
    
    MemoryRange() : baseAddress(0), valid(false) {}
};

struct StackFrame {
    uint64_t            returnAddress;
    uint64_t            framePointer;
    uint64_t            stackPointer;
    std::string         symbolName;
    std::string         fileName;
    int                 lineNumber;
    
    StackFrame() : returnAddress(0), framePointer(0), 
                   stackPointer(0), lineNumber(0) {}
};

// Callback types
using DebugEventCallback = std::function<void(const DebugEvent&)>;
using StateChangeCallback = std::function<void(DebugState oldState, DebugState newState)>;

/*===========================================================================
 * DEBUGGER SERVICE
 *===========================================================================*/

class DebuggerService {
public:
    // Singleton access
    static DebuggerService& GetInstance();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Session control
    bool LaunchProcess(const std::string& exePath, 
                       const std::string& cmdLine = "",
                       const std::string& workingDir = "");
    bool AttachToProcess(uint32_t processId);
    void Detach();
    void Terminate(uint32_t exitCode = 0);
    
    // Execution control
    void Continue();
    void Pause();           // Break into debugger
    void StepInto();
    void StepOver();
    void StepOut();
    
    // State queries
    DebugState GetState() const;
    bool IsRunning() const;
    bool IsPaused() const;
    uint32_t GetProcessId() const;
    std::string GetLastError() const;
    
    // Breakpoint management
    uint32_t SetBreakpoint(const std::string& filePath, int lineNumber);
    uint32_t SetBreakpointByAddress(uint64_t address);
    void RemoveBreakpoint(uint32_t bpId);
    void EnableBreakpoint(uint32_t bpId, bool enable);
    void ToggleBreakpoint(const std::string& filePath, int lineNumber);
    bool HasBreakpoint(const std::string& filePath, int lineNumber) const;
    const std::vector<BreakpointInfo>& GetBreakpoints() const;
    
    // Memory access
    MemoryRange ReadMemory(uint64_t address, size_t size);
    bool WriteMemory(uint64_t address, const void* data, size_t size);
    
    // Register access
    RegisterSet GetRegisters(uint32_t threadId = 0);
    void SetRegisters(uint32_t threadId, const RegisterSet& regs);
    uint64_t GetRegisterValue(uint32_t threadId, const std::string& regName);
    void SetRegisterValue(uint32_t threadId, const std::string& regName, uint64_t value);
    
    // Call stack
    std::vector<StackFrame> GetCallStack(uint32_t threadId = 0, uint32_t maxFrames = 64);
    
    // Symbol resolution
    bool ResolveSymbol(const std::string& symbolName, uint64_t& outAddress);
    bool ResolveLineInfo(uint64_t address, std::string& outFile, int& outLine);
    
    // Event callbacks
    void SetEventCallback(DebugEventCallback callback);
    void SetStateChangeCallback(StateChangeCallback callback);
    
    // UI Integration - Call from main thread
    void PollEvents();      // Process pending events
    void UpdateUI();        // Refresh all debug views
    
    // Source mapping
    void MapSourceToAddress(const std::string& filePath, int lineNumber, uint64_t address);
    bool GetAddressForLine(const std::string& filePath, int lineNumber, uint64_t& outAddress);
    bool GetLineForAddress(uint64_t address, std::string& outFile, int& outLine);

private:
    DebuggerService();
    ~DebuggerService();
    
    // Non-copyable
    DebuggerService(const DebuggerService&) = delete;
    DebuggerService& operator=(const DebuggerService&) = delete;
    
    // Internal event handling
    void OnCDBEvent(const CDB_DebugEvent* event);
    void ProcessEventQueue();
    void UpdateState(DebugState newState);
    
    // Breakpoint resolution
    void ResolvePendingBreakpoints();
    void SyncBreakpointToEngine(uint32_t bpId);
    void RemoveBreakpointFromEngine(uint32_t bpId);
    
    // Thread context caching
    void CacheThreadContext(uint32_t threadId);
    void InvalidateThreadCache();
    
    // Private implementation
    struct Impl;
    Impl* m_impl;
    
    // State
    DebugState          m_state;
    mutable std::mutex  m_stateMutex;
    
    // Callbacks
    DebugEventCallback  m_eventCallback;
    StateChangeCallback m_stateCallback;
    
    // Breakpoints
    std::vector<BreakpointInfo> m_breakpoints;
    mutable std::mutex          m_breakpointMutex;
    uint32_t                    m_nextBreakpointId;
    
    // Source mapping
    std::map<std::pair<std::string, int>, uint64_t> m_sourceToAddr;
    std::map<uint64_t, std::pair<std::string, int>> m_addrToSource;
    mutable std::mutex                                  m_sourceMapMutex;
    
    // Thread context cache
    std::map<uint32_t, RegisterSet> m_threadCache;
    mutable std::mutex              m_cacheMutex;
    
    // Last error
    std::string         m_lastError;
    mutable std::mutex  m_errorMutex;
};

/*===========================================================================
 * UTILITY FUNCTIONS
 *===========================================================================*/

namespace DebuggerUtils {
    // Format helpers
    std::string FormatAddress(uint64_t address);
    std::string FormatBytes(const uint8_t* data, size_t size, size_t bytesPerGroup = 4);
    std::string GetExceptionName(uint32_t code);
    std::string GetRegisterName(uint32_t index);
    
    // Memory formatting
    std::string FormatMemoryLine(uint64_t addr, const uint8_t* data, size_t size);
    std::string FormatAsciiDump(const uint8_t* data, size_t size);
}

} // namespace RawrXD

#endif // DEBUGGER_SERVICE_H
