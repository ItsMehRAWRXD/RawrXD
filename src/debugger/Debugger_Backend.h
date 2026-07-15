// Debugger_Backend.h
// Phase 23: CDB/WinDbg Integration for RawrXD IDE
// ============================================================================
// Provides debugging capabilities for C++, ASM, and mixed-mode execution
// ============================================================================

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <optional>

namespace RawrXD {
namespace Debugger {

// ============================================================================
// Forward Declarations
// ============================================================================
class DebugSession;
class BreakpointManager;
class StackWalker;
class SymbolResolver;

// ============================================================================
// Debug Event Types
// ============================================================================
enum class DebugEventType {
    Breakpoint,           // Hit a breakpoint
    StepComplete,         // Single step completed
    Exception,            // Access violation, divide by zero, etc.
    ModuleLoad,           // DLL/exe loaded
    ModuleUnload,         // DLL/exe unloaded
    ThreadCreate,         // New thread started
    ThreadExit,           // Thread ended
    ProcessExit,          // Debuggee terminated
    OutputDebugString,    // DebugOutputString from debuggee
};

// ============================================================================
// Breakpoint Structure
// ============================================================================
struct Breakpoint {
    uint64_t id = 0;                    // Unique identifier
    std::wstring filePath;              // Source file (if known)
    uint32_t lineNumber = 0;            // 1-based line number
    uint64_t address = 0;               // Absolute memory address
    bool enabled = true;                // Active state
    bool isHardware = false;            // True for hardware breakpoint
    std::wstring condition;             // Optional condition expression
    uint32_t hitCount = 0;              // Times triggered
    uint32_t hitTarget = 0;             // For conditional breakpoints
    
    // Original byte at breakpoint location (for software breakpoints)
    uint8_t originalByte = 0;
};

// ============================================================================
// Stack Frame Structure
// ============================================================================
struct StackFrame {
    uint64_t frameNumber = 0;            // 0 = current, 1 = caller, etc.
    uint64_t instructionPointer = 0;     // RIP/EIP
    uint64_t stackPointer = 0;           // RSP/ESP
    uint64_t framePointer = 0;           // RBP/EBP
    std::wstring moduleName;            // DLL/EXE containing function
    std::wstring functionName;          // Demangled function name
    std::wstring filePath;              // Source file (if symbols available)
    uint32_t lineNumber = 0;              // Source line (if symbols available)
    uint64_t displacement = 0;          // Offset from function start
};

// ============================================================================
// Variable/Register Structure
// ============================================================================
struct RegisterValue {
    std::wstring name;                  // "rax", "rbx", etc.
    uint64_t value = 0;                 // Raw 64-bit value
    uint32_t size = 8;                  // 1, 2, 4, 8, 16 bytes
    std::wstring formatted;             // Human-readable representation
};

struct LocalVariable {
    std::wstring name;
    std::wstring type;
    uint64_t address = 0;
    std::vector<uint8_t> rawBytes;
    std::wstring value;                 // Formatted value
    bool isPointer = false;
    bool isReference = false;
};

// ============================================================================
// Debug Event Callback
// ============================================================================
using DebugEventCallback = std::function<void(DebugEventType event, 
                                               const void* eventData,
                                               DebugSession* session)>;

// ============================================================================
// Main Debug Session Class
// ============================================================================
class DebugSession {
public:
    DebugSession();
    ~DebugSession();
    
    // Session Management
    bool Initialize();
    void Shutdown();
    bool IsActive() const { return processHandle_ != nullptr; }
    
    // Process Control
    bool LaunchProcess(const std::wstring& executable, 
                       const std::wstring& arguments,
                       const std::wstring& workingDirectory);
    bool AttachToProcess(uint32_t processId);
    bool Detach();
    bool Terminate();
    
    // Execution Control
    bool ContinueExecution();
    bool StepInto();
    bool StepOver();
    bool StepOut();
    bool BreakExecution();  // Async break
    bool RunToAddress(uint64_t address);
    bool RunToLine(const std::wstring& filePath, uint32_t lineNumber);
    
    // Breakpoint Management
    std::optional<Breakpoint> SetBreakpoint(const std::wstring& filePath, 
                                               uint32_t lineNumber);
    std::optional<Breakpoint> SetBreakpointAtAddress(uint64_t address);
    bool RemoveBreakpoint(uint64_t breakpointId);
    bool EnableBreakpoint(uint64_t breakpointId, bool enable);
    std::vector<Breakpoint> GetBreakpoints() const;
    
    // Stack Inspection
    std::vector<StackFrame> GetCallStack(uint32_t maxFrames = 100);
    bool SetActiveFrame(uint32_t frameNumber);
    
    // Variable/Register Inspection
    std::vector<RegisterValue> GetRegisters();
    bool SetRegister(const std::wstring& name, uint64_t value);
    std::vector<LocalVariable> GetLocalVariables(uint32_t frameNumber = 0);
    std::optional<LocalVariable> EvaluateExpression(const std::wstring& expression);
    
    // Memory Inspection
    std::vector<uint8_t> ReadMemory(uint64_t address, size_t size);
    bool WriteMemory(uint64_t address, const std::vector<uint8_t>& data);
    
    // Symbol Resolution
    std::optional<uint64_t> ResolveSymbol(const std::wstring& symbolName);
    std::optional<std::wstring> ResolveAddress(uint64_t address);
    
    // Event Loop
    void SetEventCallback(DebugEventCallback callback);
    void ProcessEvents(uint32_t timeoutMs = 100);  // Non-blocking
    void RunEventLoop();  // Blocking until process exits
    
    // Status
    uint32_t GetProcessId() const { return processId_; }
    uint32_t GetThreadId() const { return threadId_; }
    uint64_t GetCurrentInstructionPointer() const;
    std::wstring GetLastError() const { return lastError_; }

private:
    // Platform-specific implementation
    class Impl;
    std::unique_ptr<Impl> pImpl_;
    
    // State
    HANDLE processHandle_ = nullptr;
    HANDLE threadHandle_ = nullptr;
    uint32_t processId_ = 0;
    uint32_t threadId_ = 0;
    uint64_t currentAddress_ = 0;
    std::wstring lastError_;
    DebugEventCallback eventCallback_;
    
    // Breakpoint management
    std::vector<Breakpoint> breakpoints_;
    uint64_t nextBreakpointId_ = 1;
    
    // Symbol resolution
    std::unique_ptr<SymbolResolver> symbolResolver_;
    
    // Internal helpers
    bool WaitForDebugEvent(DEBUG_EVENT& event, uint32_t timeoutMs);
    bool HandleDebugEvent(const DEBUG_EVENT& event);
    bool SetSoftwareBreakpoint(uint64_t address);
    bool RemoveSoftwareBreakpoint(uint64_t address);
    bool SetHardwareBreakpoint(uint64_t address, uint32_t slot);
};

// ============================================================================
// Symbol Resolver Interface
// ============================================================================
class SymbolResolver {
public:
    virtual ~SymbolResolver() = default;
    
    struct SymbolInfo {
        std::wstring name;
        std::wstring module;
        uint64_t address = 0;
        uint64_t size = 0;
        std::wstring filePath;
        uint32_t lineNumber = 0;
    };
    
    virtual bool Initialize(const std::wstring& symbolPath) = 0;
    virtual void Shutdown() = 0;
    
    virtual std::optional<uint64_t> ResolveSymbol(const std::wstring& symbolName) = 0;
    virtual std::optional<SymbolInfo> ResolveAddress(uint64_t address) = 0;
    virtual bool LoadModuleSymbols(const std::wstring& modulePath, uint64_t baseAddress) = 0;
};

// ============================================================================
// CDB Integration (Console Debugger)
// ============================================================================
class CDBIntegration {
public:
    // Launch CDB as child process and communicate via pipes
    bool LaunchCDB(const std::wstring& commandLine);
    void Shutdown();
    
    // Send commands to CDB
    bool SendCommand(const std::wstring& command);
    std::wstring ReadOutput(uint32_t timeoutMs = 5000);
    
    // High-level operations
    bool ExecuteCommand(const std::wstring& command, std::wstring& output);
    
    // Status
    bool IsRunning() const;
    
private:
    HANDLE cdbProcess_ = nullptr;
    HANDLE stdinRead_ = nullptr;
    HANDLE stdinWrite_ = nullptr;
    HANDLE stdoutRead_ = nullptr;
    HANDLE stdoutWrite_ = nullptr;
};

// ============================================================================
// Utility Functions
// ============================================================================
std::wstring FormatAddress(uint64_t address);
std::wstring FormatBytes(const std::vector<uint8_t>& bytes, size_t maxBytes = 16);
std::wstring DemangleSymbol(const std::wstring& mangledName);

} // namespace Debugger
} // namespace RawrXD
