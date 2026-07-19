/*===========================================================================
 * DebugSession.h
 * Real debugger backend using CDB (Console Debugger)
 * 
 * Architecture: CDB process → Named Pipe → Parser → Triple Buffer → UI
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <string>
#include <functional>
#include <atomic>
#include <thread>
#include <vector>
#include <map>

namespace RawrXD {
namespace Debugger {

/*===========================================================================
 * Forward Declarations
 *=========================================================================*/
struct DebugStatePayload;
struct FrameArena;

/*===========================================================================
 * Event Types
 *=========================================================================*/
enum class DebugEventType {
    None,
    Breakpoint,
    StepComplete,
    Exception,
    ProcessExit,
    ModuleLoad,
    ThreadCreate,
    Output
};

/*===========================================================================
 * Breakpoint Structure
 *=========================================================================*/
struct Breakpoint {
    uint32_t id;
    std::wstring filePath;
    uint32_t lineNumber;
    uint64_t address;
    bool enabled;
    std::wstring condition;
};

/*===========================================================================
 * Debug Session State
 *=========================================================================*/
enum class DebugSessionState {
    Idle,
    Starting,
    Running,
    Breakpoint,
    Stepping,
    Exception,
    Exiting,
    Error
};

/*===========================================================================
 * Event Callback
 *=========================================================================*/
using DebugEventCallback = std::function<void(DebugEventType event, 
                                               const void* eventData,
                                               class DebugSession* session)>;

/*===========================================================================
 * Debug Session Class
 * Manages CDB process and parses output
 *=========================================================================*/
class DebugSession {
public:
    DebugSession();
    ~DebugSession();

    // Lifecycle
    bool Initialize();
    void Shutdown();

    // Session control
    bool LaunchProcess(const std::wstring& executable, 
                       const std::wstring& arguments,
                       const std::wstring& workingDir);
    bool AttachToProcess(uint32_t pid);
    void Terminate();
    void Detach();

    // Execution control
    bool ContinueExecution();
    bool StepOver();
    bool StepInto();
    bool StepOut();
    bool BreakExecution();

    // Breakpoints
    bool SetBreakpoint(const std::wstring& file, uint32_t line);
    bool SetBreakpointByAddress(uint64_t address);
    bool RemoveBreakpoint(uint32_t bpId);
    bool RemoveBreakpointAt(const std::wstring& file, uint32_t line);
    void ClearAllBreakpoints();
    std::vector<Breakpoint> GetBreakpoints() const;

    // Stack & variables
    bool RefreshStackFrames();
    bool RefreshLocalVariables();
    bool RefreshRegisters();
    bool EvaluateExpression(const std::wstring& expr, std::wstring& result);

    // State queries
    bool IsActive() const;
    bool IsRunning() const;
    DebugSessionState GetState() const;
    uint32_t GetProcessId() const;
    uint64_t GetCurrentInstructionPointer() const;
    std::wstring GetCurrentFile() const;
    uint32_t GetCurrentLine() const;

    // Callbacks
    void SetEventCallback(DebugEventCallback callback);
    void SetOutputCallback(std::function<void(const std::wstring&)> callback);

    // Direct CDB command (for advanced usage)
    bool ExecuteCommand(const std::wstring& command, std::wstring& output);

private:
    // CDB process management
    bool StartCDB(const std::wstring& commandLine);
    void StopCDB();
    void CDBReaderThread();
    
    // CDB output parsing
    void ProcessCDBOutput(const std::string& output);
    void ParseBreakpointHit(const std::string& line);
    void ParseException(const std::string& line);
    void ParseRegisters(const std::vector<std::string>& lines);
    void ParseLocals(const std::vector<std::string>& lines);
    void ParseStack(const std::vector<std::string>& lines);
    void ParseModuleLoad(const std::string& line);
    
    // Helpers
    std::string ReadCDBResponse();
    bool SendCDBCommand(const std::string& command);
    bool WaitForPrompt();
    
    // State machine
    void TransitionToState(DebugSessionState newState);
    void NotifyEvent(DebugEventType event, const void* data = nullptr);

private:
    // Process handles
    HANDLE hCDBProcess_;
    HANDLE hCDBThread_;
    HANDLE hReadPipe_;
    HANDLE hWritePipe_;
    HANDLE hErrorPipe_;
    
    // Threading
    std::thread readerThread_;
    std::atomic<bool> stopReader_;
    
    // State
    std::atomic<DebugSessionState> state_;
    std::atomic<bool> isActive_;
    std::atomic<bool> isRunning_;
    std::atomic<uint32_t> processId_;
    std::atomic<uint64_t> currentIP_;
    
    // Current location
    std::wstring currentFile_;
    std::atomic<uint32_t> currentLine_;
    
    // Breakpoints
    std::map<uint32_t, Breakpoint> breakpoints_;
    std::atomic<uint32_t> nextBpId_;
    mutable CRITICAL_SECTION bpLock_;
    
    // Callbacks
    DebugEventCallback eventCallback_;
    std::function<void(const std::wstring&)> outputCallback_;
    
    // Command synchronization
    HANDLE hCommandEvent_;
    std::string lastResponse_;
    mutable CRITICAL_SECTION commandLock_;
    
    // CDB path
    static constexpr wchar_t CDB_PATH[] = L"C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe";
};

} // namespace Debugger
} // namespace RawrXD
