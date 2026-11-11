// ============================================================================
// Phase 24: Debug Adapter Service - Production Interface
// ============================================================================
// The contract between RawrXD IDE UI and the DAP backend.
// Decoupled from Win32 specifics for testability and portability.
//
// Design Principles:
//   - Thread-safe: All methods callable from UI thread
//   - Async-by-default: Operations return immediately, callbacks deliver results
//   - State-machine driven: Clear lifecycle (Disconnected -> Initializing -> Running -> Paused)
//   - Error-transparent: All failures reported via callbacks, no exceptions
//
// Integration Points:
//   - CallStackPanel:    onStackTraceReceived()
//   - VariablesPanel:    onVariablesReceived()
//   - BreakpointsGutter: onBreakpointVerified() / onBreakpointHit()
//   - ProblemsPanel:     onOutputReceived() (stderr/stdout)
//   - StatusBar:         onStateChanged()
//
// Author: RawrXD Engineering
// Phase: 24 - Production Bridge
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>
#include <queue>
#include <condition_variable>

// Forward declarations (minimize header dependencies)
namespace nlohmann { class json; }

namespace RawrXD {
namespace Debug {

// ============================================================================
// Core Types
// ============================================================================

/// @brief DAP Service operational states
enum class DapState {
    Disconnected,       // No debugger attached
    Initializing,       // Handshake in progress
    Running,            // Target executing
    Paused,             // Target stopped (breakpoint, exception, etc.)
    Stopped             // Session terminated
};

/// @brief Structured result type (PatchResult-style)
struct DapResult {
    bool success;
    std::string error;
    
    static DapResult Ok() { return {true, ""}; }
    static DapResult Fail(const std::string& msg) { return {false, msg}; }
    
    explicit operator bool() const { return success; }
};

/// @brief Stack frame information
struct StackFrame {
    uint32_t id;
    std::string name;
    std::string source;
    uint32_t line;
    uint32_t column;
    std::string module;

    // Wide string versions for UI display (persist to avoid dangling pointers)
    mutable std::wstring wname;
    mutable std::wstring wsource;
    mutable std::wstring wmodule;
    mutable std::wstring lineStr;  // Persist line number as string for ListView

    // Initialize wide strings on first access
    void EnsureWideStrings() const {
        if (wname.empty() && !name.empty()) {
            wname = std::wstring(name.begin(), name.end());
        }
        if (wsource.empty() && !source.empty()) {
            wsource = std::wstring(source.begin(), source.end());
        }
        if (wmodule.empty() && !module.empty()) {
            wmodule = std::wstring(module.begin(), module.end());
        }
    }
};

/// @brief Variable information (scalars, objects, arrays)
struct Variable {
    std::string name;
    std::string value;
    std::string type;
    uint32_t variablesReference;  // 0 = leaf node (no children)
    bool isExpandable;
};

/// @brief Breakpoint information
struct Breakpoint {
    uint32_t id;
    std::string source;
    uint32_t line;
    bool verified;
    std::string message;  // Error message if verification failed
};

/// @brief Thread information
struct ThreadInfo {
    uint32_t id;
    std::string name;
    bool isStopped;
};

/// @brief Output channel (stdout/stderr/console)
enum class OutputChannel {
    Stdout,
    Stderr,
    Console,
    Telemetry
};

/// @brief Configuration for launching/attaching
struct LaunchConfig {
    std::string program;           // Path to executable
    std::string workingDirectory;  // Working directory
    std::vector<std::string> args; // Command line arguments
    std::vector<std::string> env;  // Environment variables (KEY=VALUE)
    bool stopOnEntry = false;      // Break at main()
    std::string debuggerType;      // "cppvsdbg", "gdb", "lldb"
    std::string debuggerPath;      // Optional: path to debugger executable
};

// ============================================================================
// Callback Types (UI Integration Points)
// ============================================================================

/// @brief State change notification
using StateChangeCallback = std::function<void(DapState oldState, DapState newState)>;

/// @brief Stack trace received
using StackTraceCallback = std::function<void(uint32_t threadId, const std::vector<StackFrame>& frames)>;

/// @brief Variables received (for a scope or variable expansion)
using VariablesCallback = std::function<void(uint32_t variablesReference, const std::vector<Variable>& vars)>;

/// @brief Breakpoint event
using BreakpointCallback = std::function<void(const Breakpoint& bp)>;

/// @brief Thread state change
using ThreadCallback = std::function<void(const ThreadInfo& thread)>;

/// @brief Output from target (stdout/stderr)
using OutputCallback = std::function<void(OutputChannel channel, const std::string& data)>;

/// @brief Stopped event (breakpoint, exception, step complete, etc.)
using StoppedCallback = std::function<void(const std::string& reason, uint32_t threadId, const std::string& description)>;

/// @brief Continued event
using ContinuedCallback = std::function<void(uint32_t threadId)>;

/// @brief Session terminated
using TerminatedCallback = std::function<void()>;

/// @brief Error notification (debugger process crash, pipe broken, etc.)
using ErrorCallback = std::function<void(const std::string& error, bool fatal)>;

// ============================================================================
// DapService Interface
// ============================================================================

/// @brief Production Debug Adapter Service
/// 
/// Thread Safety:
///   - All public methods are thread-safe
///   - Callbacks are invoked from internal reader thread
///   - UI should marshal callbacks to main thread if needed
///
/// Usage Pattern:
///   @code
///   auto& service = DapService::instance();
///   service.setCallbacks(myCallbacks);
///   service.initialize(config);
///   service.launch();
///   // ... callbacks fire as events arrive ...
///   service.disconnect();
///   @endcode
class DapService {
public:
    // ------------------------------------------------------------------------
    // Singleton Access
    // ------------------------------------------------------------------------
    static DapService& instance();
    
    // Disable copy/move
    DapService(const DapService&) = delete;
    DapService& operator=(const DapService&) = delete;
    
    // ------------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------------
    
    /// @brief Initialize the service (create debugger process, handshake)
    /// @param config Launch/attach configuration
    /// @return Ok() on successful initialization, Fail() otherwise
    DapResult initialize(const LaunchConfig& config);
    
    /// @brief Shutdown the service (terminate debugger, cleanup)
    /// @return Always returns Ok() (best-effort cleanup)
    DapResult shutdown();
    
    /// @brief Check if service is initialized and ready
    bool isInitialized() const;
    
    /// @brief Get current operational state
    DapState state() const;
    
    // ------------------------------------------------------------------------
    // Execution Control
    // ------------------------------------------------------------------------
    
    /// @brief Launch the target program (if not already running)
    DapResult launch();
    
    /// @brief Attach to a running process
    /// @param processId Process ID to attach to
    DapResult attach(uint32_t processId);
    
    /// @brief Continue execution
    /// @param threadId 0 = all threads, specific ID = resume that thread
    DapResult continueExecution(uint32_t threadId = 0);
    
    /// @brief Pause execution (break all threads)
    DapResult pause();
    
    /// @brief Step over (execute next line, don't enter functions)
    /// @param threadId Thread to step
    DapResult stepOver(uint32_t threadId);
    
    /// @brief Step into (execute next line, enter functions)
    /// @param threadId Thread to step
    DapResult stepInto(uint32_t threadId);
    
    /// @brief Step out (execute until current function returns)
    /// @param threadId Thread to step
    DapResult stepOut(uint32_t threadId);
    
    /// @brief Restart the target (if supported by debugger)
    DapResult restart();
    
    /// @brief Terminate the target process
    DapResult terminate();
    
    /// @brief Detach from target (leave it running)
    DapResult detach();
    
    // ------------------------------------------------------------------------
    // Breakpoints
    // ------------------------------------------------------------------------
    
    /// @brief Set a breakpoint
    /// @param source File path
    /// @param line Line number (1-based)
    /// @param condition Optional condition expression
    /// @return Breakpoint info (id assigned by debugger)
    DapResult setBreakpoint(const std::string& source, uint32_t line, 
                            const std::string& condition = "",
                            Breakpoint* outBp = nullptr);
    
    /// @brief Set a function breakpoint
    /// @param function Function name
    DapResult setFunctionBreakpoint(const std::string& function,
                                    Breakpoint* outBp = nullptr);
    
    /// @brief Remove a breakpoint
    /// @param breakpointId ID returned by setBreakpoint
    DapResult removeBreakpoint(uint32_t breakpointId);
    
    /// @brief Remove all breakpoints in a file
    DapResult removeBreakpoints(const std::string& source);
    
    /// @brief Remove all breakpoints everywhere
    DapResult removeAllBreakpoints();
    
    // ------------------------------------------------------------------------
    // Data Inspection
    // ------------------------------------------------------------------------
    
    /// @brief Request stack trace for a thread
    /// @param threadId Thread to inspect
    /// @param startFrame First frame to return (0 = top of stack)
    /// @param levels Max frames to return (0 = all)
    /// @return Result delivered via onStackTrace callback
    DapResult requestStackTrace(uint32_t threadId, uint32_t startFrame = 0, uint32_t levels = 0);
    
    /// @brief Request variables for a scope or variable
    /// @param variablesReference Reference from StackFrame or Variable
    DapResult requestVariables(uint32_t variablesReference);
    
    /// @brief Evaluate an expression (watch window, hover)
    /// @param expression Expression to evaluate
    /// @param frameId Stack frame context (0 = current)
    /// @param outResult Variable result (optional)
    DapResult evaluate(const std::string& expression, uint32_t frameId, Variable* outResult = nullptr);
    
    /// @brief Set variable value
    DapResult setVariable(uint32_t variablesReference, const std::string& name, const std::string& value);
    
    /// @brief Get list of all threads
    DapResult requestThreads();
    
    // ------------------------------------------------------------------------
    // Callback Registration
    // ------------------------------------------------------------------------
    
    struct Callbacks {
        StateChangeCallback onStateChanged;
        StackTraceCallback onStackTrace;
        VariablesCallback onVariables;
        BreakpointCallback onBreakpointSet;
        BreakpointCallback onBreakpointHit;
        ThreadCallback onThreadEvent;
        OutputCallback onOutput;
        StoppedCallback onStopped;
        ContinuedCallback onContinued;
        TerminatedCallback onTerminated;
        ErrorCallback onError;
    };
    
    /// @brief Register all callbacks (call before initialize)
    void setCallbacks(const Callbacks& callbacks);
    
    /// @brief Update individual callbacks
    void setStateCallback(StateChangeCallback cb);
    void setStackTraceCallback(StackTraceCallback cb);
    void setVariablesCallback(VariablesCallback cb);
    void setBreakpointCallbacks(BreakpointCallback onSet, BreakpointCallback onHit);
    void setOutputCallback(OutputCallback cb);
    void setStoppedCallback(StoppedCallback cb);
    void setContinuedCallback(ContinuedCallback cb);
    void setTerminatedCallback(TerminatedCallback cb);
    void setErrorCallback(ErrorCallback cb);
    
    // ------------------------------------------------------------------------
    // Advanced / Debug
    // ------------------------------------------------------------------------
    
    /// @brief Send raw DAP request (for extensibility)
    /// @param command DAP command name
    /// @param args JSON arguments
    /// @param outResponse Optional: wait for and return response
    DapResult sendRawRequest(const std::string& command, const nlohmann::json& args,
                             nlohmann::json* outResponse = nullptr,
                             uint32_t timeoutMs = 5000);
    
    /// @brief Get last error message
    std::string lastError() const;
    
    /// @brief Check if a request is currently pending
    bool hasPendingRequest() const;
    
    /// @brief Wait for current operation to complete (blocking)
    /// @param timeoutMs Maximum wait time
    /// @return true if operation completed, false if timeout
    bool waitForIdle(uint32_t timeoutMs = 30000);

private:
    // Private constructor for singleton
    DapService();
    ~DapService();
    
    // PIMPL idiom to hide implementation details
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// Utility Functions
// ============================================================================

/// @brief Convert state to human-readable string
const char* StateToString(DapState state);

/// @brief Convert string to state (for deserialization)
DapState StringToState(const std::string& str);

} // namespace Debug
} // namespace RawrXD

// ============================================================================
// Usage Example (Documentation)
// ============================================================================
/*
 
 // In CallStackPanel.cpp:
 void CallStackPanel::refresh(uint32_t threadId) {
     auto& service = RawrXD::Debug::DapService::instance();
     service.requestStackTrace(threadId);
 }
 
 // In your IDE initialization:
 void Win32IDE::initializeDebugger() {
     auto& service = RawrXD::Debug::DapService::instance();
     
     RawrXD::Debug::DapService::Callbacks cbs;
     cbs.onStackTrace = [this](uint32_t tid, const auto& frames) {
         // Marshal to UI thread if needed
         this->callStackPanel->update(tid, frames);
     };
     cbs.onStopped = [this](const auto& reason, uint32_t tid, const auto& desc) {
         this->statusBar->setText("Stopped: " + reason);
         this->editor->highlightLine(tid);
     };
     cbs.onError = [this](const auto& err, bool fatal) {
         if (fatal) this->showErrorDialog("Debugger Error: " + err);
     };
     
     service.setCallbacks(cbs);
 }
 
 // In Debug menu handler:
 void Win32IDE::onDebugStart() {
     RawrXD::Debug::LaunchConfig config;
     config.program = "C:\\path\\to\\target.exe";
     config.workingDirectory = "C:\\path\\to";
     config.stopOnEntry = true;
     
     auto& service = RawrXD::Debug::DapService::instance();
     auto result = service.initialize(config);
     if (!result) {
         MessageBox(nullptr, result.error.c_str(), "Debug Error", MB_OK);
         return;
     }
     
     service.launch();
 }
 
 */
