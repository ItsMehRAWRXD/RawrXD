// ============================================================================
// dap_client.hpp — Phase 23: Debug Adapter Protocol Client
// ============================================================================
// Implements DAP (Debug Adapter Protocol) client for RawrXD IDE.
// Enables communication with any DAP-compliant debugger (CDB, GDB, LLDB).
//
// Architecture:
//   DAPClient (singleton) → JSON-RPC over stdio → Debugger Process
//   ↓
//   NativeDebuggerEngine (DbgEng) OR External Debugger (CDB/GDB/LLDB)
//   ↓
//   Win32IDE_Debugger (UI)
//
// Protocol: DAP 1.60 (https://microsoft.github.io/debug-adapter-protocol/)
// Pattern: Thread-safe singleton, async event-driven, PatchResult-style errors
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <mutex>
#include <atomic>
#include <thread>
#include <condition_variable>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace DAP {

using json = nlohmann::json;

// ============================================================================
// DAP Protocol Types (DAP 1.60)
// ============================================================================

enum class DAPMessageType : uint8_t {
    Request = 0,
    Response = 1,
    Event = 2
};

enum class DAPStopReason : uint8_t {
    Step = 0,
    Breakpoint = 1,
    Exception = 2,
    Pause = 3,
    Entry = 4,
    Goto = 5,
    FunctionBreakpoint = 6,
    DataBreakpoint = 7,
    InstructionBreakpoint = 8
};

enum class DAPThreadState : uint8_t {
    Running = 0,
    Stopped = 1
};

// ============================================================================
// DAP Structures
// ============================================================================

struct DAPBreakpoint {
    uint32_t id = 0;
    bool verified = false;
    std::string file;
    uint32_t line = 0;
    uint32_t column = 0;
    std::string condition;
    std::string hitCondition;
    uint32_t hitCount = 0;
};

struct DAPStackFrame {
    uint32_t id = 0;
    std::string name;
    std::string file;
    uint32_t line = 0;
    uint32_t column = 0;
    uint64_t instructionPointer = 0;
    std::string module;
};

struct DAPVariable {
    std::string name;
    std::string value;
    std::string type;
    uint32_t variablesReference = 0;  // 0 = scalar, >0 = expandable
    bool expensive = false;
};

struct DAPThread {
    uint32_t id = 0;
    std::string name;
    DAPThreadState state = DAPThreadState::Running;
};

struct DAPModule {
    std::string name;
    std::string path;
    uint64_t baseAddress = 0;
    uint64_t size = 0;
    bool symbolsLoaded = false;
    std::string symbolPath;
};

// ============================================================================
// DAP Events (callbacks to UI)
// ============================================================================

struct DAPStoppedEvent {
    uint32_t threadId = 0;
    DAPStopReason reason = DAPStopReason::Breakpoint;
    std::string description;
    std::string text;
    bool allThreadsStopped = true;
    uint32_t hitBreakpointIds = 0;
};

struct DAPContinuedEvent {
    uint32_t threadId = 0;
    bool allThreadsContinued = true;
};

struct DAPExitedEvent {
    int exitCode = 0;
};

struct DAPTerminatedEvent {
    bool restart = false;
};

struct DAPThreadEvent {
    std::string reason;  // "started", "exited"
    uint32_t threadId = 0;
};

struct DAPOutputEvent {
    std::string category;  // "console", "stdout", "stderr", "telemetry"
    std::string output;
    uint32_t line = 0;
    uint32_t column = 0;
    std::string file;
};

struct DAPBreakpointEvent {
    std::string reason;  // "changed", "new", "removed"
    DAPBreakpoint breakpoint;
};

struct DAPModuleEvent {
    std::string reason;  // "new", "changed", "removed"
    DAPModule module;
};

struct DAPLoadedSourceEvent {
    std::string reason;  // "new", "changed", "removed"
    std::string path;
};

// ============================================================================
// DAP Configuration
// ============================================================================

struct DAPConfig {
    std::string debuggerType;     // "cppvsdbg" (CDB), "cppdbg" (GDB), "lldb"
    std::string program;          // Path to executable to debug
    std::string args;             // Command line arguments
    std::string workingDir;       // Working directory
    std::string debuggerPath;     // Path to cdb.exe/gdb.exe/lldb.exe
    std::vector<std::string> symbolPaths;
    std::map<std::string, std::string> environment;
    bool stopOnEntry = false;
    bool externalConsole = false;
    std::string sourceFileMap;    // "remote:local;remote2:local2"
};

// ============================================================================
// DAP Result Types (PatchResult-style)
// ============================================================================

struct DAPResult {
    bool success = false;
    std::string errorMessage;
    json data;
    
    static DAPResult ok(const json& d = {}) {
        DAPResult r;
        r.success = true;
        r.data = d;
        return r;
    }
    
    static DAPResult fail(const std::string& msg) {
        DAPResult r;
        r.success = false;
        r.errorMessage = msg;
        return r;
    }
};

// ============================================================================
// DAP Client (Singleton)
// ============================================================================

class DAPClient {
public:
    static DAPClient& instance();
    
    // Lifecycle
    bool initialize(const DAPConfig& config);
    void shutdown();
    bool isConnected() const { return m_connected.load(); }
    
    // Session Control
    DAPResult launch(const std::string& program, const std::string& args = "");
    DAPResult attach(uint32_t pid);
    DAPResult detach();
    DAPResult terminate();
    DAPResult restart();
    
    // Execution Control
    DAPResult continueExecution(uint32_t threadId = 0);
    DAPResult pause(uint32_t threadId = 0);
    DAPResult stepOver(uint32_t threadId = 0);
    DAPResult stepInto(uint32_t threadId = 0);
    DAPResult stepOut(uint32_t threadId = 0);
    DAPResult stepInstruction(uint32_t threadId = 0);
    DAPResult nextInstruction(uint32_t threadId = 0);
    DAPResult gotoTarget(uint32_t threadId, const std::string& file, uint32_t line);
    
    // Breakpoints
    DAPResult setBreakpoint(const std::string& file, uint32_t line, 
                            const std::string& condition = "");
    DAPResult setFunctionBreakpoint(const std::string& function,
                                   const std::string& condition = "");
    DAPResult setDataBreakpoint(const std::string& dataExpr, 
                                 const std::string& condition = "");
    DAPResult removeBreakpoint(uint32_t breakpointId);
    DAPResult enableBreakpoint(uint32_t breakpointId, bool enable);
    DAPResult updateBreakpoints(const std::vector<DAPBreakpoint>& breakpoints);
    std::vector<DAPBreakpoint> getBreakpoints() const;
    
    // Stack Trace
    DAPResult getStackTrace(uint32_t threadId, std::vector<DAPStackFrame>& outFrames,
                            uint32_t startFrame = 0, uint32_t levels = 0);
    DAPResult getScopes(uint32_t frameId, std::vector<DAPVariable>& outScopes);
    
    // Variables
    DAPResult getVariables(uint32_t variablesReference, std::vector<DAPVariable>& outVars);
    DAPResult setVariable(uint32_t variablesReference, const std::string& name,
                          const std::string& value);
    DAPResult evaluate(const std::string& expression, uint32_t frameId,
                       DAPVariable& outResult);
    
    // Threads
    DAPResult getThreads(std::vector<DAPThread>& outThreads);
    
    // Modules
    DAPResult getModules(std::vector<DAPModule>& outModules);
    
    // Source
    DAPResult getSource(uint32_t sourceReference, std::string& outContent);
    
    // Disassembly
    DAPResult disassemble(uint64_t address, uint32_t instructionCount,
                          std::vector<std::string>& outInstructions);
    
    // Data Inspection
    DAPResult readMemory(uint64_t address, uint32_t count, std::vector<uint8_t>& outData);
    DAPResult writeMemory(uint64_t address, const std::vector<uint8_t>& data);
    
    // Event Callbacks (UI registers these)
    void onStopped(std::function<void(const DAPStoppedEvent&)> callback);
    void onContinued(std::function<void(const DAPContinuedEvent&)> callback);
    void onExited(std::function<void(const DAPExitedEvent&)> callback);
    void onTerminated(std::function<void(const DAPTerminatedEvent&)> callback);
    void onThread(std::function<void(const DAPThreadEvent&)> callback);
    void onOutput(std::function<void(const DAPOutputEvent&)> callback);
    void onBreakpoint(std::function<void(const DAPBreakpointEvent&)> callback);
    void onModule(std::function<void(const DAPModuleEvent&)> callback);
    void onLoadedSource(std::function<void(const DAPLoadedSourceEvent&)> callback);
    
    // Capabilities
    bool supportsConditionalBreakpoints() const { return m_capsConditionalBreakpoints; }
    bool supportsHitConditionalBreakpoints() const { return m_capsHitConditionalBreakpoints; }
    bool supportsFunctionBreakpoints() const { return m_capsFunctionBreakpoints; }
    bool supportsDataBreakpoints() const { return m_capsDataBreakpoints; }
    bool supportsStepBack() const { return m_capsStepBack; }
    bool supportsSetVariable() const { return m_capsSetVariable; }
    bool supportsRestartRequest() const { return m_capsRestartRequest; }
    bool supportsGotoTargetsRequest() const { return m_capsGotoTargetsRequest; }
    bool supportsStepInTargetsRequest() const { return m_capsStepInTargetsRequest; }
    bool supportsCompletionsRequest() const { return m_capsCompletionsRequest; }
    bool supportsModulesRequest() const { return m_capsModulesRequest; }
    bool supportsDisassembleRequest() const { return m_capsDisassembleRequest; }
    bool supportsReadMemoryRequest() const { return m_capsReadMemoryRequest; }
    bool supportsWriteMemoryRequest() const { return m_capsWriteMemoryRequest; }

private:
    DAPClient() = default;
    ~DAPClient();
    
    // Process management
    bool startDebuggerProcess(const DAPConfig& config);
    void stopDebuggerProcess();
    
    // Communication threads
    void readerThread();
    void dispatchEvent(const json& event);
    void dispatchResponse(const json& response);
    
    // JSON-RPC helpers
    bool sendRequest(const std::string& command, const json& arguments, 
                     uint32_t& outRequestId);
    bool sendResponse(uint32_t requestId, const json& body);
    json waitForResponse(uint32_t requestId, int timeoutMs = 5000);
    
    // Protocol helpers
    void parseCapabilities(const json& caps);
    DAPStopReason parseStopReason(const std::string& reason);
    DAPThreadState parseThreadState(const std::string& state);
    
    // State
    std::atomic<bool> m_connected{false};
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_shutdown{false};
    std::atomic<uint32_t> m_seq{0};
    DAPConfig m_config;
    
    // Process handles (Windows)
    void* m_hProcess{nullptr};
    void* m_hStdinWrite{nullptr};
    void* m_hStdoutRead{nullptr};
    
    // Threading
    std::thread m_readerThread;
    mutable std::mutex m_requestMutex;
    mutable std::mutex m_responseMutex;
    std::condition_variable m_responseCv;
    std::map<uint32_t, json> m_pendingResponses;
    
    // Breakpoints
    mutable std::mutex m_breakpointMutex;
    std::map<uint32_t, DAPBreakpoint> m_breakpoints;
    uint32_t m_nextBreakpointId{1};
    
    // Event callbacks
    std::function<void(const DAPStoppedEvent&)> m_onStopped;
    std::function<void(const DAPContinuedEvent&)> m_onContinued;
    std::function<void(const DAPExitedEvent&)> m_onExited;
    std::function<void(const DAPTerminatedEvent&)> m_onTerminated;
    std::function<void(const DAPThreadEvent&)> m_onThread;
    std::function<void(const DAPOutputEvent&)> m_onOutput;
    std::function<void(const DAPBreakpointEvent&)> m_onBreakpoint;
    std::function<void(const DAPModuleEvent&)> m_onModule;
    std::function<void(const DAPLoadedSourceEvent&)> m_onLoadedSource;
    
    // Capabilities (from initialize response)
    bool m_capsConditionalBreakpoints = false;
    bool m_capsHitConditionalBreakpoints = false;
    bool m_capsFunctionBreakpoints = false;
    bool m_capsDataBreakpoints = false;
    bool m_capsStepBack = false;
    bool m_capsSetVariable = false;
    bool m_capsRestartRequest = false;
    bool m_capsGotoTargetsRequest = false;
    bool m_capsStepInTargetsRequest = false;
    bool m_capsCompletionsRequest = false;
    bool m_capsModulesRequest = false;
    bool m_capsDisassembleRequest = false;
    bool m_capsReadMemoryRequest = false;
    bool m_capsWriteMemoryRequest = false;
};

} // namespace DAP
} // namespace RawrXD
