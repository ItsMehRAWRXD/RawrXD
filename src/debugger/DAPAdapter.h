// DAPAdapter.h
// Phase 25: DAP Adapter - Protocol Dispatcher
// ============================================================================
// Routes DAP JSON-RPC requests to BeaconDebugger backend
// Implements DAP 1.60 protocol subset
// ============================================================================

#pragma once

#include <windows.h>
#include <string>
#include <memory>
#include <functional>
#include <map>

namespace RawrXD {
namespace Debugger { class DebugSession; }

namespace DAP {

// Forward declarations
class DAPTransport;

// ============================================================================
// DAP Request/Response Types
// ============================================================================
enum class DAPCommand {
    Initialize,
    Launch,
    Attach,
    ConfigurationDone,
    Disconnect,
    SetBreakpoints,
    Continue,
    Next,
    StepIn,
    StepOut,
    Pause,
    StackTrace,
    Scopes,
    Variables,
    Evaluate,
    Unknown
};

struct DAPBreakpoint {
    uint64_t id = 0;
    uint64_t address = 0;
    std::wstring filePath;
    uint32_t lineNumber = 0;
    bool verified = false;
};

struct DAPStackFrame {
    uint64_t id = 0;
    std::wstring name;
    std::wstring filePath;
    uint32_t lineNumber = 0;
    uint32_t column = 0;
};

// ============================================================================
// DAP Adapter Configuration
// ============================================================================
struct DAPAdapterConfig {
    std::wstring program;           // Path to executable to debug
    std::wstring args;              // Command line arguments
    std::wstring cwd;               // Working directory
    bool stopOnEntry = true;        // Stop at entry point
    bool trace = false;             // Enable tracing
};

// ============================================================================
// DAP Adapter
// ============================================================================
class DAPAdapter {
public:
    using EventCallback = std::function<void(const std::string& eventType, 
                                               const std::string& eventBody)>;

    DAPAdapter();
    ~DAPAdapter();

    // Initialize with transport and backend
    bool Initialize(DAPTransport* transport, 
                      RawrXD::Debugger::DebugSession* debugSession);
    void Shutdown();

    // Main loop - call this on a dedicated thread
    void Run();
    void Stop();

    // Event handlers (called by backend)
    void OnBreakpointHit(uint64_t address, const std::wstring& file, uint32_t line);
    void OnStepComplete();
    void OnProcessExited(uint32_t exitCode);
    void OnOutputDebugString(const std::wstring& message);
    void OnThreadStarted(uint32_t threadId);
    void OnThreadExited(uint32_t threadId);

    // Send events to client
    void SendStoppedEvent(const std::string& reason, uint64_t threadId);
    void SendContinuedEvent(uint64_t threadId);
    void SendOutputEvent(const std::string& category, const std::string& output);
    void SendTerminatedEvent();
    void SendExitedEvent(uint32_t exitCode);

    bool IsRunning() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

// ============================================================================
// Global Adapter Access
// ============================================================================
DAPAdapter* GetDAPAdapter();
bool InitializeDAPAdapter(DAPTransport* transport, 
                         RawrXD::Debugger::DebugSession* debugSession);
void ShutdownDAPAdapter();

} // namespace DAP
} // namespace RawrXD
