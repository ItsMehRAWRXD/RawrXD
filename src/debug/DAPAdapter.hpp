//=============================================================================
// RawrXD DAP Adapter
// Bridges DebugBackend to Debug Adapter Protocol
// Zero external dependencies
//=============================================================================
#pragma once

#include "DAPTypes.hpp"
#include "DAPTransport.hpp"
#include "DebugBackend.h"
#include <functional>

namespace RawrXD {
namespace DAP {

//=============================================================================
// DAP Adapter
// Main class that handles DAP protocol
//=============================================================================

class DAPAdapter {
public:
    DAPAdapter();
    ~DAPAdapter();
    
    // Initialize with existing debug session
    void AttachSession(DebugSession* session);
    void DetachSession();
    
    // Main loop - call this to start processing DAP messages
    void Run();
    void Stop();
    
    // Test helper - process a single message (for testing)
    void RunSingleTest(const char* json);
    
    // Send event to client (thread-safe)
    void SendEvent(const DAPEvent& event);
    void SendStoppedEvent(const char* reason, int threadId, uint64_t addr);
    void SendOutputEvent(const char* category, const char* output);
    void SendExitedEvent(int exitCode);
    void SendTerminatedEvent();
    
private:
    // Message handling
    void ProcessMessage(const char* json);
    void DispatchRequest(const char* json, const char* command, int seq);
    
    // Request handlers
    void HandleInitialize(int seq, const char* json);
    void HandleLaunch(int seq, const char* json);
    void HandleAttach(int seq, const char* json);
    void HandleDisconnect(int seq, const char* json);
    void HandleConfigurationDone(int seq, const char* json);
    void HandleSetBreakpoints(int seq, const char* json);
    void HandleContinue(int seq, const char* json);
    void HandleNext(int seq, const char* json);
    void HandleStepIn(int seq, const char* json);
    void HandleStepOut(int seq, const char* json);
    void HandlePause(int seq, const char* json);
    void HandleStackTrace(int seq, const char* json);
    void HandleScopes(int seq, const char* json);
    void HandleVariables(int seq, const char* json);
    void HandleThreads(int seq, const char* json);
    void HandleReadMemory(int seq, const char* json);
    
    // Response builders
    void SendResponse(int seq, const char* command, bool success, const char* message = nullptr);
    void SendInitializeResponse(int seq);
    void SendCapabilitiesResponse(int seq);
    void SendEmptyResponse(int seq, const char* command);
    void SendSetBreakpointsResponse(int seq, const char* json);
    void SendStackTraceResponse(int seq, int threadId);
    void SendScopesResponse(int seq, int frameId);
    void SendVariablesResponse(int seq, int variablesReference);
    void SendThreadsResponse(int seq);
    void SendReadMemoryResponse(int seq, uint64_t addr, const void* data, size_t len);
    
    // Event builders
    void SendBreakpointEvent(int id, bool verified, const char* reason);
    
    // State
    DAPTransport m_transport;
    DebugSession* m_session = nullptr;
    bool m_running = false;
    int m_seq = 0;
    int m_nextBreakpointId = 1;
    bool m_initialized = false;
    bool m_configured = false;
    
    // Thread/frame tracking
    int m_currentThreadId = 1;
    int m_nextFrameId = 1;
    int m_nextVariablesRef = 1000;
};

} // namespace DAP
} // namespace RawrXD
