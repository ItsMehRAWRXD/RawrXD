//=============================================================================
// RawrXD Debug Bridge
// Thread-safe communication between Debug Backend and UI
// Uses PostMessage for cross-thread marshalling
//=============================================================================
#pragma once

#include <windows.h>
#include <cstdint>
#include <functional>

// Forward declarations
struct DebugSession;
struct StackFrame;
struct RegisterContext;

namespace RawrXD {
namespace DebugUI {

// Custom window message for debug events
#define WM_APP_DEBUG_EVENT (WM_APP + 1)

// Debug event types passed via PostMessage
enum class DebugBridgeEventType : uint32_t {
    None = 0,
    BreakpointHit,
    Exception,
    SingleStep,
    ProcessCreated,
    ProcessExited,
    ThreadCreated,
    ThreadExited,
    DllLoaded,
    DllUnloaded,
    OutputDebugString,
    StepComplete
};

// Event data structure (must be heap-allocated for PostMessage)
struct DebugBridgeEvent {
    DebugBridgeEventType type;
    uint32_t processId;
    uint32_t threadId;
    union {
        struct {
            uint64_t address;
        } breakpoint;
        struct {
            uint32_t code;
            uint64_t address;
        } exception;
        struct {
            uint64_t exitCode;
        } processExit;
        struct {
            uint64_t baseAddress;
            wchar_t path[260];
        } dllLoad;
    };
    
    // Context at event time
    RegisterContext* registers;
    StackFrame* callStack;
    int callStackCount;
    
    DebugBridgeEvent() : type(DebugBridgeEventType::None), processId(0), threadId(0),
                         registers(nullptr), callStack(nullptr), callStackCount(0) {
        memset(&breakpoint, 0, sizeof(breakpoint));
    }
};

//=============================================================================
// Debug Bridge
// Singleton that marshals events from backend thread to UI thread
//=============================================================================
class DebugBridge {
public:
    static DebugBridge& Instance();
    
    // Initialize with target UI window handle
    void Initialize(HWND hUIWindow);
    void Shutdown();
    
    // Backend thread: Call this to post events to UI
    void PostEvent(DebugBridgeEvent* event);
    
    // UI thread: Process pending events (call from WM_APP_DEBUG_EVENT handler)
    void ProcessEvent(DebugBridgeEvent* event);
    
    // Set callbacks for event handling
    using EventCallback = std::function<void(DebugBridgeEvent*)>;
    void SetEventCallback(EventCallback callback);
    
    // Direct queries (thread-safe wrappers around backend)
    bool ReadMemory(uint64_t addr, void* buffer, size_t size);
    bool WriteMemory(uint64_t addr, const void* buffer, size_t size);
    bool GetCallStack(StackFrame* frames, int maxFrames, int* outCount);
    bool GetRegisters(RegisterContext* ctx);
    bool SetRegisters(const RegisterContext* ctx);
    bool Continue();
    bool StepInto();
    bool StepOver();
    bool StepOut();
    bool Break();
    
    // Session management
    void AttachSession(DebugSession* session);
    void DetachSession();
    DebugSession* GetSession() const { return m_session; }
    
private:
    DebugBridge() = default;
    ~DebugBridge() = default;
    
    HWND m_hUIWindow = nullptr;
    DebugSession* m_session = nullptr;
    EventCallback m_eventCallback;
    CRITICAL_SECTION m_cs;  // Protects session access
    
    void Lock() { EnterCriticalSection(&m_cs); }
    void Unlock() { LeaveCriticalSection(&m_cs); }
};

//=============================================================================
// Debug Event Handler
// Base class for objects that receive debug events
//=============================================================================
class IDebugEventHandler {
public:
    virtual ~IDebugEventHandler() = default;
    virtual void OnDebugEvent(DebugBridgeEvent* event) = 0;
};

} // namespace DebugUI
} // namespace RawrXD
