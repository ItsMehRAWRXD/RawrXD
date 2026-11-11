//=============================================================================
// RawrXD Debug Bridge
// Thread-safe communication between Debug Backend and UI
// Uses PostMessage for cross-thread marshalling
//=============================================================================
#pragma once

#include <windows.h>
#include <cstdint>
#include <functional>
#include <atomic>

// Include DebugBackend for type definitions
#include "DebugBackend.h"

// Forward declarations
namespace RawrXD {
namespace Debug {
    class DebugSession;
}
}

// Use types from Debug namespace
using RawrXD::Debug::StackFrame;
using RawrXD::Debug::RegisterContext;

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
    
    // Sequence tracking for producer/consumer telemetry
    uint64_t sequence;           // Monotonic sequence number
    uint64_t submitTimestamp;    // When event was submitted (ms)
    uint64_t renderTimestamp;    // When event was rendered (ms, set by UI)
    
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
                         sequence(0), submitTimestamp(0), renderTimestamp(0),
                         registers(nullptr), callStack(nullptr), callStackCount(0) {
        memset(&breakpoint, 0, sizeof(breakpoint));
    }
    
    // Calculate state age in milliseconds
    uint64_t GetStateAgeMs() const {
        if (renderTimestamp >= submitTimestamp) {
            return renderTimestamp - submitTimestamp;
        }
        return 0;
    }
};

//=============================================================================
// Debug Telemetry - Producer/Consumer metrics
//=============================================================================
struct DebugTelemetry {
    std::atomic<uint64_t> submittedSequence{0};      // Last sequence submitted by backend
    std::atomic<uint64_t> renderedSequence{0};       // Last sequence rendered by UI
    std::atomic<uint64_t> droppedEvents{0};        // Events dropped due to coalescing
    std::atomic<uint64_t> totalEvents{0};            // Total events generated
    
    std::atomic<uint64_t> lastStateAgeMs{0};         // Age of last rendered state
    std::atomic<uint64_t> maxStateAgeMs{0};          // Worst-case state age
    
    std::atomic<uint64_t> arenaHighWater{0};         // Peak memory usage
    std::atomic<uint64_t> currentArena{0};           // Current memory usage
    
    // Calculate sequence gaps (events submitted but not rendered)
    uint64_t GetSequenceGaps() const {
        uint64_t submitted = submittedSequence.load();
        uint64_t rendered = renderedSequence.load();
        return (submitted > rendered) ? (submitted - rendered) : 0;
    }
    
    // Record event submission (call from backend thread)
    void RecordSubmit(uint64_t seq) {
        submittedSequence.store(seq);
        totalEvents.fetch_add(1);
    }
    
    // Record event render (call from UI thread)
    void RecordRender(uint64_t seq, uint64_t ageMs) {
        renderedSequence.store(seq);
        lastStateAgeMs.store(ageMs);
        
        uint64_t maxAge = maxStateAgeMs.load();
        if (ageMs > maxAge) {
            maxStateAgeMs.store(ageMs);
        }
    }
    
    // Record dropped event
    void RecordDrop() {
        droppedEvents.fetch_add(1);
    }
    
    // Update arena usage
    void UpdateArena(uint64_t used, uint64_t highWater) {
        currentArena.store(used);
        arenaHighWater.store(highWater);
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
    void AttachSession(RawrXD::Debug::DebugSession* session);
    void DetachSession();
    RawrXD::Debug::DebugSession* GetSession() const { return m_session; }
    
    // Telemetry access
    DebugTelemetry& GetTelemetry() { return m_telemetry; }
    const DebugTelemetry& GetTelemetry() const { return m_telemetry; }
    
    // Log telemetry summary to debugger output
    void LogTelemetrySummary();
    
private:
    DebugBridge() = default;
    ~DebugBridge() = default;
    
    HWND m_hUIWindow = nullptr;
    RawrXD::Debug::DebugSession* m_session = nullptr;
    EventCallback m_eventCallback;
    CRITICAL_SECTION m_cs;  // Protects session access
    
    // Sequence counter for events
    std::atomic<uint64_t> m_sequenceCounter{0};
    
    // Telemetry
    DebugTelemetry m_telemetry;
    
    // State coalescing: drop stale events when UI is behind
    bool ShouldCoalesceEvent(DebugBridgeEvent* newEvent);
    
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
