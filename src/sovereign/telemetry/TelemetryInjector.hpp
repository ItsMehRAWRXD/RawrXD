// ============================================================================
// TelemetryInjector.hpp - Real-time Performance Telemetry Injection
// Zero-overhead instrumentation for the Sovereign runtime
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <atomic>
#include <chrono>

namespace Sovereign {

// Telemetry event types
enum class TelemetryEventType {
    CPU_CYCLE,
    CACHE_MISS,
    PAGE_FAULT,
    ALLOCATION,
    DEALLOCATION,
    THREAD_SWITCH,
    CONTEXT_SWITCH,
    SYSCALL,
    GPU_KERNEL,
    GPU_MEMCPY,
    NETWORK_SEND,
    NETWORK_RECV,
    DISK_READ,
    DISK_WRITE,
    AGENT_ACTION,
    TOOL_CALL,
    MODEL_INFERENCE,
    PATCH_APPLY,
    PATCH_ROLLBACK
};

// Telemetry event
struct TelemetryEvent {
    TelemetryEventType type;
    uint64_t timestamp;
    uint64_t duration;
    uint64_t threadId;
    uint64_t data0;
    uint64_t data1;
    uint64_t data2;
    const char* label;
};

// Telemetry ring buffer entry
struct TelemetryEntry {
    TelemetryEvent event;
    uint64_t sequence;
    bool valid;
};

// Telemetry statistics
struct TelemetryStats {
    uint64_t totalEvents;
    uint64_t eventsPerSecond;
    uint64_t droppedEvents;
    uint64_t bufferOverflows;
    uint64_t peakBufferUsage;
    double avgEventLatency;
};

// Telemetry injector
class TelemetryInjector {
public:
    TelemetryInjector();
    ~TelemetryInjector();

    // Initialize
    bool Initialize(size_t bufferSize = 65536);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    // Event injection
    void Inject(const TelemetryEvent& event);
    void InjectSimple(TelemetryEventType type, uint64_t duration = 0);
    void InjectWithData(TelemetryEventType type, uint64_t duration, uint64_t d0, uint64_t d1 = 0, uint64_t d2 = 0);

    // Batch injection
    void InjectBatch(const TelemetryEvent* events, size_t count);

    // Event consumption
    size_t Consume(TelemetryEvent* buffer, size_t maxCount);
    size_t GetAvailableCount() const;

    // Ring buffer management
    void Clear();
    void Resize(size_t newSize);

    // Statistics
    TelemetryStats GetStats() const;
    void ResetStats();

    // Callbacks
    void SetEventCallback(std::function<void(const TelemetryEvent&)> callback);
    void SetThresholdCallback(TelemetryEventType type, uint64_t threshold, 
                              std::function<void(const TelemetryEvent&)> callback);

    // Filtering
    void EnableEventType(TelemetryEventType type);
    void DisableEventType(TelemetryEventType type);
    bool IsEventEnabled(TelemetryEventType type) const;

    // Export
    bool ExportToJSON(const std::string& path);
    bool ExportToCSV(const std::string& path);

    // High-precision timing
    static uint64_t GetTimestamp();
    static uint64_t GetCPUCycles();
    static uint64_t GetThreadId();

private:
    bool initialized_ = false;
    std::atomic<uint64_t> writeIndex_{0};
    std::atomic<uint64_t> readIndex_{0};
    uint64_t sequence_ = 0;
    
    TelemetryEntry* buffer_ = nullptr;
    size_t bufferSize_ = 0;
    size_t bufferMask_ = 0;
    
    TelemetryStats stats_;
    mutable std::mutex mutex_;
    
    // Event type filters
    uint64_t enabledTypes_ = ~0ULL; // All enabled by default
    
    // Callbacks
    std::function<void(const TelemetryEvent&)> eventCallback_;
    std::vector<std::pair<uint64_t, std::function<void(const TelemetryEvent&)>>> thresholdCallbacks_;
    
    // Internal
    void ProcessEvent(const TelemetryEvent& event);
};

// Scoped telemetry timer (RAII)
class ScopedTelemetryTimer {
public:
    ScopedTelemetryTimer(TelemetryInjector& injector, TelemetryEventType type, const char* label = nullptr);
    ~ScopedTelemetryTimer();
    
    void Cancel() { cancelled_ = true; }
    uint64_t GetElapsed() const;

private:
    TelemetryInjector& injector_;
    TelemetryEventType type_;
    const char* label_;
    uint64_t start_;
    bool cancelled_ = false;
};

// Telemetry macro for easy injection
#define TELEMETRY_INJECT(injector, type) \
    do { \
        Sovereign::TelemetryEvent _tevt; \
        _tevt.type = (type); \
        _tevt.timestamp = Sovereign::TelemetryInjector::GetTimestamp(); \
        _tevt.threadId = Sovereign::TelemetryInjector::GetThreadId(); \
        (injector).Inject(_tevt); \
    } while(0)

#define TELEMETRY_SCOPE(injector, type) \
    Sovereign::ScopedTelemetryTimer _stt_##__LINE__(injector, type, #type)

} // namespace Sovereign
