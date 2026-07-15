#pragma once

// ============================================================================
// IDE_Telemetry.hpp - Lock-Free Performance Instrumentation
// ============================================================================
// Design goals:
//   - Zero-allocation hot path (ring buffer pre-allocated)
//   - Lock-free sampling (std::atomic index manipulation)
//   - <100ns overhead per sample (QPC + atomic ops only)
//   - No logging in hot path (batched async flush)
//
// Thread safety: Producer threads (any) → Lock-free ring buffer → Consumer thread (telemetry)
// ============================================================================

#include <windows.h>
#include <atomic>
#include <cstdint>
#include <array>
#include <string>
#include <psapi.h>

namespace RawrXD {
namespace Telemetry {

// Configuration
constexpr size_t kTelemetryRingBufferSize = 4096;  // Power of 2 for mask optimization
constexpr size_t kMaxMetricNameLen = 32;
constexpr uint64_t kNsPerQpc = 1000000000ULL;  // Will be calibrated at init

// Sample types
enum class SampleType : uint8_t {
    Duration = 0,      // Scoped timer start→end
    Counter = 1,       // Increment-only (queue depth, etc.)
    Gauge = 2,         // Point-in-time value (memory, CPU)
    UIStall = 3,       // Message loop stall detected
    ThreadEvent = 4    // Thread start/stop/affinity change
};

// Single telemetry sample (64 bytes, cache-line friendly)
struct alignas(64) TelemetrySample {
    uint64_t timestampQpc;                    // QPC timestamp
    uint64_t value;                           // Duration (ticks), count, or gauge value
    char metricName[kMaxMetricNameLen];     // Null-terminated metric identifier
    SampleType type;
    uint8_t threadId;                         // Logical thread ID (0-255)
    uint16_t padding;                         // Align to 64 bytes

    TelemetrySample() : timestampQpc(0), value(0), type(SampleType::Duration), threadId(0), padding(0) {
        metricName[0] = '\0';
    }
};

static_assert(sizeof(TelemetrySample) == 64, "TelemetrySample must be 64 bytes for cache alignment");

// ============================================================================
// Lock-Free Ring Buffer
// Single-producer-safe (per thread), multi-consumer via atomic index
// ============================================================================
class LockFreeRingBuffer {
public:
    LockFreeRingBuffer() : writeIndex_(0), readIndex_(0) {
        samples_.fill({});
    }

    // Push a sample. Returns false if buffer full (samples dropped).
    // Lock-free: single atomic fetch_add
    bool Push(const TelemetrySample& sample) {
        const size_t index = writeIndex_.fetch_add(1, std::memory_order_relaxed);
        const size_t slot = index & (kTelemetryRingBufferSize - 1);

        // Check for overflow (simplified: if write - read > size, drop)
        const size_t currentRead = readIndex_.load(std::memory_order_acquire);
        if (index - currentRead >= kTelemetryRingBufferSize) {
            // Buffer full - drop sample (or block, but we choose drop for zero-latency)
            return false;
        }

        samples_[slot] = sample;
        samples_[slot].timestampQpc = sample.timestampQpc;
        return true;
    }

    // Pop a sample. Returns false if empty.
    // Called by dedicated telemetry thread only
    bool Pop(TelemetrySample& outSample) {
        const size_t currentRead = readIndex_.load(std::memory_order_relaxed);
        const size_t currentWrite = writeIndex_.load(std::memory_order_acquire);

        if (currentRead >= currentWrite) {
            return false;  // Empty
        }

        const size_t slot = currentRead & (kTelemetryRingBufferSize - 1);
        outSample = samples_[slot];
        readIndex_.store(currentRead + 1, std::memory_order_release);
        return true;
    }

    size_t Size() const {
        return writeIndex_.load(std::memory_order_acquire) - readIndex_.load(std::memory_order_acquire);
    }

    bool IsEmpty() const {
        return writeIndex_.load(std::memory_order_acquire) == readIndex_.load(std::memory_order_acquire);
    }

private:
    alignas(64) std::atomic<size_t> writeIndex_;
    alignas(64) std::atomic<size_t> readIndex_;
    std::array<TelemetrySample, kTelemetryRingBufferSize> samples_;
};

// ============================================================================
// Global Telemetry Sink
// Thread-safe singleton for all producers
// ============================================================================
class TelemetrySink {
public:
    static TelemetrySink& Instance() {
        static TelemetrySink instance;
        return instance;
    }

    // Initialize QPC frequency calibration
    void Initialize();

    // Push sample from any thread (lock-free)
    void PushSample(const char* metricName, uint64_t value, SampleType type);

    // Push duration sample (convenience)
    void PushDuration(const char* metricName, uint64_t startQpc, uint64_t endQpc);

    // Push gauge sample (memory, CPU, etc.)
    void PushGauge(const char* metricName, uint64_t value);

    // Push counter increment
    void PushCounter(const char* metricName, uint64_t delta);

    // Flush samples to output (called by telemetry thread)
    void FlushSamples();

    // Get current QPC timestamp
    static uint64_t NowQpc();

    // Convert QPC ticks to nanoseconds
    static uint64_t QpcToNs(uint64_t qpc);

    // Memory sampling (PSAPI)
    void SampleMemory(const char* contextLabel);

    bool IsInitialized() const { return initialized_.load(std::memory_order_acquire); }

private:
    TelemetrySink() = default;
    ~TelemetrySink() = default;
    TelemetrySink(const TelemetrySink&) = delete;
    TelemetrySink& operator=(const TelemetrySink&) = delete;

    LockFreeRingBuffer ringBuffer_;
    std::atomic<bool> initialized_{false};
    static double qpcFrequencyInv_;  // 1.0 / QPC frequency for ns conversion
    static uint64_t qpcFrequency_;
};

// ============================================================================
// Scoped Performance Timer (RAII)
// Usage: PerfScopeTimer timer("VoiceTaskLatency");
// ============================================================================
class PerfScopeTimer {
public:
    explicit PerfScopeTimer(const char* metricName) : metricName_(metricName), active_(true) {
        if (TelemetrySink::Instance().IsInitialized()) {
            startQpc_ = TelemetrySink::NowQpc();
        } else {
            active_ = false;
        }
    }

    ~PerfScopeTimer() {
        if (active_) {
            const uint64_t endQpc = TelemetrySink::NowQpc();
            TelemetrySink::Instance().PushDuration(metricName_, startQpc_, endQpc);
        }
    }

    // Manual stop (optional, for conditional timing)
    void Stop() {
        if (active_) {
            const uint64_t endQpc = TelemetrySink::NowQpc();
            TelemetrySink::Instance().PushDuration(metricName_, startQpc_, endQpc);
            active_ = false;
        }
    }

    // Cancel timer without recording
    void Cancel() { active_ = false; }

private:
    const char* metricName_;
    uint64_t startQpc_;
    bool active_;
};

// ============================================================================
// UI Watchdog - Detects message loop stalls
// ============================================================================
class UIWatchdog {
public:
    static UIWatchdog& Instance();

    void Initialize(HWND hwndMain);
    void Shutdown();

    // Call this from the message loop (GetMessage/dispatch)
    void OnMessagePumpTick();

    // Check if UI is stalling (>16ms between pumps)
    bool IsStalling() const;

private:
    UIWatchdog() = default;
    ~UIWatchdog() = default;

    static DWORD WINAPI WatchdogThreadProc(LPVOID param);

    std::atomic<bool> running_{false};
    std::atomic<uint64_t> lastPumpQpc_{0};
    std::atomic<bool> stallDetected_{false};
    HANDLE hThread_ = nullptr;
    HWND hwndMain_ = nullptr;
};

// ============================================================================
// Convenience Macros (zero-cost when telemetry disabled)
// ============================================================================
#ifdef RAWRXD_ENABLE_TELEMETRY
    #define PERF_SCOPE(name) RawrXD::Telemetry::PerfScopeTimer _perfTimer(name)
    #define PERF_COUNTER(name, delta) RawrXD::Telemetry::TelemetrySink::Instance().PushCounter(name, delta)
    #define PERF_GAUGE(name, value) RawrXD::Telemetry::TelemetrySink::Instance().PushGauge(name, value)
#else
    #define PERF_SCOPE(name) ((void)0)
    #define PERF_COUNTER(name, delta) ((void)0)
    #define PERF_GAUGE(name, value) ((void)0)
#endif

} // namespace Telemetry
} // namespace RawrXD
