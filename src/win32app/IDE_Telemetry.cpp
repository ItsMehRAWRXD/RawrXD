#include "IDE_Telemetry.hpp"
#include <cstdio>
#include <cstring>
#include <algorithm>

namespace RawrXD {
namespace Telemetry {

// Static member definitions
double TelemetrySink::qpcFrequencyInv_ = 0.0;
uint64_t TelemetrySink::qpcFrequency_ = 0;

// ============================================================================
// TelemetrySink Implementation
// ============================================================================

void TelemetrySink::Initialize() {
    if (initialized_.exchange(true, std::memory_order_acq_rel)) {
        return;  // Already initialized
    }

    LARGE_INTEGER freq;
    if (QueryPerformanceFrequency(&freq)) {
        qpcFrequency_ = static_cast<uint64_t>(freq.QuadPart);
        qpcFrequencyInv_ = 1.0 / static_cast<double>(qpcFrequency_);
    } else {
        // Fallback: assume 1MHz (common on modern Windows)
        qpcFrequency_ = 1000000ULL;
        qpcFrequencyInv_ = 1.0 / 1000000.0;
    }

    // Log initialization
    char msg[256];
    snprintf(msg, sizeof(msg), "[Telemetry] Initialized. QPC Frequency: %llu Hz\n", 
             static_cast<unsigned long long>(qpcFrequency_));
    OutputDebugStringA(msg);
}

uint64_t TelemetrySink::NowQpc() {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return static_cast<uint64_t>(now.QuadPart);
}

uint64_t TelemetrySink::QpcToNs(uint64_t qpc) {
    return static_cast<uint64_t>(static_cast<double>(qpc) * qpcFrequencyInv_ * 1e9);
}

void TelemetrySink::PushSample(const char* metricName, uint64_t value, SampleType type) {
    if (!initialized_.load(std::memory_order_acquire)) {
        return;
    }

    TelemetrySample sample;
    sample.timestampQpc = NowQpc();
    sample.value = value;
    sample.type = type;
    sample.threadId = static_cast<uint8_t>(GetCurrentThreadId() & 0xFF);
    
    // Safe string copy
    strncpy_s(sample.metricName, metricName, kMaxMetricNameLen - 1);
    sample.metricName[kMaxMetricNameLen - 1] = '\0';

    // Lock-free push (may drop if buffer full)
    if (!ringBuffer_.Push(sample)) {
        // Buffer overflow - increment overflow counter (atomic)
        static std::atomic<uint64_t> overflowCount{0};
        overflowCount.fetch_add(1, std::memory_order_relaxed);
    }
}

void TelemetrySink::PushDuration(const char* metricName, uint64_t startQpc, uint64_t endQpc) {
    const uint64_t duration = (endQpc > startQpc) ? (endQpc - startQpc) : 0;
    PushSample(metricName, duration, SampleType::Duration);
}

void TelemetrySink::PushGauge(const char* metricName, uint64_t value) {
    PushSample(metricName, value, SampleType::Gauge);
}

void TelemetrySink::PushCounter(const char* metricName, uint64_t delta) {
    PushSample(metricName, delta, SampleType::Counter);
}

void TelemetrySink::SampleMemory(const char* contextLabel) {
    if (!initialized_.load(std::memory_order_acquire)) {
        return;
    }

    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        // Working set size in bytes
        PushGauge("Memory.WorkingSet", pmc.WorkingSetSize);
        PushGauge("Memory.PrivateBytes", pmc.PrivateUsage);
        
        // Also push a labeled sample for context
        char labeledMetric[64];
        snprintf(labeledMetric, sizeof(labeledMetric), "Memory.WorkingSet.%s", contextLabel);
        PushGauge(labeledMetric, pmc.WorkingSetSize);
    }
}

void TelemetrySink::FlushSamples() {
    TelemetrySample sample;
    size_t flushed = 0;

    while (ringBuffer_.Pop(sample)) {
        // Convert to nanoseconds for human-readable output
        const uint64_t durationNs = QpcToNs(sample.value);
        
        // Output to debug stream (or file, or network)
        char output[256];
        const char* typeStr = "?";
        switch (sample.type) {
            case SampleType::Duration: typeStr = "DUR"; break;
            case SampleType::Counter:  typeStr = "CTR"; break;
            case SampleType::Gauge:    typeStr = "GAU"; break;
            case SampleType::UIStall:  typeStr = "UI!"; break;
            case SampleType::ThreadEvent: typeStr = "THR"; break;
        }

        snprintf(output, sizeof(output), 
                 "[TELEMETRY] %s | %s | %llu ns | tid=%u\n",
                 typeStr, sample.metricName, 
                 static_cast<unsigned long long>(durationNs),
                 sample.threadId);
        
        OutputDebugStringA(output);
        flushed++;
    }

    if (flushed > 0) {
        char msg[64];
        snprintf(msg, sizeof(msg), "[Telemetry] Flushed %zu samples\n", flushed);
        OutputDebugStringA(msg);
    }
}

// ============================================================================
// UIWatchdog Implementation
// ============================================================================

UIWatchdog& UIWatchdog::Instance() {
    static UIWatchdog instance;
    return instance;
}

void UIWatchdog::Initialize(HWND hwndMain) {
    if (running_.exchange(true, std::memory_order_acq_rel)) {
        return;  // Already running
    }

    hwndMain_ = hwndMain;
    lastPumpQpc_.store(TelemetrySink::NowQpc(), std::memory_order_release);
    stallDetected_.store(false, std::memory_order_release);

    hThread_ = CreateThread(nullptr, 0, WatchdogThreadProc, this, 0, nullptr);
    if (hThread_) {
        SetThreadPriority(hThread_, THREAD_PRIORITY_ABOVE_NORMAL);
        OutputDebugStringA("[UIWatchdog] Initialized\n");
    }
}

void UIWatchdog::Shutdown() {
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    if (hThread_) {
        WaitForSingleObject(hThread_, 1000);  // 1 second timeout
        CloseHandle(hThread_);
        hThread_ = nullptr;
    }

    OutputDebugStringA("[UIWatchdog] Shutdown\n");
}

void UIWatchdog::OnMessagePumpTick() {
    lastPumpQpc_.store(TelemetrySink::NowQpc(), std::memory_order_release);
    stallDetected_.store(false, std::memory_order_release);
}

bool UIWatchdog::IsStalling() const {
    return stallDetected_.load(std::memory_order_acquire);
}

DWORD WINAPI UIWatchdog::WatchdogThreadProc(LPVOID param) {
    UIWatchdog* self = static_cast<UIWatchdog*>(param);
    
    // 16ms threshold = ~60fps target
    const uint64_t stallThresholdTicks = static_cast<uint64_t>(
        0.016 * TelemetrySink::qpcFrequencyInv_ * TelemetrySink::qpcFrequency_);
    
    while (self->running_.load(std::memory_order_acquire)) {
        Sleep(5);  // Check every 5ms

        const uint64_t now = TelemetrySink::NowQpc();
        const uint64_t lastPump = self->lastPumpQpc_.load(std::memory_order_acquire);
        
        if (now > lastPump) {
            const uint64_t elapsed = now - lastPump;
            if (elapsed > stallThresholdTicks) {
                // UI stall detected
                if (!self->stallDetected_.exchange(true, std::memory_order_acq_rel)) {
                    // First detection - log it
                    const uint64_t elapsedMs = (elapsed * 1000) / TelemetrySink::qpcFrequency_;
                    
                    TelemetrySample sample;
                    sample.timestampQpc = now;
                    sample.value = elapsedMs;  // Store ms in value
                    sample.type = SampleType::UIStall;
                    sample.threadId = 255;  // Watchdog thread
                    strncpy_s(sample.metricName, "UI.MessageLoopStall", kMaxMetricNameLen - 1);
                    
                    TelemetrySink::Instance().PushSample("UI.MessageLoopStall", elapsedMs, SampleType::UIStall);
                    
                    char msg[128];
                    snprintf(msg, sizeof(msg), "[UIWatchdog] STALL DETECTED: %llu ms\n", 
                             static_cast<unsigned long long>(elapsedMs));
                    OutputDebugStringA(msg);
                }
            }
        }
    }

    return 0;
}

} // namespace Telemetry
} // namespace RawrXD
