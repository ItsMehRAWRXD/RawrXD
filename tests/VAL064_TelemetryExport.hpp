#pragma once
// VAL064_TelemetryExport.hpp
// Header for RawrXD to export telemetry to VAL-064 certification harness
// Include this in NativeBackend or inference engine code

#include <cstdint>
#include <cstring>
#include <string>
#include <atomic>
#include <chrono>

namespace val064 {

// Version of the telemetry structure
constexpr uint32_t VAL064_TELEMETRY_VERSION = 1;

// Shared memory name for Windows
constexpr const char* VAL064_SHM_NAME = "Global\\RawrXD_Telemetry";

// Telemetry data structure - matches VAL064_TelemetryAdapter expectations
struct alignas(64) TelemetryData {
    volatile uint32_t version = VAL064_TELEMETRY_VERSION;
    volatile uint32_t sequence = 0;
    volatile double prefill_tps = 0.0;
    volatile double decode_tps = 0.0;
    volatile double first_token_ms = 0.0;
    volatile double peak_vram_mb = 0.0;
    volatile double peak_ram_mb = 0.0;
    volatile int prompt_tokens = 0;
    volatile int generated_tokens = 0;
    volatile uint64_t timestamp_ns = 0;
    volatile bool valid = false;
    char error_message[256] = {0};
    
    // Padding to ensure 64-byte alignment
    char _padding[24] = {0};
};

// Telemetry exporter class - singleton for easy integration
class TelemetryExporter {
public:
    static TelemetryExporter& Instance() {
        static TelemetryExporter instance;
        return instance;
    }
    
    // Initialize shared memory (call once at startup)
    bool Initialize();
    
    // Shutdown and cleanup
    void Shutdown();
    
    // Export telemetry data
    bool Export(const TelemetryData& data);
    
    // Convenience method to populate and export
    bool ExportMetrics(
        double prefill_tps,
        double decode_tps,
        double first_token_ms,
        double peak_vram_mb,
        double peak_ram_mb,
        int prompt_tokens,
        int generated_tokens
    );
    
    // Check if exporter is ready
    bool IsReady() const { return initialized_; }
    
private:
    TelemetryExporter() = default;
    ~TelemetryExporter() { Shutdown(); }
    
    TelemetryExporter(const TelemetryExporter&) = delete;
    TelemetryExporter& operator=(const TelemetryExporter&) = delete;
    
#ifdef _WIN32
    void* shm_handle_ = nullptr;
    void* shm_view_ = nullptr;
#endif
    bool initialized_ = false;
    std::atomic<uint32_t> sequence_{0};
};

// RAII helper for timing measurements
class ScopedTiming {
public:
    explicit ScopedTiming(double& out_ms) : out_ms_(out_ms) {
        start_ = std::chrono::high_resolution_clock::now();
    }
    
    ~ScopedTiming() {
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration<double, std::milli>(end - start_).count();
        out_ms_ = duration;
    }
    
private:
    double& out_ms_;
    std::chrono::high_resolution_clock::time_point start_;
};

// Convenience macros for integration
#define VAL064_INIT() val064::TelemetryExporter::Instance().Initialize()
#define VAL064_EXPORT(data) val064::TelemetryExporter::Instance().Export(data)
#define VAL064_EXPORT_METRICS(prefill, decode, ttft, vram, ram, prompt, gen) \
    val064::TelemetryExporter::Instance().ExportMetrics(prefill, decode, ttft, vram, ram, prompt, gen)
#define VAL064_SHUTDOWN() val064::TelemetryExporter::Instance().Shutdown()

} // namespace val064
