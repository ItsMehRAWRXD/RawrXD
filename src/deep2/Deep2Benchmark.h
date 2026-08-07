#pragma once

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>
#include <chrono>

namespace Deep2 {

// ============================================================================
// Benchmark Phase Enumeration
// ============================================================================
enum class BenchmarkPhase : uint8_t {
    PREFILL = 0,        // Prompt ingestion throughput
    DECODE = 1,         // Token-by-token generation
    STREAM = 2,         // Sustained decode over N tokens
    ENDURANCE = 3,      // TPS decay vs context growth
    SATURATION = 4,     // Multi-stream aggregate throughput
    THERMAL = 5,        // Sustained performance under load
    LATENCY = 6         // First token and per-token latency
};

// ============================================================================
// Stream Benchmark Telemetry Structure
// Native ABI for Deep2 Engine telemetry emission
// ============================================================================
struct __attribute__((packed)) StreamBenchmark {
    // Identity
    uint64_t    timestamp_ns;
    uint32_t    model_id_hash;
    uint16_t    quant_bits;         // 2, 4, 8, 16
    uint16_t    context_length;
    
    // Tokens
    uint64_t    prompt_tokens;
    uint64_t    generated_tokens;
    uint64_t    target_tokens;
    
    // Timing (nanoseconds for precision, reported as ms)
    uint64_t    first_token_ns;
    uint64_t    total_decode_ns;
    uint64_t    per_token_min_ns;
    uint64_t    per_token_max_ns;
    uint64_t    per_token_avg_ns;
    
    // Throughput
    double      prefill_tps;
    double      decode_tps;
    double      sustained_tps;      // TPS at 90% of stream completion
    
    // Memory
    uint64_t    kv_bytes;
    uint64_t    peak_vram_bytes;
    uint64_t    peak_system_bytes;
    double      kv_bytes_per_token;
    
    // GPU
    uint64_t    gpu_cycles;
    uint32_t    kernel_calls;
    uint32_t    gpu_util_percent;
    uint32_t    vram_util_percent;
    uint32_t    temperature_c;
    uint32_t    power_watts;
    
    // Stability
    uint32_t    token_drops;        // Missed decode deadlines
    uint32_t    thermal_throttle_events;
    double      tps_variance;       // Coefficient of variation
    
    // Stream health
    bool        stream_stable;
    double      degradation_ratio;    // TPS(end) / TPS(start)
    
    StreamBenchmark() {
        memset(this, 0, sizeof(*this));
    }
};

// ============================================================================
// Endurance Test Result
// ============================================================================
struct EnduranceResult {
    uint32_t    context_size;
    double      prefill_tps;
    double      decode_tps;
    double      sustained_tps;
    double      kv_bytes_per_token;
    uint64_t    peak_vram_bytes;
    bool        stable;
};

// ============================================================================
// Saturation Test Result
// ============================================================================
struct SaturationResult {
    uint32_t        num_streams;
    double          aggregate_tps;
    double          worst_first_token_ms;
    double          avg_stream_tps;
    uint64_t        total_tokens_generated;
    bool            all_streams_stable;
};

// ============================================================================
// Thermal Test Result
// ============================================================================
struct ThermalResult {
    uint32_t    duration_seconds;
    uint32_t    peak_temp_c;
    uint32_t    throttle_events;
    double      avg_power_watts;
    double      tps_start;
    double      tps_end;
    double      tps_degradation_percent;
};

// ============================================================================
// Certification Report
// ============================================================================
struct CertificationReport {
    std::string certification_id;
    std::string timestamp;
    std::string hardware_summary;
    std::string model_info;
    
    // Phase results
    StreamBenchmark     single_stream;
    std::vector<EnduranceResult> endurance_matrix;
    SaturationResult    saturation;
    ThermalResult       thermal;
    
    // Overall status
    bool prefill_pass;
    bool decode_pass;
    bool stream_pass;
    bool endurance_pass;
    bool saturation_pass;
    bool thermal_pass;
    bool overall_certified;
    
    // Targets
    double target_prefill_tps;
    double target_decode_tps;
    double target_sustained_tps;
    uint32_t target_max_context;
};

// ============================================================================
// Benchmark Configuration
// ============================================================================
struct BenchmarkConfig {
    // Model
    std::string model_path;
    std::string model_name;
    uint16_t    quant_bits = 4;
    
    // Single stream test
    std::string prompt_text;
    uint64_t    max_tokens = 8192;
    uint32_t    context_size = 32768;
    
    // Endurance matrix
    std::vector<uint32_t> endurance_contexts = {1024, 4096, 8192, 16384, 32768};
    uint64_t    endurance_tokens_per_test = 2048;
    
    // Saturation test
    uint32_t    saturation_streams = 4;
    uint64_t    saturation_tokens_per_stream = 2048;
    uint32_t    saturation_ctx_per_stream = 8192;
    
    // Thermal test
    uint32_t    thermal_duration_seconds = 1800;  // 30 minutes
    uint32_t    thermal_sample_interval_seconds = 5;
    
    // Thresholds
    double      degradation_threshold = 0.75;     // 75% = failure
    double      variance_threshold = 0.15;          // 15% CV = unstable
    
    // Output
    std::string output_path = "deep2_benchmark_report.json";
    bool        emit_telemetry = true;
    bool        verbose = true;
};

// ============================================================================
// Benchmark Harness Interface
// ============================================================================
class BenchmarkHarness {
public:
    BenchmarkHarness();
    ~BenchmarkHarness();
    
    // Initialize with Deep2 engine
    bool initialize(const std::string& modelPath);
    
    // Run complete certification suite
    CertificationReport runFullCertification(const BenchmarkConfig& config);
    
    // Individual test phases
    StreamBenchmark runSingleStreamTest(
        const std::string& prompt,
        uint64_t maxTokens,
        uint32_t ctxSize
    );
    
    std::vector<EnduranceResult> runEnduranceMatrix(
        const std::vector<uint32_t>& contextSizes,
        uint64_t tokensPerTest
    );
    
    SaturationResult runSaturationTest(
        uint32_t numStreams,
        uint64_t tokensPerStream,
        uint32_t ctxPerStream
    );
    
    ThermalResult runThermalTest(
        uint32_t durationSeconds,
        uint32_t sampleIntervalSeconds
    );
    
    // Emit telemetry
    void emitBenchmarkTelemetry(const StreamBenchmark& bench, BenchmarkPhase phase);
    
    // Generate reports
    std::string generateJSONReport(const CertificationReport& report);
    std::string generateMarkdownReport(const CertificationReport& report);
    void saveReport(const CertificationReport& report, const std::string& path);
    
    // Utility
    static uint64_t nowNs();
    static std::string formatBytes(uint64_t bytes);
    static std::string formatTps(double tps);
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// ============================================================================
// Global benchmark telemetry emitter
// ============================================================================
void EmitBenchmarkTelemetry(const StreamBenchmark& bench, BenchmarkPhase phase);

} // namespace Deep2
