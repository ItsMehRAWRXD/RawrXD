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

// Fail reason codes for certification (hard guards)
enum BenchmarkFailReason : uint32_t {
    BENCH_FAIL_NONE = 0,
    BENCH_FAIL_NON_PRODUCTION_DECODE_PATH = 1,
    BENCH_FAIL_DECODE_UNSTABLE = 2,
    BENCH_FAIL_ZERO_TOKENS = 3,          // symptom; prefer owner codes below
    BENCH_FAIL_INSUFFICIENT_WINDOWS = 4,
    BENCH_FAIL_LOAD_FAILED = 5,
    BENCH_FAIL_PREFILL_FAILED = 6,
    BENCH_FAIL_DECODE_NOT_ENTERED = 7,
    BENCH_FAIL_SAMPLER_FAILED = 8,
    BENCH_FAIL_EOS_BEFORE_FIRST_TOKEN = 9,
    BENCH_FAIL_TOKEN_CALLBACK_NOT_FIRED = 10,
    BENCH_FAIL_RUN_VOID = 11,
    BENCH_FAIL_COMPLETION_BLOCKED = 12,
};

// Full 512-token windows required before endurance / certify stream lock.
constexpr uint64_t kBenchDecodeWindowTokens = 512;
constexpr uint32_t kBenchRequiredFullWindowsCertify = 4;

// Rolling decode window (endurance / stability)
struct DecodeWindow {
    uint64_t tokenBegin = 0;
    uint64_t tokenEnd = 0;
    double   seconds = 0.0;
    double   tps = 0.0;
    uint64_t ns_per_token = 0; // authority: (last-first)/(count-1)
    uint64_t vramBytes = 0;
    uint64_t kvBytes = 0;
};

// ============================================================================
// Stream Benchmark Telemetry Structure
// Native ABI for Deep2 Engine telemetry emission
// ============================================================================
#pragma pack(push, 1)
struct StreamBenchmark {
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
    uint64_t    first_token_ns;                 // legacy: TTFT_E2E
    uint64_t    total_decode_ns;
    uint64_t    per_token_min_ns;
    uint64_t    per_token_max_ns;
    uint64_t    per_token_avg_ns;
    uint64_t    ttft_e2e_ns;                    // submit → first emittable token
    uint64_t    first_decode_after_prefill_ns;  // prefill end → first decode token
    
    // Throughput
    double      prefill_tps;
    double      decode_tps;                     // DECODE_TPS_AVG (engine decode window)
    double      sustained_tps;                  // min rolling-window TPS
    double      decode_tps_start;               // first window TPS
    double      decode_tps_min_window;          // lowest window TPS
    double      max_stable_streaming_tps;       // certified stream capacity
    uint64_t    capacity_ns_token;              // authority: max full-window NS/token
    uint64_t    capacity_target_ns_token;       // 200000000 → 5.0 tok/s
    uint64_t    decode_ns_token_avg;            // steady commit span / (N-1)
    
    // Latency percentiles (per-token decode, ms)
    double      decode_p50_ms;
    double      decode_p95_ms;
    double      decode_p99_ms;
    
    // Memory
    uint64_t    kv_bytes;
    uint64_t    kv_start_bytes;
    uint64_t    kv_end_bytes;
    uint64_t    peak_vram_bytes;
    uint64_t    peak_system_bytes;
    double      kv_bytes_per_token;
    double      duration_sec;
    
    // GPU
    uint64_t    gpu_cycles;
    uint32_t    kernel_calls;
    uint32_t    gpu_util_percent;
    uint32_t    vram_util_percent;
    uint32_t    temperature_c;
    uint32_t    power_watts;
    
    // GPU decode efficiency (AMD sensor only; invalid when gpu_power_valid=false)
    bool        gpu_power_valid;
    double      avg_gpu_power_watts;
    double      tokens_per_watt_gpu;
    uint32_t    gpu_power_sample_count;
    
    // Stability
    uint32_t    token_drops;
    uint32_t    thermal_throttle_events;
    double      tps_variance;
    
    // Stream health / certification guards
    bool        stream_stable;              // cert AND: decode+vram+kv+production
    bool        used_production_decode_path;
    bool        decode_real;
    bool        decode_stable;              // full windows + degradation only
    bool        vram_stable;
    bool        kv_stable;
    bool        endurance_certifiable;      // >= kBenchRequiredFullWindowsCertify
    double      degradation_ratio;          // min_full_window / start_full_window
    uint32_t    full_window_count;          // complete 512-token windows only
    uint32_t    tail_window_tokens;         // incomplete final window (excluded from min)
    uint32_t    fail_reason_code;
    
    StreamBenchmark() {
        memset(this, 0, sizeof(*this));
    }
};
#pragma pack(pop)

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
    double          worst_stream_tps;
    double          p95_ttft_ms;
    double          fairness_ratio;     // slowest / fastest stream TPS
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
    std::string quant_info;
    std::string fail_reason;
    
    // Phase results
    StreamBenchmark     single_stream;
    std::vector<EnduranceResult> endurance_matrix;
    std::vector<DecodeWindow> decode_windows;
    SaturationResult    saturation;
    ThermalResult       thermal;
    
    // Overall status
    bool prefill_pass;
    bool decode_pass;
    bool stream_pass;
    bool endurance_pass;
    bool saturation_pass;
    bool thermal_pass;
    bool production_decode_pass;
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
    void emitBenchmarkCertTelemetry(const StreamBenchmark& bench,
                                    const CertificationReport* report = nullptr);
    
    // Generate reports
    std::string generateJSONReport(const CertificationReport& report);
    std::string generateMarkdownReport(const CertificationReport& report);
    std::string generateCertTelemetry(const CertificationReport& report);
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
void EmitBenchmarkCertTelemetry(const StreamBenchmark& bench,
                                const char* model,
                                const char* quant,
                                const char* device,
                                uint32_t concurrentStreams = 1);

const char* BenchmarkFailReasonString(uint32_t code);

} // namespace Deep2
