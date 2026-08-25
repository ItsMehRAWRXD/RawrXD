// ============================================================================
// CertificationHarness.hpp — Adversarial Evidence-Producing Certification Suite
// ============================================================================
// Produces defensible technical evidence for valuation thesis validation.
// Every measurement carries provenance. Every gate is explicit.
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

namespace Deep2 {
    class Deep2Engine;
}

namespace rawrxd {
namespace certify {

// ============================================================================
// 1. MetricEvidence — Every measurement carries provenance
// ============================================================================
struct MetricEvidence {
    double value = 0.0;
    double min = 0.0;
    double max = 0.0;
    double median = 0.0;
    double mean = 0.0;
    double p95 = 0.0;
    double p99 = 0.0;
    double stddev = 0.0;
    uint32_t samples = 0;
    uint32_t warmup_samples = 0;
    std::string methodology;   // e.g., "median of 20 steady-state measurements after 10 warmup"
    std::string source;          // e.g., "RawrXD v1.0.0 commit abc123"
    std::string unit;            // e.g., "tokens/sec", "ms", "GB"
    bool valid = false;          // true only if measurement protocol was followed
};

// ============================================================================
// 2. Benchmark Identity — Reproducibility metadata
// ============================================================================
struct BenchmarkIdentity {
    std::string benchmark_id;       // e.g., "DECODE_128_Q5K_LLAMA32"
    std::string run_id;             // UUID for this specific execution
    std::string git_commit;         // Full SHA
    std::string git_branch;
    std::string build_type;         // Release, RelWithDebInfo, Debug
    std::string compiler;
    std::string compiler_version;
    std::string binary_hash;        // SHA-256 of the executable
    std::string command_line;
    std::string timestamp_start;
    std::string timestamp_end;
    std::string hostname;
};

// ============================================================================
// 3. Canonical BenchmarkScenario — Identical workload for all runtimes
// ============================================================================
struct BenchmarkScenario {
    std::string scenario_id;        // e.g., "DECODE_128", "PREFILL_512", "CONTEXT_4K"
    std::string model_path;
    std::string model_sha256;       // SHA-256 of the GGUF file
    uint64_t model_size_bytes = 0;
    std::string architecture;       // Llama, Qwen, Mistral, etc.
    std::string quantization;       // Q4_K, Q5_K, etc.
    uint32_t tensor_count = 0;
    uint32_t context_length = 0;

    std::string prompt_text;
    uint32_t prompt_tokens = 0;
    uint32_t generation_tokens = 0;

    float temperature = 1.0f;
    uint32_t top_k = 40;
    float top_p = 1.0f;
    uint32_t seed = 42;

    bool warmup = true;
    uint32_t warmup_iterations = 10;
    uint32_t measurement_iterations = 20;

    bool operator==(const BenchmarkScenario& other) const {
        return scenario_id == other.scenario_id &&
               model_sha256 == other.model_sha256 &&
               prompt_text == other.prompt_text &&
               generation_tokens == other.generation_tokens &&
               temperature == other.temperature &&
               top_k == other.top_k &&
               top_p == other.top_p &&
               seed == other.seed;
    }
};

// ============================================================================
// 4. Correctness Evidence — Reference comparison with tolerances
// ============================================================================
struct CorrectnessEvidence {
    bool token_ids_match = false;
    bool top_k_logits_match = false;
    bool generated_sequence_match = false;
    bool eos_behavior_match = false;

    // Tolerances (explicit, not implicit)
    float logits_max_abs_diff = 0.0f;
    float logits_rel_diff_pct = 0.0f;
    uint32_t token_mismatch_count = 0;
    uint32_t token_total_count = 0;

    std::string reference_runtime;  // e.g., "llama.cpp b3654", "Ollama v0.3.0"
    std::string reference_git_commit;
    std::string note;               // Explanation of any divergence
};

// ============================================================================
// 5. Quantization Certification State
// ============================================================================
enum class QuantStatus {
    NOT_PRESENT,      // No GGUF with this quant was available
    NOT_APPLICABLE,   // This quant doesn't exist for this architecture
    SUPPORTED,        // Code claims support
    TESTED,           // Was executed
    PASSED,           // Executed and correct
    FAILED            // Executed but incorrect or crashed
};

struct QuantCertEntry {
    std::string quant_type;       // Q2_K, Q3_K, Q4_K, Q5_K, Q6_K, Q8_0, F16, BF16, F32
    QuantStatus status = QuantStatus::NOT_PRESENT;
    std::string model_tested;     // Which model was used
    std::string note;
};

// ============================================================================
// 6. Architecture Certification State
// ============================================================================
enum class ArchStatus {
    UNSUPPORTED,      // Explicitly not supported by RawrXD
    UNTESTED,         // No model available
    TESTED,           // Was executed
    PASSED,           // Executed and correct
    FAILED            // Executed but incorrect or crashed
};

struct ArchCertEntry {
    std::string architecture;       // Llama, Qwen, Mistral, Mixtral, Gemma, Phi, DeepSeek, Codestral
    ArchStatus status = ArchStatus::UNTESTED;
    std::vector<std::string> models_tested;
    std::string note;
};

// ============================================================================
// 7. Zero-Stub Verification Result
// ============================================================================
struct StubVerification {
    uint32_t source_references = 0;         // TODO/FIXME/NOT_IMPLEMENTED in critical source
    uint32_t linked_stub_objects = 0;       // Stub .obj files linked into binary
    uint32_t fake_success_apis = 0;         // Functions that return true without work
    uint32_t fake_null_capabilities = 0;    // Functions that return nullptr
    uint32_t unimplemented_production_apis = 0;
    bool binary_inspected = false;
    bool runtime_exercised = false;
    bool passed = false;
};

// ============================================================================
// 8. Crash/Failure Isolation Record
// ============================================================================
struct FailureRecord {
    std::string scenario_id;
    std::string model_path;
    int exit_code = 0;
    std::string exception_type;
    std::string signal;
    std::string stderr_tail;
    std::string last_phase;         // e.g., "prefill", "decode_token_47", "kv_cache_store"
    std::string last_kernel;        // e.g., "sovereign_q5k_gemv_v2"
    std::string timestamp;
};

// ============================================================================
// 9. First-Token Decomposition
// ============================================================================
struct TTFTDecomposition {
    MetricEvidence model_readiness_ms;
    MetricEvidence tokenization_ms;
    MetricEvidence prefix_cache_lookup_ms;
    MetricEvidence embedding_ms;
    MetricEvidence prefill_ms;
    MetricEvidence logits_ms;
    MetricEvidence first_sampling_ms;
    MetricEvidence total_ttft_ms;
};

// ============================================================================
// 10. Memory Methodology
// ============================================================================
struct MemoryEvidence {
    MetricEvidence model_size_gb;           // GGUF file size
    MetricEvidence mapped_file_gb;          // Memory-mapped model
    MetricEvidence resident_ram_gb;         // Actually resident
    MetricEvidence working_set_gb;          // OS working set
    MetricEvidence private_bytes_gb;        // Private committed
    MetricEvidence peak_ram_gb;             // Peak observed
    MetricEvidence gpu_allocated_gb;        // GPU memory allocated
    MetricEvidence gpu_reserved_gb;         // GPU memory reserved
    MetricEvidence kv_cache_gb;             // KV cache footprint
    MetricEvidence temporary_buffers_gb;    // Temp buffers during inference
};

// ============================================================================
// 11. Power/Thermal (optional, for serious claims)
// ============================================================================
struct ThermalEvidence {
    MetricEvidence gpu_utilization_pct;
    MetricEvidence gpu_clock_mhz;
    MetricEvidence gpu_temp_c;
    MetricEvidence gpu_power_w;
    MetricEvidence gpu_throttled;
    MetricEvidence cpu_utilization_pct;
};

// ============================================================================
// 12. Per-Scenario Result
// ============================================================================
struct ScenarioResult {
    BenchmarkScenario scenario;
    BenchmarkIdentity identity;

    // Timing
    MetricEvidence ttft_ms;
    MetricEvidence decode_tps;
    MetricEvidence prefill_tps;
    TTFTDecomposition ttft_breakdown;

    // Memory
    MemoryEvidence memory;

    // Thermal
    std::optional<ThermalEvidence> thermal;

    // Correctness
    CorrectnessEvidence correctness;

    // Comparison
    MetricEvidence vs_ollama_tps;
    MetricEvidence vs_llamacpp_tps;
    MetricEvidence vs_baseline_tps;

    // Status
    bool crashed = false;
    std::optional<FailureRecord> failure;
    bool passed = false;
};

// ============================================================================
// 13. Certification Status
// ============================================================================
enum class CertificationStatus {
    NOT_RUN,
    INCOMPLETE,
    FAILED,
    CONDITIONALLY_CERTIFIED,    // Some non-critical gates failed
    CERTIFIED                   // All mandatory gates passed
};

// ============================================================================
// 14. Certification Gates (deterministic scoring)
// ============================================================================
struct CertificationGates {
    // Mandatory gates (failure of any = CERTIFICATION FAILED)
    bool correctness = false;           // 20 points — output matches reference
    bool zero_stubs = false;            // 5 points — no production stubs
    bool stability = false;             // 5 points — 1000 requests without crash

    // Scored gates
    bool compatibility_matrix = false;  // 15 points — models load and infer
    bool quantization_coverage = false; // 10 points — all claimed quants work
    bool architecture_coverage = false; // 10 points — all claimed archs work
    bool performance_measured = false;  // 15 points — TPS measured with stats
    bool gpu_execution = false;         // 10 points — GPU path works
    bool multi_gpu = false;             // 5 points — dual GPU works
    bool concurrency = false;           // 5 points — concurrent requests work

    uint32_t Score() const {
        uint32_t score = 0;
        if (correctness)          score += 20;
        if (zero_stubs)           score += 5;
        if (stability)            score += 5;
        if (compatibility_matrix)   score += 15;
        if (quantization_coverage) score += 10;
        if (architecture_coverage) score += 10;
        if (performance_measured)  score += 15;
        if (gpu_execution)         score += 10;
        if (multi_gpu)             score += 5;
        if (concurrency)           score += 5;
        return score;
    }

    bool MandatoryPassed() const {
        return correctness && zero_stubs && stability;
    }

    CertificationStatus OverallStatus() const {
        if (!correctness && !zero_stubs && !stability && !compatibility_matrix)
            return CertificationStatus::NOT_RUN;
        if (!MandatoryPassed())
            return CertificationStatus::FAILED;
        uint32_t s = Score();
        if (s >= 90)
            return CertificationStatus::CERTIFIED;
        if (s >= 70)
            return CertificationStatus::CONDITIONALLY_CERTIFIED;
        return CertificationStatus::FAILED;
    }
};

// ============================================================================
// Full Certification Report
// ============================================================================
struct CertificationReport {
    BenchmarkIdentity identity;
    CertificationStatus status = CertificationStatus::NOT_RUN;
    CertificationGates gates;
    uint32_t evidence_score = 0;  // Deterministic from gates

    // System under test
    struct SystemInfo {
        std::string cpu;
        uint32_t cpu_cores = 0;
        uint32_t cpu_threads = 0;
        bool avx2 = false;
        bool avx512 = false;
        uint64_t total_ram_bytes = 0;
        std::string gpu0;
        std::string gpu1;
        uint64_t gpu0_vram_bytes = 0;
        uint64_t gpu1_vram_bytes = 0;
        std::string os;
    } system;

    // Results
    std::vector<ScenarioResult> scenario_results;
    std::vector<QuantCertEntry> quant_matrix;
    std::vector<ArchCertEntry> arch_matrix;
    StubVerification stub_verification;
    std::vector<FailureRecord> failures;

    // Executive summary
    uint32_t total_scenarios_tested = 0;
    uint32_t total_scenarios_passed = 0;
    uint32_t total_scenarios_failed = 0;
    uint32_t total_scenarios_crashed = 0;
    double best_cpu_tps = 0.0;
    double best_gpu_tps = 0.0;
    std::string best_scenario;

    // Valuation note (not a score)
    std::string valuation_note;
};

// ============================================================================
// Certification Configuration
// ============================================================================
struct CertConfig {
    std::vector<BenchmarkScenario> scenarios;
    std::vector<std::string> model_paths;  // Fallback: auto-generate scenarios

    bool test_cpu = true;
    bool test_gpu = true;
    bool test_dual_gpu = false;

    uint32_t stability_requests = 1000;
    uint32_t concurrent_requests = 4;

    bool compare_ollama = true;
    bool compare_llamacpp = true;
    std::string ollama_host = "http://localhost:11434";
    std::string llamacpp_host = "http://localhost:8080";

    std::string reference_runtime = "llama.cpp";  // For correctness comparison
    std::string reference_runtime_version;

    std::string output_dir = "certification_results";
    bool export_json = true;
    bool export_markdown = true;
    bool export_html = true;

    bool collect_thermal = false;
};

// ============================================================================
// Certification Harness
// ============================================================================
class CertificationHarness {
public:
    explicit CertificationHarness(const CertConfig& config);
    ~CertificationHarness();

    // Run full certification suite
    CertificationReport Run();

    // Individual phases (can be run standalone)
    ScenarioResult RunScenario(const BenchmarkScenario& scenario);
    bool RunStabilityTest();
    bool RunConcurrencyTest();
    StubVerification VerifyZeroProductionStubs();

    // Comparison adapters (identical scenario fed to all)
    MetricEvidence MeasureRuntimeTPS(const BenchmarkScenario& scenario,
                                      const std::string& runtime); // "rawrxd", "ollama", "llamacpp"

    // Correctness
    CorrectnessEvidence CompareToReference(const BenchmarkScenario& scenario);

    // Report generation
    bool ExportJSON(const std::string& path) const;
    bool ExportMarkdown(const std::string& path) const;
    bool ExportHTML(const std::string& path) const;

    const CertificationReport& GetReport() const { return report_; }

private:
    CertConfig config_;
    CertificationReport report_;

    // Internal helpers
    void DetectSystemInfo();
    void BuildIdentity();
    bool RunSingleScenario(const BenchmarkScenario& scenario, ScenarioResult& out);

    // Measurement
    MetricEvidence MeasureDecodeTPS(Deep2::Deep2Engine& engine,
                                     const BenchmarkScenario& scenario,
                                     bool use_gpu);
    MetricEvidence MeasureTTFT(Deep2::Deep2Engine& engine,
                                const BenchmarkScenario& scenario);
    TTFTDecomposition DecomposeTTFT(Deep2::Deep2Engine& engine,
                                    const BenchmarkScenario& scenario);
    MemoryEvidence MeasureMemory(Deep2::Deep2Engine& engine);
    std::optional<ThermalEvidence> MeasureThermal();

    // Correctness
    bool VerifyCorrectness(Deep2::Deep2Engine& engine,
                           const BenchmarkScenario& scenario,
                           const std::vector<int>& reference_tokens);

    // Statistical aggregation
    MetricEvidence AggregateMeasurements(const std::vector<double>& values,
                                          const std::string& methodology,
                                          const std::string& unit);

    // Stub detection
    uint32_t ScanSourceForStubs(const std::vector<std::string>& files);
    uint32_t ScanBinaryForStubSymbols(const std::string& binary_path);
    uint32_t RuntimeExerciseSubsystems();

    // System (implemented as static helpers in .cpp)
    // double SampleRAMUsedGB();
    // double SampleVRAMUsedGB();
};

// ============================================================================
// CLI Entry Point
// ============================================================================
int RunCertificationCLI(int argc, char** argv);

} // namespace certify
} // namespace rawrxd
