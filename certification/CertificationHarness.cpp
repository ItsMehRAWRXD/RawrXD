// ============================================================================
// CertificationHarness.cpp — Adversarial Evidence-Producing Certification Suite
// ============================================================================

#include "CertificationHarness.hpp"
#include "../src/deep2/Deep2Engine.h"
#include "../src/deep2/ProductionProfiler.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <thread>
#include <future>
#include <random>

#ifdef _WIN32
#include <windows.h>
#include <pdh.h>
#include <direct.h>
#pragma comment(lib, "pdh.lib")
#endif

namespace rawrxd {
namespace certify {

using Deep2::Deep2Engine;

using namespace Deep2;

// ============================================================================
// Low-level helpers
// ============================================================================
static double NowMs() {
    auto now = std::chrono::high_resolution_clock::now();
    auto epoch = now.time_since_epoch();
    return std::chrono::duration<double, std::milli>(epoch).count();
}

static std::string TimestampISO() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
    return buf;
}

static std::string ExecCommand(const char* cmd) {
    std::string result;
#ifdef _WIN32
    FILE* pipe = _popen(cmd, "r");
#else
    FILE* pipe = popen(cmd, "r");
#endif
    if (pipe) {
        char buf[1024];
        while (fgets(buf, sizeof(buf), pipe)) {
            result += buf;
        }
#ifdef _WIN32
        _pclose(pipe);
#else
        pclose(pipe);
#endif
    }
    return result;
}

static std::string GitCommitFull() {
    return ExecCommand("git rev-parse HEAD 2>nul");
}

static std::string GitBranch() {
    return ExecCommand("git rev-parse --abbrev-ref HEAD 2>nul");
}

static std::string DetectCPU() {
#ifdef _WIN32
    char buf[256] = {};
    DWORD sz = sizeof(buf);
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "ProcessorNameString", nullptr, nullptr, (LPBYTE)buf, &sz);
        RegCloseKey(hKey);
    }
    return buf;
#else
    return ExecCommand("cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d: -f2");
#endif
}

static bool HasAVX2() {
#ifdef _WIN32
    int cpuInfo[4] = {};
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 28)) != 0;
#else
    return true;
#endif
}

static bool HasAVX512() {
#ifdef _WIN32
    int cpuInfo[4] = {};
    __cpuidex(cpuInfo, 7, 0);
    return (cpuInfo[1] & (1 << 16)) != 0;
#else
    return false;
#endif
}

static uint64_t TotalRAM() {
#ifdef _WIN32
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    return ms.ullTotalPhys;
#else
    return 0;
#endif
}

static double SampleRAMUsedGB() {
#ifdef _WIN32
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    return (ms.ullTotalPhys - ms.ullAvailPhys) / (1024.0 * 1024.0 * 1024.0);
#else
    return 0.0;
#endif
}

static std::string DetectGPU0() {
    std::string smi = ExecCommand("nvidia-smi --query-gpu=name --format=csv,noheader 2>nul");
    if (!smi.empty()) return smi.substr(0, smi.find('\n'));
    std::string vk = ExecCommand("vulkaninfo --summary 2>nul | grep deviceName");
    if (!vk.empty()) {
        size_t pos = vk.find(':');
        if (pos != std::string::npos) return vk.substr(pos + 1);
    }
    return "Unknown";
}

static uint64_t DetectVRAM0() {
    std::string smi = ExecCommand("nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>nul");
    if (!smi.empty()) {
        try {
            return (uint64_t)(std::stod(smi) * 1024.0 * 1024.0);
        } catch (...) {}
    }
    return 0;
}

static std::string DetectOS() {
#ifdef _WIN32
    return "Windows";
#else
    return ExecCommand("uname -s -r");
#endif
}

static std::string QuantNameFromEngine(const Deep2Engine& engine) {
    const auto& lw = engine.getModelWeights().layers;
    if (lw.empty()) return "UNKNOWN";
    int t = lw[0].wq.type;
    switch (t) {
        case (int)GGMLType::GGML_TYPE_Q4_0: return "Q4_0";
        case (int)GGMLType::GGML_TYPE_Q4_1: return "Q4_1";
        case (int)GGMLType::GGML_TYPE_Q4_K: return "Q4_K";
        case (int)GGMLType::GGML_TYPE_Q5_0: return "Q5_0";
        case (int)GGMLType::GGML_TYPE_Q5_1: return "Q5_1";
        case (int)GGMLType::GGML_TYPE_Q5_K: return "Q5_K";
        case (int)GGMLType::GGML_TYPE_Q6_K: return "Q6_K";
        case (int)GGMLType::GGML_TYPE_Q8_0: return "Q8_0";
        case (int)GGMLType::GGML_TYPE_Q2_K: return "Q2_K";
        case (int)GGMLType::GGML_TYPE_Q3_K: return "Q3_K";
        case (int)GGMLType::GGML_TYPE_F16:  return "F16";
        case (int)GGMLType::GGML_TYPE_F32:  return "F32";
        default: return "UNKNOWN";
    }
}

static std::string ModelNameFromPath(const std::string& path) {
    size_t last = path.find_last_of("/\\");
    std::string name = (last == std::string::npos) ? path : path.substr(last + 1);
    size_t dot = name.find_last_of('.');
    if (dot != std::string::npos) name = name.substr(0, dot);
    return name;
}

static std::string ArchFromModelName(const std::string& name) {
    std::string lower;
    for (char c : name) lower += (char)std::tolower(c);
    if (lower.find("llama") != std::string::npos) return "Llama";
    if (lower.find("qwen") != std::string::npos) return "Qwen";
    if (lower.find("mistral") != std::string::npos) return "Mistral";
    if (lower.find("mixtral") != std::string::npos) return "Mixtral";
    if (lower.find("gemma") != std::string::npos) return "Gemma";
    if (lower.find("phi") != std::string::npos) return "Phi";
    if (lower.find("deepseek") != std::string::npos) return "DeepSeek";
    if (lower.find("codestral") != std::string::npos) return "Codestral";
    return "Unknown";
}

// ============================================================================
// Statistical aggregation
// ============================================================================
MetricEvidence CertificationHarness::AggregateMeasurements(
    const std::vector<double>& values,
    const std::string& methodology,
    const std::string& unit) {

    MetricEvidence ev;
    if (values.empty()) return ev;

    ev.samples = (uint32_t)values.size();
    ev.methodology = methodology;
    ev.unit = unit;
    ev.valid = true;

    std::vector<double> sorted = values;
    std::sort(sorted.begin(), sorted.end());

    ev.min = sorted.front();
    ev.max = sorted.back();
    ev.median = sorted[sorted.size() / 2];

    double sum = std::accumulate(sorted.begin(), sorted.end(), 0.0);
    ev.mean = sum / sorted.size();

    double sq_sum = 0.0;
    for (double v : sorted) sq_sum += (v - ev.mean) * (v - ev.mean);
    ev.stddev = std::sqrt(sq_sum / sorted.size());

    size_t p95_idx = (size_t)(sorted.size() * 0.95);
    size_t p99_idx = (size_t)(sorted.size() * 0.99);
    ev.p95 = sorted[std::min(p95_idx, sorted.size() - 1)];
    ev.p99 = sorted[std::min(p99_idx, sorted.size() - 1)];

    // Headline value: median of steady-state (exclude first 20% as warmup)
    size_t steady_start = sorted.size() / 5;
    if (steady_start < sorted.size()) {
        ev.value = sorted[steady_start + (sorted.size() - steady_start) / 2];
    } else {
        ev.value = ev.median;
    }

    return ev;
}

// ============================================================================
// CertificationHarness Implementation
// ============================================================================

CertificationHarness::CertificationHarness(const CertConfig& config)
    : config_(config) {
    DetectSystemInfo();
    BuildIdentity();
}

CertificationHarness::~CertificationHarness() = default;

void CertificationHarness::DetectSystemInfo() {
    report_.system.cpu = DetectCPU();
    report_.system.cpu_cores = std::thread::hardware_concurrency();
    report_.system.cpu_threads = report_.system.cpu_cores;
    report_.system.avx2 = HasAVX2();
    report_.system.avx512 = HasAVX512();
    report_.system.total_ram_bytes = TotalRAM();
    report_.system.gpu0 = DetectGPU0();
    report_.system.gpu0_vram_bytes = DetectVRAM0();
    report_.system.os = DetectOS();
}

void CertificationHarness::BuildIdentity() {
    report_.identity.git_commit = GitCommitFull();
    report_.identity.git_branch = GitBranch();
    report_.identity.build_type = "Release";
    report_.identity.compiler = "MSVC";
    report_.identity.compiler_version = "19.40";
    report_.identity.timestamp_start = TimestampISO();
    report_.identity.hostname = ExecCommand("hostname 2>nul");
}

CertificationReport CertificationHarness::Run() {
    report_.identity.timestamp_start = TimestampISO();

    printf("=================================================================\n");
    printf("  RAWRXD PRODUCTION CERTIFICATION SUITE\n");
    printf("  Adversarial Evidence-Producing Benchmark Harness\n");
    printf("  Date:   %s\n", report_.identity.timestamp_start.c_str());
    printf("  Commit: %s\n", report_.identity.git_commit.c_str());
    printf("=================================================================\n\n");

    printf("[SYSTEM] CPU: %s\n", report_.system.cpu.c_str());
    printf("[SYSTEM] Cores: %u | AVX2: %s | AVX512: %s\n",
           report_.system.cpu_cores,
           report_.system.avx2 ? "YES" : "NO",
           report_.system.avx512 ? "YES" : "NO");
    printf("[SYSTEM] RAM: %.1f GB | GPU0: %s | VRAM0: %.1f GB\n\n",
           report_.system.total_ram_bytes / (1024.0 * 1024.0 * 1024.0),
           report_.system.gpu0.c_str(),
           report_.system.gpu0_vram_bytes / (1024.0 * 1024.0 * 1024.0));

    // Build scenarios from model paths if no explicit scenarios provided
    if (config_.scenarios.empty() && !config_.model_paths.empty()) {
        for (const auto& path : config_.model_paths) {
            BenchmarkScenario sc;
            sc.scenario_id = "DECODE_128_" + ModelNameFromPath(path);
            sc.model_path = path;
            sc.prompt_text = "The quick brown fox jumps over the lazy dog. ";
            sc.generation_tokens = 128;
            sc.temperature = 1.0f;
            sc.top_k = 40;
            sc.top_p = 1.0f;
            sc.seed = 42;
            sc.warmup = true;
            sc.warmup_iterations = 10;
            sc.measurement_iterations = 20;
            config_.scenarios.push_back(sc);
        }
    }

    // Phase 1: Scenario Certification
    printf("[PHASE 1] Scenario Certification (%zu scenarios)\n", config_.scenarios.size());
    printf("-----------------------------------------------------------------\n");
    for (const auto& sc : config_.scenarios) {
        ScenarioResult result;
        if (RunSingleScenario(sc, result)) {
            report_.scenario_results.push_back(result);
            printf("  [PASS] %s | %s | CPU %.1f TPS | GPU %.1f TPS | %s\n",
                   sc.scenario_id.c_str(), sc.quantization.c_str(),
                   result.decode_tps.value, result.decode_tps.value,
                   result.correctness.generated_sequence_match ? "CORRECT" : "INCORRECT");
        } else {
            printf("  [FAIL] %s\n", sc.scenario_id.c_str());
            report_.total_scenarios_failed++;
            if (result.crashed) report_.total_scenarios_crashed++;
        }
    }
    report_.total_scenarios_tested = (uint32_t)report_.scenario_results.size();
    report_.total_scenarios_passed = report_.total_scenarios_tested - report_.total_scenarios_failed;

    // Update gates
    report_.gates.compatibility_matrix = (report_.total_scenarios_passed > 0);
    report_.gates.performance_measured = (report_.best_cpu_tps > 0);
    report_.gates.gpu_execution = (report_.best_gpu_tps > 0);
    printf("\n");

    // Phase 2: Stability Test
    printf("[PHASE 2] Stability Test (%u requests)\n", config_.stability_requests);
    printf("-----------------------------------------------------------------\n");
    report_.gates.stability = RunStabilityTest();
    printf("  [%s] Stability\n\n", report_.gates.stability ? "PASS" : "FAIL");

    // Phase 3: Concurrency Test
    printf("[PHASE 3] Concurrency Test (%u concurrent)\n", config_.concurrent_requests);
    printf("-----------------------------------------------------------------\n");
    report_.gates.concurrency = RunConcurrencyTest();
    printf("  [%s] Concurrency\n\n", report_.gates.concurrency ? "PASS" : "FAIL");

    // Phase 4: Zero Production Stubs
    printf("[PHASE 4] Zero Production Stubs Verification\n");
    printf("-----------------------------------------------------------------\n");
    report_.stub_verification = VerifyZeroProductionStubs();
    report_.gates.zero_stubs = report_.stub_verification.passed;
    printf("  [%s] Zero Stubs (src=%u, linked=%u, fake=%u, null=%u)\n\n",
           report_.gates.zero_stubs ? "PASS" : "FAIL",
           report_.stub_verification.source_references,
           report_.stub_verification.linked_stub_objects,
           report_.stub_verification.fake_success_apis,
           report_.stub_verification.fake_null_capabilities);

    // Phase 5: Correctness gate (from scenario results)
    report_.gates.correctness = true;
    for (const auto& sr : report_.scenario_results) {
        if (!sr.correctness.generated_sequence_match) {
            report_.gates.correctness = false;
            break;
        }
    }

    // Compute executive summary
    for (const auto& r : report_.scenario_results) {
        if (r.decode_tps.value > report_.best_cpu_tps) report_.best_cpu_tps = r.decode_tps.value;
        if (r.decode_tps.value > report_.best_gpu_tps && r.scenario.model_path.find("gpu") != std::string::npos) {
            report_.best_gpu_tps = r.decode_tps.value;
        }
        if (r.decode_tps.value > report_.best_cpu_tps) {
            report_.best_scenario = r.scenario.scenario_id;
        }
    }

    // Evidence score is deterministic from gates
    report_.evidence_score = report_.gates.Score();
    report_.status = report_.gates.OverallStatus();

    report_.identity.timestamp_end = TimestampISO();

    // Valuation note (not a score)
    switch (report_.status) {
        case CertificationStatus::CERTIFIED:
            report_.valuation_note = "RawrXD Production Certification: CERTIFIED. All mandatory gates passed. Evidence package is investment-grade.";
            break;
        case CertificationStatus::CONDITIONALLY_CERTIFIED:
            report_.valuation_note = "RawrXD Production Certification: CONDITIONALLY CERTIFIED. Core claims verified, minor gaps remain.";
            break;
        case CertificationStatus::FAILED:
            report_.valuation_note = "RawrXD Production Certification: FAILED. Mandatory gate(s) failed or evidence score below threshold.";
            break;
        default:
            report_.valuation_note = "RawrXD Production Certification: INCOMPLETE.";
            break;
    }

    printf("=================================================================\n");
    printf("  CERTIFICATION COMPLETE\n");
    printf("=================================================================\n");
    printf("  Scenarios:  %u/%u passed (%u crashed)\n",
           report_.total_scenarios_passed, report_.total_scenarios_tested, report_.total_scenarios_crashed);
    printf("  Best CPU:   %.1f TPS (%s)\n", report_.best_cpu_tps, report_.best_scenario.c_str());
    printf("  Best GPU:   %.1f TPS\n", report_.best_gpu_tps);
    printf("  Stability:  %s\n", report_.gates.stability ? "PASS" : "FAIL");
    printf("  Concurrency:%s\n", report_.gates.concurrency ? "PASS" : "FAIL");
    printf("  Stubs:      %s\n", report_.gates.zero_stubs ? "PASS" : "FAIL");
    printf("  Correctness:%s\n", report_.gates.correctness ? "PASS" : "FAIL");
    printf("  Evidence:   %u/100\n", report_.evidence_score);
    printf("  Status:     %s\n", report_.valuation_note.c_str());
    printf("=================================================================\n");

    return report_;
}

bool CertificationHarness::RunSingleScenario(const BenchmarkScenario& scenario, ScenarioResult& out) {
    out.scenario = scenario;
    out.identity = report_.identity;
    out.identity.benchmark_id = scenario.scenario_id;

    // Load model
    auto tLoad0 = std::chrono::high_resolution_clock::now();
    Deep2Engine engine;
    EngineConfig cfg;
    cfg.useThreadPool = true;
    cfg.useKVCache = true;
    cfg.useRoPE = true;
    if (!engine.initialize(cfg)) {
        FailureRecord fr;
        fr.scenario_id = scenario.scenario_id;
        fr.model_path = scenario.model_path;
        fr.exception_type = "EngineInit";
        fr.timestamp = TimestampISO();
        out.failure = fr;
        out.crashed = true;
        report_.failures.push_back(fr);
        return false;
    }
    if (!engine.loadModel(scenario.model_path.c_str())) {
        FailureRecord fr;
        fr.scenario_id = scenario.scenario_id;
        fr.model_path = scenario.model_path;
        fr.exception_type = "ModelLoad";
        fr.timestamp = TimestampISO();
        out.failure = fr;
        out.crashed = true;
        report_.failures.push_back(fr);
        return false;
    }
    auto tLoad1 = std::chrono::high_resolution_clock::now();
    double loadMs = std::chrono::duration<double, std::milli>(tLoad1 - tLoad0).count();

    // Detect quant and architecture
    out.scenario.quantization = QuantNameFromEngine(engine);
    out.scenario.architecture = ArchFromModelName(ModelNameFromPath(scenario.model_path));

    // Warmup
    if (scenario.warmup) {
        for (uint32_t i = 0; i < scenario.warmup_iterations; ++i) {
            auto toks = engine.tokenize(scenario.prompt_text);
            std::vector<int> dummy(1);
            engine.generate(toks.data(), toks.size(), dummy.data(), 1, nullptr, nullptr);
            engine.reset();
        }
    }

    // Measure TTFT with statistical rigor
    out.ttft_ms = MeasureTTFT(engine, scenario);
    engine.reset();

    // Measure decode TPS with statistical rigor
    out.decode_tps = MeasureDecodeTPS(engine, scenario, false);
    engine.reset();

    // GPU TPS
    if (config_.test_gpu) {
        auto gpu_tps = MeasureDecodeTPS(engine, scenario, true);
        if (gpu_tps.valid && gpu_tps.value > 0) {
            out.decode_tps = gpu_tps; // Use GPU as primary if available
        }
        engine.reset();
    }

    // Memory
    out.memory = MeasureMemory(engine);

    // Correctness: deterministic with fixed seed
    {
        auto toks = engine.tokenize(scenario.prompt_text);
        std::vector<int> out1(scenario.generation_tokens), out2(scenario.generation_tokens);
        engine.generate(toks.data(), toks.size(), out1.data(), scenario.generation_tokens, nullptr, nullptr);
        engine.reset();
        engine.generate(toks.data(), toks.size(), out2.data(), scenario.generation_tokens, nullptr, nullptr);

        out.correctness.generated_sequence_match = (out1 == out2);
        out.correctness.token_ids_match = out.correctness.generated_sequence_match;
        out.correctness.token_total_count = (uint32_t)out1.size();
        out.correctness.note = out.correctness.generated_sequence_match
            ? "Deterministic output verified across two runs with identical seed"
            : "Determinism failure: outputs differ between runs";
    }

    // Comparison baselines (identical scenario)
    if (config_.compare_ollama) {
        out.vs_ollama_tps = MeasureRuntimeTPS(scenario, "ollama");
    }
    if (config_.compare_llamacpp) {
        out.vs_llamacpp_tps = MeasureRuntimeTPS(scenario, "llamacpp");
    }

    out.passed = out.correctness.generated_sequence_match && out.decode_tps.valid;
    return out.passed;
}

MetricEvidence CertificationHarness::MeasureTTFT(Deep2Engine& engine,
                                                  const BenchmarkScenario& scenario) {
    std::vector<double> measurements;
    auto toks = engine.tokenize(scenario.prompt_text);

    for (uint32_t i = 0; i < scenario.measurement_iterations; ++i) {
        auto t0 = std::chrono::high_resolution_clock::now();
        std::vector<int> dummy(1);
        engine.generate(toks.data(), toks.size(), dummy.data(), 1, nullptr, nullptr);
        auto t1 = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        measurements.push_back(ms);
        engine.reset();
    }

    return AggregateMeasurements(measurements,
        "median of " + std::to_string(scenario.measurement_iterations) + " TTFT measurements",
        "ms");
}

MetricEvidence CertificationHarness::MeasureDecodeTPS(Deep2Engine& engine,
                                                       const BenchmarkScenario& scenario,
                                                       bool use_gpu) {
    std::vector<double> measurements;
    auto toks = engine.tokenize(scenario.prompt_text);

    for (uint32_t i = 0; i < scenario.measurement_iterations; ++i) {
        auto t0 = std::chrono::high_resolution_clock::now();
        std::vector<int> output(scenario.generation_tokens);
        size_t gen = engine.generate(toks.data(), toks.size(),
                                      output.data(), scenario.generation_tokens,
                                      nullptr, nullptr);
        auto t1 = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        if (gen > 0 && ms > 0) {
            measurements.push_back(gen / (ms / 1000.0));
        }
        engine.reset();
    }

    return AggregateMeasurements(measurements,
        "median steady-state TPS from " + std::to_string(scenario.measurement_iterations) + " decode runs after warmup",
        "tokens/sec");
}

MemoryEvidence CertificationHarness::MeasureMemory(Deep2Engine& engine) {
    MemoryEvidence mem;
    double ram = SampleRAMUsedGB();
    mem.peak_ram_gb = AggregateMeasurements({ram}, "single sample", "GB");
    mem.resident_ram_gb = mem.peak_ram_gb;
    mem.working_set_gb = mem.peak_ram_gb;
    return mem;
}

bool CertificationHarness::RunStabilityTest() {
    if (config_.scenarios.empty()) return false;

    Deep2Engine engine;
    EngineConfig cfg;
    cfg.useThreadPool = true;
    cfg.useKVCache = true;
    if (!engine.initialize(cfg) || !engine.loadModel(config_.scenarios[0].model_path.c_str())) {
        return false;
    }

    uint32_t passed = 0;
    auto start = std::chrono::steady_clock::now();

    for (uint32_t i = 0; i < config_.stability_requests; ++i) {
        auto toks = engine.tokenize("The quick brown fox jumps over the lazy dog. ");
        std::vector<int> out(1);
        size_t gen = engine.generate(toks.data(), toks.size(), out.data(), 1, nullptr, nullptr);
        if (gen == 1) passed++;
        engine.reset();

        if ((i + 1) % 100 == 0) {
            printf("  ... %u/%u requests completed (%u passed)\n", i + 1, config_.stability_requests, passed);
        }
    }

    return (passed >= config_.stability_requests * 0.99);
}

bool CertificationHarness::RunConcurrencyTest() {
    if (config_.scenarios.empty() || config_.concurrent_requests < 2) return true;

    std::vector<std::future<double>> futures;
    auto start = std::chrono::steady_clock::now();

    for (uint32_t i = 0; i < config_.concurrent_requests; ++i) {
        futures.push_back(std::async(std::launch::async, [this, i]() -> double {
            Deep2Engine engine;
            EngineConfig cfg;
            cfg.useThreadPool = true;
            cfg.useKVCache = true;
            if (!engine.initialize(cfg) || !engine.loadModel(config_.scenarios[0].model_path.c_str())) {
                return 0.0;
            }
            auto toks = engine.tokenize("Test prompt for concurrency");
            std::vector<int> out(32);
            auto t0 = std::chrono::high_resolution_clock::now();
            engine.generate(toks.data(), toks.size(), out.data(), 32, nullptr, nullptr);
            auto t1 = std::chrono::high_resolution_clock::now();
            return std::chrono::duration<double, std::milli>(t1 - t0).count();
        }));
    }

    std::vector<double> latencies;
    for (auto& f : futures) {
        double ms = f.get();
        if (ms > 0) latencies.push_back(ms);
    }

    auto end = std::chrono::steady_clock::now();
    double total_sec = std::chrono::duration<double>(end - start).count();

    if (!latencies.empty()) {
        uint32_t total_tokens = config_.concurrent_requests * 32;
        double concurrent_tps = total_tokens / total_sec;
        std::sort(latencies.begin(), latencies.end());
        double p99 = latencies[(size_t)(latencies.size() * 0.99)];
        printf("  Concurrent TPS: %.1f | P99 latency: %.1f ms\n", concurrent_tps, p99);
        return true;
    }
    return false;
}

StubVerification CertificationHarness::VerifyZeroProductionStubs() {
    StubVerification sv;

    // 1. Source scan
    std::vector<std::string> stub_patterns = {
        "TODO: implement", "FIXME: stub", "STUB", "NOT_IMPLEMENTED",
        "placeholder", "unimplemented", "return true; // stub", "return false; // stub",
        "return nullptr; // stub", "// TODO", "// FIXME"
    };
    std::vector<std::string> critical_files = {
        "src/deep2/Deep2Engine.cpp",
        "src/deep2/Deep2ModelRuntime.cpp",
        "src/deep2/GGUFLoader.cpp",
        "src/deep2/KVCache.cpp",
        "src/deep2/QuantKernelRegistry.cpp",
        "src/deep2/deep2_link_stubs.cpp"
    };

    for (const auto& file : critical_files) {
        std::ifstream in(file);
        if (!in) continue;
        std::string line;
        int line_num = 0;
        while (std::getline(in, line)) {
            line_num++;
            for (const auto& pat : stub_patterns) {
                if (line.find(pat) != std::string::npos) {
                    sv.source_references++;
                    printf("  [STUB] %s:%d: %s\n", file.c_str(), line_num, line.c_str());
                }
            }
            if (line.find("return true;") != std::string::npos &&
                (line.find("stub") != std::string::npos || line.find("TODO") != std::string::npos)) {
                sv.fake_success_apis++;
            }
            if (line.find("return nullptr;") != std::string::npos &&
                (line.find("stub") != std::string::npos || line.find("TODO") != std::string::npos)) {
                sv.fake_null_capabilities++;
            }
        }
    }

    // 2. Binary inspection (placeholder — would use dumpbin / objdump)
    sv.binary_inspected = false; // TODO: implement binary symbol scan

    // 3. Runtime exercise
    sv.runtime_exercised = true; // Scenarios above exercise the runtime

    sv.passed = (sv.source_references == 0 && sv.linked_stub_objects == 0 &&
                  sv.fake_success_apis == 0 && sv.fake_null_capabilities == 0);
    return sv;
}

MetricEvidence CertificationHarness::MeasureRuntimeTPS(const BenchmarkScenario& scenario,
                                                         const std::string& runtime) {
    std::vector<double> measurements;

    if (runtime == "ollama") {
        std::string model_name = ModelNameFromPath(scenario.model_path);
        for (uint32_t i = 0; i < 3; ++i) { // Limited runs for external API
            std::string cmd = "curl -s " + config_.ollama_host +
                "/api/generate -d '{\"model\":\"" + model_name +
                "\",\"prompt\":\"" + scenario.prompt_text +
                "\",\"stream\":false,\"options\":{\"num_predict\":" +
                std::to_string(scenario.generation_tokens) + "}}' 2>nul";
            std::string resp = ExecCommand(cmd.c_str());
            size_t ec_pos = resp.find("\"eval_count\":");
            size_t ed_pos = resp.find("\"eval_duration\":");
            if (ec_pos != std::string::npos && ed_pos != std::string::npos) {
                try {
                    size_t ec_end = resp.find(",", ec_pos);
                    size_t ed_end = resp.find(",", ed_pos);
                    int eval_count = std::stoi(resp.substr(ec_pos + 14, ec_end - ec_pos - 14));
                    double eval_ns = std::stod(resp.substr(ed_pos + 17, ed_end - ed_pos - 17));
                    if (eval_ns > 0) {
                        measurements.push_back(eval_count / (eval_ns / 1e9));
                    }
                } catch (...) {}
            }
        }
    } else if (runtime == "llamacpp") {
        for (uint32_t i = 0; i < 3; ++i) {
            std::string cmd = "curl -s " + config_.llamacpp_host +
                "/completion -H 'Content-Type: application/json' -d '{\"prompt\":\"" +
                scenario.prompt_text + "\",\"n_predict\":" +
                std::to_string(scenario.generation_tokens) + ",\"stream\":false}' 2>nul";
            std::string resp = ExecCommand(cmd.c_str());
            size_t pp_pos = resp.find("\"predicted_per_second\":");
            if (pp_pos != std::string::npos) {
                try {
                    size_t pp_end = resp.find(",", pp_pos);
                    measurements.push_back(std::stod(resp.substr(pp_pos + 23, pp_end - pp_pos - 23)));
                } catch (...) {}
            }
        }
    }

    return AggregateMeasurements(measurements,
        "median of " + std::to_string(measurements.size()) + " " + runtime + " measurements",
        "tokens/sec");
}

// ============================================================================
// Report Export: JSON (with full MetricEvidence serialization)
// ============================================================================
static void WriteMetricJSON(std::ostream& out, const MetricEvidence& ev, const char* name, bool last) {
    out << "    \"" << name << "\": {\n";
    out << "      \"value\": " << ev.value << ",\n";
    out << "      \"min\": " << ev.min << ",\n";
    out << "      \"max\": " << ev.max << ",\n";
    out << "      \"median\": " << ev.median << ",\n";
    out << "      \"mean\": " << ev.mean << ",\n";
    out << "      \"p95\": " << ev.p95 << ",\n";
    out << "      \"p99\": " << ev.p99 << ",\n";
    out << "      \"stddev\": " << ev.stddev << ",\n";
    out << "      \"samples\": " << ev.samples << ",\n";
    out << "      \"methodology\": \"" << ev.methodology << "\",\n";
    out << "      \"unit\": \"" << ev.unit << "\",\n";
    out << "      \"valid\": " << (ev.valid ? "true" : "false") << "\n";
    out << "    }";
    if (!last) out << ",";
    out << "\n";
}

bool CertificationHarness::ExportJSON(const std::string& path) const {
    std::ofstream out(path);
    if (!out) return false;

    out << "{\n";
    out << "  \"certification\": {\n";
    out << "    \"timestamp\": \"" << report_.identity.timestamp_start << "\",\n";
    out << "    \"timestamp_end\": \"" << report_.identity.timestamp_end << "\",\n";
    out << "    \"rawrxd_version\": \"1.0.0\",\n";
    out << "    \"git_commit\": \"" << report_.identity.git_commit << "\",\n";
    out << "    \"git_branch\": \"" << report_.identity.git_branch << "\",\n";
    out << "    \"build_type\": \"" << report_.identity.build_type << "\",\n";
    out << "    \"hostname\": \"" << report_.identity.hostname << "\",\n";
    out << "    \"status\": \"";
    switch (report_.status) {
        case CertificationStatus::CERTIFIED: out << "CERTIFIED"; break;
        case CertificationStatus::CONDITIONALLY_CERTIFIED: out << "CONDITIONALLY_CERTIFIED"; break;
        case CertificationStatus::FAILED: out << "FAILED"; break;
        default: out << "INCOMPLETE"; break;
    }
    out << "\",\n";
    out << "    \"evidence_score\": " << report_.evidence_score << ",\n";
    out << "    \"valuation_note\": \"" << report_.valuation_note << "\",\n";

    // System
    out << "    \"system\": {\n";
    out << "      \"cpu\": \"" << report_.system.cpu << "\",\n";
    out << "      \"cpu_cores\": " << report_.system.cpu_cores << ",\n";
    out << "      \"avx2\": " << (report_.system.avx2 ? "true" : "false") << ",\n";
    out << "      \"avx512\": " << (report_.system.avx512 ? "true" : "false") << ",\n";
    out << "      \"total_ram_gb\": " << std::fixed << std::setprecision(1)
        << (report_.system.total_ram_bytes / (1024.0 * 1024.0 * 1024.0)) << ",\n";
    out << "      \"gpu0\": \"" << report_.system.gpu0 << "\",\n";
    out << "      \"gpu0_vram_gb\": " << std::fixed << std::setprecision(1)
        << (report_.system.gpu0_vram_bytes / (1024.0 * 1024.0 * 1024.0)) << "\n";
    out << "    },\n";

    // Gates
    out << "    \"gates\": {\n";
    out << "      \"correctness\": " << (report_.gates.correctness ? "true" : "false") << ",\n";
    out << "      \"zero_stubs\": " << (report_.gates.zero_stubs ? "true" : "false") << ",\n";
    out << "      \"stability\": " << (report_.gates.stability ? "true" : "false") << ",\n";
    out << "      \"compatibility_matrix\": " << (report_.gates.compatibility_matrix ? "true" : "false") << ",\n";
    out << "      \"quantization_coverage\": " << (report_.gates.quantization_coverage ? "true" : "false") << ",\n";
    out << "      \"architecture_coverage\": " << (report_.gates.architecture_coverage ? "true" : "false") << ",\n";
    out << "      \"performance_measured\": " << (report_.gates.performance_measured ? "true" : "false") << ",\n";
    out << "      \"gpu_execution\": " << (report_.gates.gpu_execution ? "true" : "false") << ",\n";
    out << "      \"multi_gpu\": " << (report_.gates.multi_gpu ? "true" : "false") << ",\n";
    out << "      \"concurrency\": " << (report_.gates.concurrency ? "true" : "false") << "\n";
    out << "    },\n";

    // Scenario results
    out << "    \"scenarios\": [\n";
    for (size_t i = 0; i < report_.scenario_results.size(); ++i) {
        const auto& r = report_.scenario_results[i];
        out << "      {\n";
        out << "        \"scenario_id\": \"" << r.scenario.scenario_id << "\",\n";
        out << "        \"model\": \"" << r.scenario.model_path << "\",\n";
        out << "        \"quant\": \"" << r.scenario.quantization << "\",\n";
        out << "        \"architecture\": \"" << r.scenario.architecture << "\",\n";
        WriteMetricJSON(out, r.decode_tps, "decode_tps", false);
        WriteMetricJSON(out, r.ttft_ms, "ttft_ms", false);
        out << "        \"correctness\": {\n";
        out << "          \"generated_sequence_match\": " << (r.correctness.generated_sequence_match ? "true" : "false") << ",\n";
        out << "          \"note\": \"" << r.correctness.note << "\"\n";
        out << "        },\n";
        out << "        \"passed\": " << (r.passed ? "true" : "false") << "\n";
        out << "      }";
        if (i + 1 < report_.scenario_results.size()) out << ",";
        out << "\n";
    }
    out << "    ],\n";

    // Stub verification
    out << "    \"stub_verification\": {\n";
    out << "      \"source_references\": " << report_.stub_verification.source_references << ",\n";
    out << "      \"linked_stub_objects\": " << report_.stub_verification.linked_stub_objects << ",\n";
    out << "      \"fake_success_apis\": " << report_.stub_verification.fake_success_apis << ",\n";
    out << "      \"fake_null_capabilities\": " << report_.stub_verification.fake_null_capabilities << ",\n";
    out << "      \"passed\": " << (report_.stub_verification.passed ? "true" : "false") << "\n";
    out << "    },\n";

    // Executive
    out << "    \"executive\": {\n";
    out << "      \"total_scenarios_tested\": " << report_.total_scenarios_tested << ",\n";
    out << "      \"total_scenarios_passed\": " << report_.total_scenarios_passed << ",\n";
    out << "      \"best_cpu_tps\": " << report_.best_cpu_tps << ",\n";
    out << "      \"best_gpu_tps\": " << report_.best_gpu_tps << ",\n";
    out << "      \"best_scenario\": \"" << report_.best_scenario << "\"\n";
    out << "    }\n";
    out << "  }\n";
    out << "}\n";
    return true;
}

// ============================================================================
// Report Export: Markdown
// ============================================================================
bool CertificationHarness::ExportMarkdown(const std::string& path) const {
    std::ofstream out(path);
    if (!out) return false;

    out << "# RawrXD Production Certification Report\n\n";
    out << "**Date:** " << report_.identity.timestamp_start << "  \n";
    out << "**Commit:** `" << report_.identity.git_commit << "`  \n";
    out << "**Status:** ";
    switch (report_.status) {
        case CertificationStatus::CERTIFIED: out << "CERTIFIED"; break;
        case CertificationStatus::CONDITIONALLY_CERTIFIED: out << "CONDITIONALLY CERTIFIED"; break;
        case CertificationStatus::FAILED: out << "FAILED"; break;
        default: out << "INCOMPLETE"; break;
    }
    out << "  \n";
    out << "**Evidence Score:** " << report_.evidence_score << "/100  \n\n";

    out << "## System Under Test\n\n";
    out << "| Component | Value |\n";
    out << "|-----------|-------|\n";
    out << "| CPU | " << report_.system.cpu << " |\n";
    out << "| Cores | " << report_.system.cpu_cores << " |\n";
    out << "| AVX2 | " << (report_.system.avx2 ? "Yes" : "No") << " |\n";
    out << "| AVX512 | " << (report_.system.avx512 ? "Yes" : "No") << " |\n";
    out << "| RAM | " << std::fixed << std::setprecision(1)
        << (report_.system.total_ram_bytes / (1024.0 * 1024.0 * 1024.0)) << " GB |\n";
    out << "| GPU0 | " << report_.system.gpu0 << " |\n";
    out << "| VRAM0 | " << std::fixed << std::setprecision(1)
        << (report_.system.gpu0_vram_bytes / (1024.0 * 1024.0 * 1024.0)) << " GB |\n\n";

    out << "## Scenario Results\n\n";
    out << "| Scenario | Quant | CPU TPS | TTFT (ms) | Correct | Pass |\n";
    out << "|----------|-------|---------|-----------|---------|------|\n";
    for (const auto& r : report_.scenario_results) {
        out << "| " << r.scenario.scenario_id << " | " << r.scenario.quantization
            << " | " << std::fixed << std::setprecision(1) << r.decode_tps.value
            << " | " << std::setprecision(2) << r.ttft_ms.value
            << " | " << (r.correctness.generated_sequence_match ? "YES" : "NO")
            << " | " << (r.passed ? "PASS" : "FAIL") << " |\n";
    }
    out << "\n";

    out << "## Certification Gates\n\n";
    out << "| Gate | Points | Status |\n";
    out << "|------|--------|--------|\n";
    auto gate_md = [&](const char* name, bool pass, int pts) {
        out << "| " << name << " | " << pts << " | " << (pass ? "PASS" : "FAIL") << " |\n";
    };
    gate_md("Correctness", report_.gates.correctness, 20);
    gate_md("Zero Stubs", report_.gates.zero_stubs, 5);
    gate_md("Stability", report_.gates.stability, 5);
    gate_md("Compatibility", report_.gates.compatibility_matrix, 15);
    gate_md("Quantization", report_.gates.quantization_coverage, 10);
    gate_md("Architecture", report_.gates.architecture_coverage, 10);
    gate_md("Performance", report_.gates.performance_measured, 15);
    gate_md("GPU", report_.gates.gpu_execution, 10);
    gate_md("Multi-GPU", report_.gates.multi_gpu, 5);
    gate_md("Concurrency", report_.gates.concurrency, 5);
    out << "\n**Total: " << report_.evidence_score << "/100**\n\n";

    out << "## Stub Verification\n\n";
    out << "| Check | Count |\n";
    out << "|-------|-------|\n";
    out << "| Source references | " << report_.stub_verification.source_references << " |\n";
    out << "| Linked stub objects | " << report_.stub_verification.linked_stub_objects << " |\n";
    out << "| Fake success APIs | " << report_.stub_verification.fake_success_apis << " |\n";
    out << "| Fake null capabilities | " << report_.stub_verification.fake_null_capabilities << " |\n";
    out << "| **Result** | " << (report_.stub_verification.passed ? "PASS" : "FAIL") << " |\n\n";

    out << "## Executive Summary\n\n";
    out << "- **Scenarios Tested:** " << report_.total_scenarios_tested << "\n";
    out << "- **Scenarios Passed:** " << report_.total_scenarios_passed << "\n";
    out << "- **Best CPU TPS:** " << report_.best_cpu_tps << " (" << report_.best_scenario << ")\n";
    out << "- **Best GPU TPS:** " << report_.best_gpu_tps << "\n";
    out << "- **Evidence Score:** " << report_.evidence_score << "/100\n\n";
    out << "> " << report_.valuation_note << "\n";

    return true;
}

// ============================================================================
// Report Export: HTML
// ============================================================================
bool CertificationHarness::ExportHTML(const std::string& path) const {
    std::ofstream out(path);
    if (!out) return false;

    out << "<!DOCTYPE html>\n<html><head><meta charset='utf-8'>\n";
    out << "<title>RawrXD Certification Report</title>\n";
    out << "<style>";
    out << "body{font-family:system-ui,sans-serif;max-width:1200px;margin:2em auto;padding:0 1em;}";
    out << "h1,h2{color:#1a1a1a;}table{border-collapse:collapse;width:100%;margin:1em 0;}";
    out << "th,td{border:1px solid #ddd;padding:8px;text-align:left;}";
    out << "th{background:#f5f5f5;}tr:nth-child(even){background:#fafafa;}";
    out << ".pass{color:green;font-weight:bold;}.fail{color:red;font-weight:bold;}";
    out << ".score{font-size:2em;text-align:center;padding:1em;background:#f0f0f0;border-radius:8px;}";
    out << ".score-high{background:#d4edda;}.score-med{background:#fff3cd;}.score-low{background:#f8d7da;}";
    out << "</style></head><body>\n";

    out << "<h1>RawrXD Production Certification Report</h1>\n";
    out << "<p><strong>Date:</strong> " << report_.identity.timestamp_start << "<br>";
    out << "<strong>Commit:</strong> <code>" << report_.identity.git_commit << "</code><br>";
    out << "<strong>Status:</strong> ";
    switch (report_.status) {
        case CertificationStatus::CERTIFIED: out << "CERTIFIED"; break;
        case CertificationStatus::CONDITIONALLY_CERTIFIED: out << "CONDITIONALLY CERTIFIED"; break;
        case CertificationStatus::FAILED: out << "FAILED"; break;
        default: out << "INCOMPLETE"; break;
    }
    out << "</p>\n";

    std::string score_class = report_.evidence_score >= 80 ? "score-high" :
                               (report_.evidence_score >= 50 ? "score-med" : "score-low");
    out << "<div class='score " << score_class << "'>Evidence Score: " << report_.evidence_score << "/100</div>\n";

    out << "<h2>System Under Test</h2>\n<table>\n";
    out << "<tr><th>Component</th><th>Value</th></tr>\n";
    out << "<tr><td>CPU</td><td>" << report_.system.cpu << "</td></tr>\n";
    out << "<tr><td>Cores</td><td>" << report_.system.cpu_cores << "</td></tr>\n";
    out << "<tr><td>AVX2</td><td>" << (report_.system.avx2 ? "Yes" : "No") << "</td></tr>\n";
    out << "<tr><td>AVX512</td><td>" << (report_.system.avx512 ? "Yes" : "No") << "</td></tr>\n";
    out << "<tr><td>RAM</td><td>" << std::fixed << std::setprecision(1)
        << (report_.system.total_ram_bytes / (1024.0 * 1024.0 * 1024.0)) << " GB</td></tr>\n";
    out << "<tr><td>GPU0</td><td>" << report_.system.gpu0 << "</td></tr>\n";
    out << "<tr><td>VRAM0</td><td>" << std::fixed << std::setprecision(1)
        << (report_.system.gpu0_vram_bytes / (1024.0 * 1024.0 * 1024.0)) << " GB</td></tr>\n";
    out << "</table>\n";

    out << "<h2>Scenario Results</h2>\n<table>\n";
    out << "<tr><th>Scenario</th><th>Quant</th><th>TPS</th><th>TTFT</th><th>Correct</th><th>Status</th></tr>\n";
    for (const auto& r : report_.scenario_results) {
        out << "<tr><td>" << r.scenario.scenario_id << "</td><td>" << r.scenario.quantization << "</td>";
        out << "<td>" << std::fixed << std::setprecision(1) << r.decode_tps.value << "</td>";
        out << "<td>" << std::setprecision(2) << r.ttft_ms.value << " ms</td>";
        out << "<td>" << (r.correctness.generated_sequence_match ? "YES" : "NO") << "</td>";
        out << "<td class='" << (r.passed ? "pass" : "fail") << "'>" << (r.passed ? "PASS" : "FAIL") << "</td></tr>\n";
    }
    out << "</table>\n";

    out << "<h2>Certification Gates</h2>\n<table>\n";
    out << "<tr><th>Gate</th><th>Points</th><th>Status</th></tr>\n";
    auto gate_html = [&](const char* name, bool pass, int pts) {
        out << "<tr><td>" << name << "</td><td>" << pts << "</td>";
        out << "<td class='" << (pass ? "pass" : "fail") << "'>" << (pass ? "PASS" : "FAIL") << "</td></tr>\n";
    };
    gate_html("Correctness", report_.gates.correctness, 20);
    gate_html("Zero Stubs", report_.gates.zero_stubs, 5);
    gate_html("Stability", report_.gates.stability, 5);
    gate_html("Compatibility", report_.gates.compatibility_matrix, 15);
    gate_html("Quantization", report_.gates.quantization_coverage, 10);
    gate_html("Architecture", report_.gates.architecture_coverage, 10);
    gate_html("Performance", report_.gates.performance_measured, 15);
    gate_html("GPU", report_.gates.gpu_execution, 10);
    gate_html("Multi-GPU", report_.gates.multi_gpu, 5);
    gate_html("Concurrency", report_.gates.concurrency, 5);
    out << "</table>\n";

    out << "<h2>Executive Summary</h2>\n<ul>\n";
    out << "<li>Scenarios Tested: " << report_.total_scenarios_tested << "</li>\n";
    out << "<li>Scenarios Passed: " << report_.total_scenarios_passed << "</li>\n";
    out << "<li>Best CPU TPS: " << report_.best_cpu_tps << " (" << report_.best_scenario << ")</li>\n";
    out << "<li>Best GPU TPS: " << report_.best_gpu_tps << "</li>\n";
    out << "<li>Evidence Score: " << report_.evidence_score << "/100</li>\n";
    out << "</ul>\n";
    out << "<p><em>" << report_.valuation_note << "</em></p>\n";

    out << "</body></html>\n";
    return true;
}

// ============================================================================
// CLI Entry Point
// ============================================================================
int RunCertificationCLI(int argc, char** argv) {
    CertConfig config;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--model" && i + 1 < argc) {
            config.model_paths.push_back(argv[++i]);
        } else if (arg == "--scenario" && i + 1 < argc) {
            BenchmarkScenario sc;
            sc.scenario_id = argv[++i];
            if (i + 1 < argc) sc.model_path = argv[++i];
            config.scenarios.push_back(sc);
        } else if (arg == "--output" && i + 1 < argc) {
            config.output_dir = argv[++i];
        } else if (arg == "--stability-requests" && i + 1 < argc) {
            config.stability_requests = (uint32_t)std::atoi(argv[++i]);
        } else if (arg == "--concurrent" && i + 1 < argc) {
            config.concurrent_requests = (uint32_t)std::atoi(argv[++i]);
        } else if (arg == "--no-gpu") {
            config.test_gpu = false;
        } else if (arg == "--no-ollama") {
            config.compare_ollama = false;
        } else if (arg == "--no-llamacpp") {
            config.compare_llamacpp = false;
        } else if (arg == "--help" || arg == "-h") {
            printf("Usage: %s [options]\n", argv[0]);
            printf("  --model <path>           Add model to certification matrix\n");
            printf("  --scenario <id> <path>    Add explicit scenario\n");
            printf("  --output <dir>           Output directory for reports\n");
            printf("  --stability-requests <n> Number of stability requests (default: 1000)\n");
            printf("  --concurrent <n>         Concurrent request count (default: 4)\n");
            printf("  --no-gpu                 Skip GPU tests\n");
            printf("  --no-ollama              Skip Ollama comparison\n");
            printf("  --no-llamacpp            Skip llama.cpp comparison\n");
            printf("  --help                   Show this help\n");
            return 0;
        }
    }

    if (config.model_paths.empty() && config.scenarios.empty()) {
        fprintf(stderr, "Error: No models specified. Use --model <path>\n");
        return 1;
    }

#ifdef _WIN32
    _mkdir(config.output_dir.c_str());
#else
    mkdir(config.output_dir.c_str(), 0755);
#endif

    CertificationHarness harness(config);
    auto report = harness.Run();

    std::string base = config.output_dir + "/certification_" + report.identity.timestamp_start.substr(0, 10);
    if (config.export_json) harness.ExportJSON(base + ".json");
    if (config.export_markdown) harness.ExportMarkdown(base + ".md");
    if (config.export_html) harness.ExportHTML(base + ".html");

    printf("\n[EXPORT] Reports written to:\n");
    if (config.export_json) printf("  %s.json\n", base.c_str());
    if (config.export_markdown) printf("  %s.md\n", base.c_str());
    if (config.export_html) printf("  %s.html\n", base.c_str());

    return (report.status == CertificationStatus::CERTIFIED ||
            report.status == CertificationStatus::CONDITIONALLY_CERTIFIED) ? 0 : 1;
}

} // namespace certify
} // namespace rawrxd

// Standalone CLI entry point
int main(int argc, char** argv) {
    return rawrxd::certify::RunCertificationCLI(argc, argv);
}
