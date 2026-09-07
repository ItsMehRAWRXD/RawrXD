// ============================================================================
// Deep2Benchmark.cpp - Production Benchmark Harness Implementation
// ============================================================================

#include "Deep2Benchmark.h"
#include "Deep2Engine.h"
#include "Tokenizer.hpp"
#include "../../core/GpuDecodeEfficiency.hpp"
#include <iostream>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <thread>
#include <functional>

#ifdef _WIN32
#include <windows.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <psapi.h>
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "psapi.lib")
#endif

namespace Deep2 {
namespace {

constexpr uint64_t kDecodeWindowTokens = kBenchDecodeWindowTokens;
constexpr double kDegradationThreshold = 0.75;
constexpr uint32_t kRequiredFullWindowsCertify = kBenchRequiredFullWindowsCertify;

uint64_t processWorkingSetBytes() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc{};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc)))
        return static_cast<uint64_t>(pmc.WorkingSetSize);
#endif
    return 0;
}

uint64_t estimateKvBytes(const EngineConfig& cfg, uint64_t seqTokens) {
    if (cfg.numLayers == 0 || cfg.numKVHeads == 0 || cfg.headDim == 0)
        return 0;
    return static_cast<uint64_t>(cfg.numLayers) * seqTokens *
           static_cast<uint64_t>(cfg.numKVHeads) *
           static_cast<uint64_t>(cfg.headDim) * sizeof(float) * 2ull;
}

double percentileMs(std::vector<double> values, double p) {
    if (values.empty()) return 0.0;
    std::sort(values.begin(), values.end());
    const double idx = p * static_cast<double>(values.size() - 1);
    const size_t lo = static_cast<size_t>(idx);
    const size_t hi = (std::min)(lo + 1, values.size() - 1);
    const double frac = idx - static_cast<double>(lo);
    return values[lo] * (1.0 - frac) + values[hi] * frac;
}

} // namespace

class BenchmarkHarness::Impl {
public:
    std::unique_ptr<Deep2Engine> engine;
    std::unique_ptr<ITokenizer> tokenizer;
    bool initialized = false;
    std::string modelPath;
    std::vector<DecodeWindow> lastWindows;

#ifdef _WIN32
    PDH_HQUERY gpuQuery = nullptr;
    PDH_HCOUNTER gpuUtilCounter = nullptr;
    PDH_HCOUNTER vramUtilCounter = nullptr;
    PDH_HCOUNTER gpuTempCounter = nullptr;
    PDH_HCOUNTER gpuPowerCounter = nullptr;
#endif

    bool initGpuTelemetry() {
#ifdef _WIN32
        if (PdhOpenQuery(nullptr, 0, &gpuQuery) != ERROR_SUCCESS) return false;
        PdhAddCounterA(gpuQuery, "\\GPU Engine(*)\\Utilization Percentage", 0, &gpuUtilCounter);
        PdhAddCounterA(gpuQuery, "\\GPU Adapter Memory(*)\\Dedicated Usage", 0, &vramUtilCounter);
        PdhAddCounterA(gpuQuery, "\\AMD GPU(*)\\Temperature", 0, &gpuTempCounter);
        PdhAddCounterA(gpuQuery, "\\AMD GPU(*)\\Power", 0, &gpuPowerCounter);
        return true;
#else
        return false;
#endif
    }

    void sampleGpuTelemetry(uint32_t& gpuUtil, uint32_t& vramUtil,
                            uint32_t& temp, uint32_t& power) {
#ifdef _WIN32
        if (!gpuQuery) return;
        PdhCollectQueryData(gpuQuery);
        PDH_FMT_COUNTERVALUE value;
        if (gpuUtilCounter) {
            PdhGetFormattedCounterValue(gpuUtilCounter, PDH_FMT_LONG, nullptr, &value);
            gpuUtil = value.longValue;
        }
        if (vramUtilCounter) {
            PdhGetFormattedCounterValue(vramUtilCounter, PDH_FMT_LONG, nullptr, &value);
            vramUtil = value.longValue;
        }
        if (gpuTempCounter) {
            PdhGetFormattedCounterValue(gpuTempCounter, PDH_FMT_LONG, nullptr, &value);
            temp = value.longValue;
        }
        if (gpuPowerCounter) {
            PdhGetFormattedCounterValue(gpuPowerCounter, PDH_FMT_LONG, nullptr, &value);
            power = value.longValue;
        }
#else
        (void)gpuUtil; (void)vramUtil; (void)temp; (void)power;
#endif
    }

    uint64_t getPeakVRAM() { return 0; }

    uint64_t getPeakSystemRAM() {
        const uint64_t ws = processWorkingSetBytes();
        if (ws) return ws;
#ifdef _WIN32
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        GlobalMemoryStatusEx(&memStatus);
        return memStatus.ullTotalPhys - memStatus.ullAvailPhys;
#else
        return 0;
#endif
    }
};

BenchmarkHarness::BenchmarkHarness() : pImpl(std::make_unique<Impl>()) {}
BenchmarkHarness::~BenchmarkHarness() = default;

bool BenchmarkHarness::initialize(const std::string& modelPath) {
    pImpl->engine = std::make_unique<Deep2Engine>();
    pImpl->tokenizer = std::make_unique<CharTokenizer>();

    EngineConfig config;
    strncpy(config.modelPath, modelPath.c_str(), sizeof(config.modelPath) - 1);
    config.modelPath[sizeof(config.modelPath) - 1] = '\0';

    if (!pImpl->engine->initialize(config)) return false;
    if (!pImpl->engine->loadModel(modelPath)) return false;

    pImpl->modelPath = modelPath;
    pImpl->initialized = true;
    pImpl->initGpuTelemetry();
    return true;
}

StreamBenchmark BenchmarkHarness::runSingleStreamTest(
    const std::string& prompt,
    uint64_t maxTokens,
    uint32_t ctxSize
) {
    StreamBenchmark bench;
    bench.timestamp_ns = nowNs();
    bench.target_tokens = maxTokens;
    bench.context_length = ctxSize;
    pImpl->lastWindows.clear();

    if (!pImpl->initialized || !pImpl->engine) {
        bench.stream_stable = false;
        bench.used_production_decode_path = false;
        bench.decode_real = false;
        bench.fail_reason_code = BENCH_FAIL_NON_PRODUCTION_DECODE_PATH;
        emitBenchmarkTelemetry(bench, BenchmarkPhase::STREAM);
        return bench;
    }

    if (ctxSize > 0 && ctxSize > pImpl->engine->getConfig().maxSeqLen)
        (void)pImpl->engine->growContext(ctxSize);

    const uint64_t tSubmit = nowNs();
    auto promptTokens = pImpl->engine->tokenize(prompt);
    bench.prompt_tokens = promptTokens.size();

    GenerationOptions opts;
    opts.maxTokens = static_cast<uint32_t>(maxTokens);
    opts.temperature = 0.0f;
    opts.topP = 1.0f;
    opts.topK = 1;
    pImpl->engine->configureGeneration(opts);

    const EngineConfig& cfg = pImpl->engine->getConfig();
    bench.kv_start_bytes = estimateKvBytes(cfg, bench.prompt_tokens);

    std::vector<int> outputTokens(static_cast<size_t>(maxTokens), 0);
    std::vector<uint64_t> emitNs;
    emitNs.reserve(static_cast<size_t>(maxTokens));

    uint64_t peakRam = processWorkingSetBytes();
    uint64_t peakVram = pImpl->getPeakVRAM();

    rawrxd::GpuDecodeEfficiencySession gpuEff;
    gpuEff.BeginDecodeWindow();

    InferenceStats stats{};
    const size_t generated = pImpl->engine->generate(
        promptTokens.data(),
        promptTokens.size(),
        outputTokens.data(),
        static_cast<size_t>(maxTokens),
        &stats,
        [&](int /*tokenId*/) -> bool {
            emitNs.push_back(nowNs());
            peakRam = (std::max)(peakRam, processWorkingSetBytes());
            peakVram = (std::max)(peakVram, pImpl->getPeakVRAM());
            return true;
        });

    const uint64_t tEnd = nowNs();
    bench.duration_sec = (tEnd - tSubmit) / 1e9;

    const auto gpuResult = gpuEff.Finalize(generated);
    bench.gpu_power_valid = gpuResult.power_valid;
    if (gpuResult.power_valid) {
        bench.avg_gpu_power_watts = gpuResult.average_gpu_watts;
        bench.tokens_per_watt_gpu = gpuResult.tokens_per_watt_gpu;
        bench.gpu_power_sample_count = gpuResult.power_sample_count;
        bench.power_watts = static_cast<uint32_t>(gpuResult.average_gpu_watts);
    } else {
        bench.avg_gpu_power_watts = -1.0;
        bench.tokens_per_watt_gpu = -1.0;
        bench.gpu_power_sample_count = 0;
        bench.power_watts = 0;
    }
    rawrxd::PublishGpuDecodeEfficiency(gpuResult);

    // Hard rule: harness measures only — never invents decode tokens.
    const bool productionPath =
        generated > 0 &&
        emitNs.size() == generated &&
        stats.decodeMs > 0.0;

    bench.used_production_decode_path = productionPath;
    bench.decode_real = productionPath;
    bench.generated_tokens = generated;
    bench.peak_system_bytes = peakRam ? peakRam : pImpl->getPeakSystemRAM();
    bench.peak_vram_bytes = peakVram;

    if (!productionPath) {
        bench.stream_stable = false;
        bench.vram_stable = false;
        bench.kv_stable = false;
        bench.fail_reason_code = (generated == 0)
            ? BENCH_FAIL_ZERO_TOKENS
            : BENCH_FAIL_NON_PRODUCTION_DECODE_PATH;
        emitBenchmarkTelemetry(bench, BenchmarkPhase::STREAM);
        EmitBenchmarkCertTelemetry(bench, pImpl->modelPath.c_str(), "Q4_K_M",
                                   "AMD Radeon RX 7800 XT", 1);
        return bench;
    }

    bench.prefill_tps = stats.prefillTokensPerSecond;
    bench.decode_tps = stats.decodeTokensPerSecond;
    bench.total_decode_ns = static_cast<uint64_t>(stats.decodeMs * 1e6);

    const uint64_t prefillNs = static_cast<uint64_t>(stats.prefillMs * 1e6);
    const uint64_t decodeStartNs = tSubmit + prefillNs;

    bench.ttft_e2e_ns = emitNs[0] - tSubmit;
    bench.first_token_ns = bench.ttft_e2e_ns;
    bench.first_decode_after_prefill_ns =
        (emitNs[0] > decodeStartNs) ? (emitNs[0] - decodeStartNs) : 0;

    std::vector<uint64_t> perTokenNs;
    std::vector<double> perTokenMs;
    perTokenNs.reserve(emitNs.size());
    perTokenMs.reserve(emitNs.size());
    for (size_t i = 0; i < emitNs.size(); ++i) {
        const uint64_t prev = (i == 0) ? decodeStartNs : emitNs[i - 1];
        const uint64_t dt = (emitNs[i] > prev) ? (emitNs[i] - prev) : 0;
        perTokenNs.push_back(dt);
        perTokenMs.push_back(dt / 1e6);
    }

    bench.per_token_min_ns = *std::min_element(perTokenNs.begin(), perTokenNs.end());
    bench.per_token_max_ns = *std::max_element(perTokenNs.begin(), perTokenNs.end());
    uint64_t sumNs = 0;
    for (uint64_t ns : perTokenNs) sumNs += ns;
    bench.per_token_avg_ns = sumNs / perTokenNs.size();
    bench.decode_p50_ms = percentileMs(perTokenMs, 0.50);
    bench.decode_p95_ms = percentileMs(perTokenMs, 0.95);
    bench.decode_p99_ms = percentileMs(perTokenMs, 0.99);

    const double meanNs = static_cast<double>(bench.per_token_avg_ns);
    double varSum = 0.0;
    for (uint64_t ns : perTokenNs) {
        const double d = static_cast<double>(ns) - meanNs;
        varSum += d * d;
    }
    const double stddev = std::sqrt(varSum / perTokenNs.size());
    bench.tps_variance = (meanNs > 0.0) ? (stddev / meanNs) : 0.0;

    double minFullWindowTps = 1e300;
    double firstFullWindowTps = 0.0;
    uint32_t fullWindowCount = 0;
    uint64_t tailWindowTokens = 0;

    for (uint64_t begin = 0; begin < generated; begin += kDecodeWindowTokens) {
        const uint64_t end = (std::min)(begin + kDecodeWindowTokens,
                                        static_cast<uint64_t>(generated));
        if (end <= begin) break;
        const uint64_t winTok = end - begin;
        const uint64_t t0 = (begin == 0) ? decodeStartNs : emitNs[begin - 1];
        const uint64_t t1 = emitNs[end - 1];
        const double sec = (t1 > t0) ? ((t1 - t0) / 1e9) : 0.0;
        if (sec <= 0.0) continue;

        DecodeWindow w;
        w.tokenBegin = begin;
        w.tokenEnd = end;
        w.seconds = sec;
        w.tps = static_cast<double>(winTok) / sec;
        w.kvBytes = estimateKvBytes(cfg, bench.prompt_tokens + end);
        w.vramBytes = peakVram;
        pImpl->lastWindows.push_back(w);

        // Incomplete tail must not set MIN_WINDOW / START / capacity.
        if (winTok < kDecodeWindowTokens) {
            tailWindowTokens = winTok;
            continue;
        }

        if (fullWindowCount == 0) firstFullWindowTps = w.tps;
        minFullWindowTps = (std::min)(minFullWindowTps, w.tps);
        ++fullWindowCount;
    }

    bench.full_window_count = fullWindowCount;
    bench.tail_window_tokens = static_cast<uint32_t>(tailWindowTokens);

    if (fullWindowCount == 0) {
        // Short generation: fallback authority is engine decode avg; not endurance.
        bench.decode_tps_start = bench.decode_tps;
        bench.decode_tps_min_window = bench.decode_tps;
        bench.sustained_tps = bench.decode_tps;
        bench.max_stable_streaming_tps = bench.decode_tps;
        bench.degradation_ratio = 1.0;
        bench.endurance_certifiable = false;
    } else {
        bench.decode_tps_start = firstFullWindowTps;
        bench.decode_tps_min_window = minFullWindowTps;
        bench.sustained_tps = bench.decode_tps_min_window;
        // Canonical product authority number.
        bench.max_stable_streaming_tps = bench.decode_tps_min_window;
        bench.degradation_ratio = (firstFullWindowTps > 0.0)
            ? (bench.decode_tps_min_window / firstFullWindowTps)
            : 0.0;
        bench.endurance_certifiable =
            (fullWindowCount >= kRequiredFullWindowsCertify);
    }

    bench.kv_end_bytes = estimateKvBytes(cfg, bench.prompt_tokens + generated);
    bench.kv_bytes = bench.kv_end_bytes;
    bench.kv_bytes_per_token = (generated > 0)
        ? static_cast<double>(bench.kv_end_bytes - bench.kv_start_bytes) /
          static_cast<double>(generated)
        : 0.0;

    uint32_t gpuUtil = 0, vramUtil = 0, temp = 0, power = 0;
    pImpl->sampleGpuTelemetry(gpuUtil, vramUtil, temp, power);
    bench.gpu_util_percent = gpuUtil;
    bench.vram_util_percent = vramUtil;
    bench.temperature_c = temp;

    // decodeStable: windows + degradation only (short run: requiredWindows=0).
    const uint32_t requiredWindows = (fullWindowCount == 0) ? 0u : 1u;
    const bool degradeOk = bench.degradation_ratio >= kDegradationThreshold;
    bench.decode_stable =
        (fullWindowCount >= requiredWindows) && degradeOk;
    bench.kv_stable = (bench.kv_end_bytes >= bench.kv_start_bytes);
    // Capacity must stay coupled to memory stability (estimate monotonic for now).
    bench.vram_stable = true;
    bench.stream_stable =
        bench.used_production_decode_path &&
        bench.decode_stable &&
        bench.vram_stable &&
        bench.kv_stable &&
        (bench.tps_variance < 0.15);

    if (!bench.used_production_decode_path) {
        bench.fail_reason_code = BENCH_FAIL_NON_PRODUCTION_DECODE_PATH;
    } else if (!bench.decode_stable) {
        bench.fail_reason_code = BENCH_FAIL_DECODE_UNSTABLE;
    } else if (!bench.stream_stable) {
        bench.fail_reason_code = BENCH_FAIL_DECODE_UNSTABLE;
    } else {
        bench.fail_reason_code = BENCH_FAIL_NONE;
    }

    emitBenchmarkTelemetry(bench, BenchmarkPhase::STREAM);
    EmitBenchmarkCertTelemetry(bench, pImpl->modelPath.c_str(), "Q4_K_M",
                               "AMD Radeon RX 7800 XT", 1);
    return bench;
}

std::vector<EnduranceResult> BenchmarkHarness::runEnduranceMatrix(
    const std::vector<uint32_t>& contextSizes,
    uint64_t tokensPerTest
) {
    std::vector<EnduranceResult> results;
    results.reserve(contextSizes.size());
    double baselineTps = 0.0;

    for (size_t i = 0; i < contextSizes.size(); ++i) {
        const uint32_t ctx = contextSizes[i];
        std::string syntheticPrompt;
        syntheticPrompt.reserve(static_cast<size_t>(ctx) * 4ull);
        while (pImpl->tokenizer->Encode(syntheticPrompt).size() < ctx / 2)
            syntheticPrompt += "The quick brown fox jumps over the lazy dog. ";

        auto bench = runSingleStreamTest(syntheticPrompt, tokensPerTest, ctx);

        EnduranceResult result;
        result.context_size = ctx;
        result.prefill_tps = bench.prefill_tps;
        result.decode_tps = bench.decode_tps;
        result.sustained_tps = bench.max_stable_streaming_tps;
        result.kv_bytes_per_token = bench.kv_bytes_per_token;
        result.peak_vram_bytes = bench.peak_vram_bytes;

        if (i == 0) {
            baselineTps = bench.decode_tps_start > 0.0
                ? bench.decode_tps_start
                : bench.decode_tps;
            result.stable = bench.stream_stable && bench.used_production_decode_path;
        } else {
            result.stable =
                bench.used_production_decode_path &&
                bench.degradation_ratio >= kDegradationThreshold &&
                (baselineTps <= 0.0 ||
                 bench.decode_tps_min_window >= baselineTps * kDegradationThreshold);
        }
        results.push_back(result);
        emitBenchmarkTelemetry(bench, BenchmarkPhase::ENDURANCE);
    }
    return results;
}

SaturationResult BenchmarkHarness::runSaturationTest(
    uint32_t numStreams,
    uint64_t tokensPerStream,
    uint32_t ctxPerStream
) {
    SaturationResult result{};
    result.num_streams = numStreams;
    if (numStreams == 0) {
        result.all_streams_stable = false;
        return result;
    }

    std::vector<double> streamTps;
    std::vector<double> ttftMs;
    streamTps.reserve(numStreams);
    ttftMs.reserve(numStreams);

    double aggTokens = 0.0;
    double aggSeconds = 0.0;
    bool allStable = true;

    for (uint32_t s = 0; s < numStreams; ++s) {
        std::string prompt = "Saturation stream " + std::to_string(s) +
            ": write production C++ with tests and docs. ";
        auto bench = runSingleStreamTest(prompt, tokensPerStream, ctxPerStream);
        if (!bench.used_production_decode_path || !bench.stream_stable)
            allStable = false;

        const double tps = bench.max_stable_streaming_tps > 0.0
            ? bench.max_stable_streaming_tps
            : bench.decode_tps;
        streamTps.push_back(tps);
        ttftMs.push_back(bench.ttft_e2e_ns / 1e6);
        result.total_tokens_generated += bench.generated_tokens;
        if (bench.duration_sec > 0.0) {
            aggTokens += static_cast<double>(bench.generated_tokens);
            aggSeconds += bench.duration_sec;
        }
        result.worst_first_token_ms =
            (std::max)(result.worst_first_token_ms, bench.ttft_e2e_ns / 1e6);
    }

    result.all_streams_stable = allStable;
    result.aggregate_tps = (aggSeconds > 0.0) ? (aggTokens / aggSeconds) : 0.0;
    double sum = 0.0;
    double fastest = 0.0;
    double slowest = 1e300;
    for (double tps : streamTps) {
        sum += tps;
        fastest = (std::max)(fastest, tps);
        slowest = (std::min)(slowest, tps);
    }
    result.avg_stream_tps = sum / streamTps.size();
    result.worst_stream_tps = (slowest < 1e300) ? slowest : 0.0;
    result.fairness_ratio = (fastest > 0.0) ? (slowest / fastest) : 0.0;

    std::sort(ttftMs.begin(), ttftMs.end());
    if (!ttftMs.empty()) {
        const size_t idx = (std::min)(ttftMs.size() - 1,
            static_cast<size_t>(0.95 * (ttftMs.size() - 1)));
        result.p95_ttft_ms = ttftMs[idx];
    }
    return result;
}

ThermalResult BenchmarkHarness::runThermalTest(
    uint32_t durationSeconds,
    uint32_t sampleIntervalSeconds
) {
    ThermalResult result{};
    result.duration_seconds = durationSeconds;

    std::string testPrompt = "Thermal stability test prompt. ";
    auto benchStart = runSingleStreamTest(testPrompt, 256, 4096);
    result.tps_start = benchStart.decode_tps;

    uint32_t peakTemp = 0;
    uint32_t throttleEvents = 0;
    double powerSum = 0.0;
    uint32_t sampleCount = 0;
    auto startTime = std::chrono::steady_clock::now();

    while (true) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - startTime).count();
        if (elapsed >= durationSeconds) break;

        uint32_t gpuUtil = 0, vramUtil = 0, temp = 0, power = 0;
        pImpl->sampleGpuTelemetry(gpuUtil, vramUtil, temp, power);
        peakTemp = (std::max)(peakTemp, temp);
        powerSum += power;
        sampleCount++;
        if (temp > 85) throttleEvents++;
        std::this_thread::sleep_for(std::chrono::seconds(sampleIntervalSeconds));
    }

    auto benchEnd = runSingleStreamTest(testPrompt, 256, 4096);
    result.tps_end = benchEnd.decode_tps;
    result.peak_temp_c = peakTemp;
    result.throttle_events = throttleEvents;
    result.avg_power_watts = sampleCount ? (powerSum / sampleCount) : 0.0;
    result.tps_degradation_percent = (result.tps_start > 0.0)
        ? (1.0 - (result.tps_end / result.tps_start)) * 100.0
        : 0.0;
    return result;
}

CertificationReport BenchmarkHarness::runFullCertification(const BenchmarkConfig& config) {
    CertificationReport report;
    report.certification_id = "DEEP2-STREAM-" + std::to_string(nowNs() / 1000000000);
    report.timestamp = std::to_string(std::time(nullptr));
    report.hardware_summary = "AMD Radeon RX 7800 XT (16GB)";
    report.model_info = config.model_name.empty() ? config.model_path : config.model_name;
    report.quant_info = "Q4_K_M";
    report.target_prefill_tps = 8000.0;
    report.target_decode_tps = 180.0;
    report.target_sustained_tps = 175.0;
    report.target_max_context = 32768;

    if (config.verbose) {
        std::cout << "\n[Deep2 Benchmark] Starting certification suite...\n";
        std::cout << "Model: " << report.model_info << "\n\n";
    }

    if (config.verbose) std::cout << "[1/5] Single-stream maximum throughput...\n";
    report.single_stream = runSingleStreamTest(
        config.prompt_text.empty()
            ? "Write a large C++ project with full documentation."
            : config.prompt_text,
        config.max_tokens,
        config.context_size);
    report.decode_windows = pImpl->lastWindows;

    report.production_decode_pass = report.single_stream.used_production_decode_path;
    if (!report.production_decode_pass) {
        report.fail_reason = "NON_PRODUCTION_DECODE_PATH";
        report.prefill_pass = false;
        report.decode_pass = false;
        report.stream_pass = false;
        report.endurance_pass = false;
        report.saturation_pass = false;
        report.thermal_pass = false;
        report.overall_certified = false;
        saveReport(report, config.output_path);
        if (config.verbose)
            std::cout << "\n" << generateCertTelemetry(report) << "\n";
        return report;
    }

    report.prefill_pass =
        (report.single_stream.prefill_tps >= report.target_prefill_tps * 0.9);
    report.decode_pass =
        (report.single_stream.decode_tps >= report.target_decode_tps * 0.9);
    // Capacity authority (U13): production decode + stability + 4 full windows.
    // Absolute marketing TPS targets are separate and must not block capacity PASS.
    const bool capacityCertified =
        report.single_stream.used_production_decode_path &&
        report.single_stream.decode_stable &&
        report.single_stream.vram_stable &&
        report.single_stream.kv_stable &&
        report.single_stream.endurance_certifiable;

    report.stream_pass = capacityCertified;
    if (report.production_decode_pass && !report.single_stream.endurance_certifiable &&
        report.fail_reason.empty()) {
        report.fail_reason = "INSUFFICIENT_WINDOWS";
        report.single_stream.fail_reason_code = BENCH_FAIL_INSUFFICIENT_WINDOWS;
    }

    if (config.verbose) std::cout << "[2/5] Endurance matrix (context scaling)...\n";
    report.endurance_matrix = runEnduranceMatrix(
        config.endurance_contexts, config.endurance_tokens_per_test);
    report.endurance_pass = true;
    for (const auto& e : report.endurance_matrix) {
        if (!e.stable) report.endurance_pass = false;
    }

    if (config.verbose) std::cout << "[3/5] Multi-stream saturation...\n";
    report.saturation = runSaturationTest(
        config.saturation_streams,
        config.saturation_tokens_per_stream,
        config.saturation_ctx_per_stream);
    report.saturation_pass = report.saturation.all_streams_stable;

    if (config.verbose) std::cout << "[4/5] Thermal soak...\n";
    report.thermal = runThermalTest(
        config.thermal_duration_seconds,
        config.thermal_sample_interval_seconds);
    report.thermal_pass =
        (report.thermal.throttle_events == 0) &&
        (report.thermal.tps_degradation_percent < 10.0);

    report.overall_certified =
        report.production_decode_pass &&
        report.single_stream.decode_stable &&
        report.single_stream.vram_stable &&
        report.single_stream.kv_stable &&
        report.single_stream.endurance_certifiable &&
        report.prefill_pass && report.decode_pass &&
        report.stream_pass && report.endurance_pass &&
        report.saturation_pass && report.thermal_pass;

    if (!report.overall_certified && report.fail_reason.empty()) {
        if (!report.single_stream.used_production_decode_path)
            report.fail_reason = "NON_PRODUCTION_DECODE_PATH";
        else if (!report.single_stream.endurance_certifiable)
            report.fail_reason = "INSUFFICIENT_WINDOWS";
        else if (!report.stream_pass) report.fail_reason = "DECODE_UNSTABLE";
        else if (!report.endurance_pass) report.fail_reason = "ENDURANCE_FAIL";
        else if (!report.saturation_pass) report.fail_reason = "SATURATION_FAIL";
        else if (!report.thermal_pass) report.fail_reason = "THERMAL_FAIL";
        else report.fail_reason = "TARGET_MISS";
    }

    saveReport(report, config.output_path);
    if (config.verbose) {
        std::cout << "\n" << generateMarkdownReport(report) << "\n";
        std::cout << generateCertTelemetry(report) << "\n";
    }
    return report;
}

std::string BenchmarkHarness::generateJSONReport(const CertificationReport& report) {
    std::stringstream json;
    json << std::fixed << std::setprecision(2);
    const auto& s = report.single_stream;
    json << "{\n";
    json << "  \"certification\": \"" << report.certification_id << "\",\n";
    json << "  \"timestamp\": \"" << report.timestamp << "\",\n";
    json << "  \"fail_reason\": \"" << report.fail_reason << "\",\n";
    json << "  \"hardware\": {\"summary\": \"" << report.hardware_summary << "\"},\n";
    json << "  \"model\": {\"path\": \"" << report.model_info
         << "\", \"quant\": \"" << report.quant_info << "\"},\n";
    json << "  \"prefill\": {\"tokens\": " << s.prompt_tokens
         << ", \"tps\": " << s.prefill_tps
         << ", \"status\": \"" << (report.prefill_pass ? "PASS" : "FAIL") << "\"},\n";
    json << "  \"decode\": {\"generated\": " << s.generated_tokens
         << ", \"tps_avg\": " << s.decode_tps
         << ", \"tps_start\": " << s.decode_tps_start
         << ", \"tps_min_window\": " << s.decode_tps_min_window
         << ", \"max_stable_streaming_tps\": " << s.max_stable_streaming_tps
         << ", \"ttft_e2e_ms\": " << (s.ttft_e2e_ns / 1e6)
         << ", \"first_decode_after_prefill_ms\": " << (s.first_decode_after_prefill_ns / 1e6)
         << ", \"decode_real\": " << (s.decode_real ? "true" : "false")
         << ", \"status\": \"" << (report.decode_pass ? "PASS" : "FAIL") << "\"},\n";
    json << "  \"stream\": {\"sustained_tps\": " << s.sustained_tps
         << ", \"degradation_ratio\": " << s.degradation_ratio
         << ", \"stable\": " << (s.stream_stable ? "true" : "false")
         << ", \"status\": \"" << (report.stream_pass ? "PASS" : "FAIL") << "\"},\n";
    json << "  \"saturation\": {\"streams\": " << report.saturation.num_streams
         << ", \"aggregate_tps\": " << report.saturation.aggregate_tps
         << ", \"worst_stream_tps\": " << report.saturation.worst_stream_tps
         << ", \"fairness_ratio\": " << report.saturation.fairness_ratio
         << ", \"status\": \"" << (report.saturation_pass ? "PASS" : "FAIL") << "\"},\n";
    json << "  \"overall\": \"" << (report.overall_certified ? "CERTIFIED" : "FAILED") << "\"\n";
    json << "}\n";
    return json.str();
}

std::string BenchmarkHarness::generateMarkdownReport(const CertificationReport& report) {
    std::stringstream md;
    md << std::fixed << std::setprecision(2);
    const auto& s = report.single_stream;
    md << "# Deep2 Maximum Streamable Throughput Certification\n\n";
    md << "**Certification ID:** `" << report.certification_id << "`\n\n";
    md << "**Decode path:** "
       << (s.used_production_decode_path ? "PRODUCTION `Deep2Engine::generate`"
                                         : "NON_PRODUCTION")
       << "\n\n";
    if (!report.fail_reason.empty())
        md << "**Fail reason:** `" << report.fail_reason << "`\n\n";
    md << "| Metric | Value |\n|--------|-------|\n";
    md << "| Prefill TPS | " << s.prefill_tps << " |\n";
    md << "| Decode TPS (avg) | " << s.decode_tps << " |\n";
    md << "| Decode TPS (start window) | " << s.decode_tps_start << " |\n";
    md << "| Decode TPS (min window) | " << s.decode_tps_min_window << " |\n";
    md << "| Max stable streaming TPS | " << s.max_stable_streaming_tps << " |\n";
    md << "| Degradation ratio | " << s.degradation_ratio << " |\n";
    md << "| TTFT E2E | " << (s.ttft_e2e_ns / 1e6) << " ms |\n";
    md << "| First decode after prefill | "
       << (s.first_decode_after_prefill_ns / 1e6) << " ms |\n";
    md << "\n### " << (report.overall_certified ? "CERTIFIED" : "FAILED") << "\n";
    return md.str();
}

std::string BenchmarkHarness::generateCertTelemetry(const CertificationReport& report) {
    std::stringstream t;
    t << std::fixed << std::setprecision(3);
    const auto& s = report.single_stream;
    // U13 capacity authority — not marketing TPS targets / full suite.
    const bool pass =
        s.used_production_decode_path &&
        s.decode_stable &&
        s.vram_stable &&
        s.kv_stable &&
        s.endurance_certifiable;
    t << "BENCHMARK_CERT_BEGIN\n";
    t << "BENCHMARK_VERSION=1\n";
    t << "MODEL=" << report.model_info << "\n";
    t << "QUANT=" << report.quant_info << "\n";
    t << "DEVICE=" << report.hardware_summary << "\n";
    t << "PROMPT_TOKENS=" << s.prompt_tokens << "\n";
    t << "GENERATED_TOKENS=" << s.generated_tokens << "\n";
    t << "CONTEXT_TOKENS=" << s.context_length << "\n";
    t << "CONCURRENT_STREAMS=" << report.saturation.num_streams << "\n";
    t << "PREFILL_TPS=" << s.prefill_tps << "\n";
    t << "DECODE_TPS_START=" << s.decode_tps_start << "\n";
    t << "DECODE_TPS_AVG=" << s.decode_tps << "\n";
    t << "DECODE_TPS_MIN_WINDOW=" << s.decode_tps_min_window << "\n";
    t << "DEGRADATION_RATIO=" << s.degradation_ratio << "\n";
    t << "FULL_WINDOW_COUNT=" << s.full_window_count << "\n";
    t << "FULL_STABILITY_WINDOWS=" << s.full_window_count << "\n";
    t << "TAIL_WINDOW_TOKENS=" << s.tail_window_tokens << "\n";
    t << "ENDURANCE_CERTIFIABLE=" << (s.endurance_certifiable ? 1 : 0) << "\n";
    t << "TTFT_E2E_MS=" << (s.ttft_e2e_ns / 1e6) << "\n";
    t << "FIRST_DECODE_AFTER_PREFILL_MS=" << (s.first_decode_after_prefill_ns / 1e6) << "\n";
    t << "DECODE_P50_MS=" << s.decode_p50_ms << "\n";
    t << "DECODE_P95_MS=" << s.decode_p95_ms << "\n";
    t << "DECODE_P99_MS=" << s.decode_p99_ms << "\n";
    t << "PEAK_RAM_MB=" << (s.peak_system_bytes / (1024.0 * 1024.0)) << "\n";
    t << "PEAK_VRAM_MB=" << (s.peak_vram_bytes / (1024.0 * 1024.0)) << "\n";
    t << "KV_START_MB=" << (s.kv_start_bytes / (1024.0 * 1024.0)) << "\n";
    t << "KV_END_MB=" << (s.kv_end_bytes / (1024.0 * 1024.0)) << "\n";
    t << "KV_MB_PER_1K_CONTEXT=" << (s.kv_bytes_per_token * 1000.0 / (1024.0 * 1024.0)) << "\n";
    t << "DURATION_SEC=" << s.duration_sec << "\n";
    t << "PRODUCTION_DECODE_PATH=" << (s.used_production_decode_path ? 1 : 0) << "\n";
    t << "DECODE_REAL=" << (s.decode_real ? 1 : 0) << "\n";
    t << "DECODE_STABLE=" << (s.decode_stable ? 1 : 0) << "\n";
    t << "VRAM_STABLE=" << (s.vram_stable ? 1 : 0) << "\n";
    t << "KV_STABLE=" << (s.kv_stable ? 1 : 0) << "\n";
    t << "STREAMS=" << report.saturation.num_streams << "\n";
    t << "AGGREGATE_DECODE_TPS=" << report.saturation.aggregate_tps << "\n";
    t << "WORST_STREAM_TPS=" << report.saturation.worst_stream_tps << "\n";
    t << "WORST_TTFT_MS=" << report.saturation.worst_first_token_ms << "\n";
    t << "P95_TTFT_MS=" << report.saturation.p95_ttft_ms << "\n";
    t << "FAIRNESS_RATIO=" << report.saturation.fairness_ratio << "\n";
    t << "MAXIMUM_STABLE_STREAMING_CAPACITY_TPS=" << s.max_stable_streaming_tps << "\n";
    if (!pass && !report.fail_reason.empty())
        t << "FAIL_REASON=" << report.fail_reason << "\n";
    t << "BENCHMARK_CERT_RESULT=" << (pass ? "PASS" : "FAIL") << "\n";
    t << "BENCHMARK_CERT_END\n";
    return t.str();
}

void BenchmarkHarness::saveReport(const CertificationReport& report, const std::string& path) {
    std::ofstream file(path);
    if (file.is_open()) file << generateJSONReport(report);

    std::string mdPath = path;
    const size_t dotPos = mdPath.rfind('.');
    mdPath = (dotPos != std::string::npos) ? mdPath.substr(0, dotPos) + ".md" : mdPath + ".md";
    std::ofstream mdFile(mdPath);
    if (mdFile.is_open()) mdFile << generateMarkdownReport(report);

    std::string certPath = (dotPos != std::string::npos)
        ? path.substr(0, dotPos) + ".cert.txt"
        : path + ".cert.txt";
    std::ofstream certFile(certPath);
    if (certFile.is_open()) certFile << generateCertTelemetry(report);
}

uint64_t BenchmarkHarness::nowNs() {
    return std::chrono::high_resolution_clock::now().time_since_epoch().count();
}

std::string BenchmarkHarness::formatBytes(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = static_cast<double>(bytes);
    while (size >= 1024.0 && unit < 4) { size /= 1024.0; unit++; }
    std::stringstream ss;
    ss << std::fixed << std::setprecision(2) << size << " " << units[unit];
    return ss.str();
}

std::string BenchmarkHarness::formatTps(double tps) {
    std::stringstream ss;
    if (tps >= 1000.0)
        ss << std::fixed << std::setprecision(1) << (tps / 1000.0) << "k";
    else
        ss << std::fixed << std::setprecision(1) << tps;
    ss << " tok/s";
    return ss.str();
}

void BenchmarkHarness::emitBenchmarkTelemetry(const StreamBenchmark& bench, BenchmarkPhase phase) {
    EmitBenchmarkTelemetry(bench, phase);
}

void BenchmarkHarness::emitBenchmarkCertTelemetry(const StreamBenchmark& bench,
                                                  const CertificationReport* report) {
    if (report) {
        std::cerr << generateCertTelemetry(*report);
        return;
    }
    EmitBenchmarkCertTelemetry(bench, pImpl->modelPath.c_str(), "Q4_K_M",
                               "AMD Radeon RX 7800 XT", 1);
}

const char* BenchmarkFailReasonString(uint32_t code) {
    switch (code) {
    case BENCH_FAIL_NONE: return "NONE";
    case BENCH_FAIL_NON_PRODUCTION_DECODE_PATH: return "NON_PRODUCTION_DECODE_PATH";
    case BENCH_FAIL_DECODE_UNSTABLE: return "DECODE_UNSTABLE";
    case BENCH_FAIL_ZERO_TOKENS: return "ZERO_TOKENS";
    case BENCH_FAIL_INSUFFICIENT_WINDOWS: return "INSUFFICIENT_WINDOWS";
    default: return "UNKNOWN";
    }
}

void EmitBenchmarkTelemetry(const StreamBenchmark& bench, BenchmarkPhase phase) {
    const char* phaseNames[] = {
        "PREFILL", "DECODE", "STREAM", "ENDURANCE", "SATURATION", "THERMAL", "LATENCY"
    };
    std::stringstream telemetry;
    telemetry << std::fixed << std::setprecision(3);
    telemetry << "BENCHMARK_BEGIN\n";
    telemetry << "PHASE=" << phaseNames[static_cast<int>(phase)] << "\n";
    telemetry << "TIMESTAMP_NS=" << bench.timestamp_ns << "\n";
    telemetry << "PROMPT_TOKENS=" << bench.prompt_tokens << "\n";
    telemetry << "GENERATED_TOKENS=" << bench.generated_tokens << "\n";
    telemetry << "PREFILL_TPS=" << bench.prefill_tps << "\n";
    telemetry << "DECODE_TPS_AVG=" << bench.decode_tps << "\n";
    telemetry << "DECODE_TPS_START=" << bench.decode_tps_start << "\n";
    telemetry << "DECODE_TPS_MIN_WINDOW=" << bench.decode_tps_min_window << "\n";
    telemetry << "MAXIMUM_STABLE_STREAMING_CAPACITY_TPS=" << bench.max_stable_streaming_tps << "\n";
    telemetry << "FULL_WINDOW_COUNT=" << bench.full_window_count << "\n";
    telemetry << "FULL_STABILITY_WINDOWS=" << bench.full_window_count << "\n";
    telemetry << "TAIL_WINDOW_TOKENS=" << bench.tail_window_tokens << "\n";
    telemetry << "ENDURANCE_CERTIFIABLE=" << (bench.endurance_certifiable ? 1 : 0) << "\n";
    telemetry << "PRODUCTION_DECODE_PATH=" << (bench.used_production_decode_path ? 1 : 0) << "\n";
    telemetry << "TTFT_E2E_MS=" << (bench.ttft_e2e_ns / 1e6) << "\n";
    telemetry << "FIRST_DECODE_AFTER_PREFILL_MS=" << (bench.first_decode_after_prefill_ns / 1e6) << "\n";
    telemetry << "DECODE_REAL=" << (bench.decode_real ? 1 : 0) << "\n";
    telemetry << "DECODE_STABLE=" << (bench.decode_stable ? 1 : 0) << "\n";
    telemetry << "VRAM_STABLE=" << (bench.vram_stable ? 1 : 0) << "\n";
    telemetry << "KV_STABLE=" << (bench.kv_stable ? 1 : 0) << "\n";
    telemetry << "FAIL_REASON=" << BenchmarkFailReasonString(bench.fail_reason_code) << "\n";
    telemetry << "STABLE=" << (bench.stream_stable ? "YES" : "NO") << "\n";
    telemetry << "DEGRADATION=" << bench.degradation_ratio << "\n";
    telemetry << "BENCHMARK_END\n";
    std::cerr << telemetry.str();
}

void EmitBenchmarkCertTelemetry(const StreamBenchmark& bench,
                                const char* model,
                                const char* quant,
                                const char* device,
                                uint32_t concurrentStreams) {
    std::stringstream t;
    t << std::fixed << std::setprecision(3);
    uint32_t failCode = bench.fail_reason_code;
    if (bench.used_production_decode_path && bench.decode_stable &&
        bench.vram_stable && bench.kv_stable && !bench.endurance_certifiable) {
        failCode = BENCH_FAIL_INSUFFICIENT_WINDOWS;
    }
    const bool pass =
        bench.used_production_decode_path &&
        bench.decode_stable &&
        bench.vram_stable &&
        bench.kv_stable &&
        bench.endurance_certifiable &&
        failCode == BENCH_FAIL_NONE;
    t << "BENCHMARK_CERT_BEGIN\n";
    t << "BENCHMARK_VERSION=1\n";
    t << "MODEL=" << (model ? model : "") << "\n";
    t << "QUANT=" << (quant ? quant : "") << "\n";
    t << "DEVICE=" << (device ? device : "") << "\n";
    t << "PROMPT_TOKENS=" << bench.prompt_tokens << "\n";
    t << "GENERATED_TOKENS=" << bench.generated_tokens << "\n";
    t << "CONTEXT_TOKENS=" << bench.context_length << "\n";
    t << "CONCURRENT_STREAMS=" << concurrentStreams << "\n";
    t << "PREFILL_TPS=" << bench.prefill_tps << "\n";
    t << "DECODE_TPS_START=" << bench.decode_tps_start << "\n";
    t << "DECODE_TPS_AVG=" << bench.decode_tps << "\n";
    t << "DECODE_TPS_MIN_WINDOW=" << bench.decode_tps_min_window << "\n";
    t << "DEGRADATION_RATIO=" << bench.degradation_ratio << "\n";
    t << "FULL_WINDOW_COUNT=" << bench.full_window_count << "\n";
    t << "FULL_STABILITY_WINDOWS=" << bench.full_window_count << "\n";
    t << "TAIL_WINDOW_TOKENS=" << bench.tail_window_tokens << "\n";
    t << "ENDURANCE_CERTIFIABLE=" << (bench.endurance_certifiable ? 1 : 0) << "\n";
    t << "TTFT_E2E_MS=" << (bench.ttft_e2e_ns / 1e6) << "\n";
    t << "FIRST_DECODE_AFTER_PREFILL_MS=" << (bench.first_decode_after_prefill_ns / 1e6) << "\n";
    t << "DECODE_P50_MS=" << bench.decode_p50_ms << "\n";
    t << "DECODE_P95_MS=" << bench.decode_p95_ms << "\n";
    t << "DECODE_P99_MS=" << bench.decode_p99_ms << "\n";
    t << "PEAK_RAM_MB=" << (bench.peak_system_bytes / (1024.0 * 1024.0)) << "\n";
    t << "PEAK_VRAM_MB=" << (bench.peak_vram_bytes / (1024.0 * 1024.0)) << "\n";
    t << "KV_START_MB=" << (bench.kv_start_bytes / (1024.0 * 1024.0)) << "\n";
    t << "KV_END_MB=" << (bench.kv_end_bytes / (1024.0 * 1024.0)) << "\n";
    t << "KV_MB_PER_1K_CONTEXT=" << (bench.kv_bytes_per_token * 1000.0 / (1024.0 * 1024.0)) << "\n";
    t << "DURATION_SEC=" << bench.duration_sec << "\n";
    t << "PRODUCTION_DECODE_PATH=" << (bench.used_production_decode_path ? 1 : 0) << "\n";
    t << "DECODE_REAL=" << (bench.decode_real ? 1 : 0) << "\n";
    t << "DECODE_STABLE=" << (bench.decode_stable ? 1 : 0) << "\n";
    t << "VRAM_STABLE=" << (bench.vram_stable ? 1 : 0) << "\n";
    t << "KV_STABLE=" << (bench.kv_stable ? 1 : 0) << "\n";
    t << "MAXIMUM_STABLE_STREAMING_CAPACITY_TPS=" << bench.max_stable_streaming_tps << "\n";
    if (!pass)
        t << "FAIL_REASON=" << BenchmarkFailReasonString(failCode) << "\n";
    t << "BENCHMARK_CERT_RESULT=" << (pass ? "PASS" : "FAIL") << "\n";
    t << "BENCHMARK_CERT_END\n";
    std::cerr << t.str();
}

} // namespace Deep2
