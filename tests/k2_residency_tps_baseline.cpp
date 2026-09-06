// ============================================================================
// k2_residency_tps_baseline.cpp — K2-001 measurement harness
// Captures host RAM peak, GPU VRAM capacity, and wall-clock TPS baseline.
// Skips gracefully if K2 shards are absent; does not require model weights.
// ============================================================================
#include "../src/deep2/KimiK2Config.hpp"
#include "../src/deep2/K2GlobalTensorIndex.hpp"
#include "../src/deep2/K2MLAWeights.hpp"
#include "../src/deep2/K2MoEWeights.hpp"
#include "../src/deep2/GGUFLoader.hpp"
#include "../src/deep2/K2NativeStreamGate.hpp"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#include <dxgi1_6.h>
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "psapi.lib")
#endif

namespace fs = std::filesystem;

struct K2BaselineReport {
    uint64_t wallUs = 0;
    uint64_t hostRamPeakBytes = 0;
    uint64_t gpu0DedicatedBytes = 0;
    uint64_t gpu0SharedBytes = 0;
    uint64_t gpu1DedicatedBytes = 0;
    uint64_t gpu1SharedBytes = 0;
    uint32_t shardsDiscovered = 0;
    uint32_t layerDepth = 0;
    uint32_t streamTokens = 0;
    double tokensPerSecond = 0.0;
    double msPerToken = 0.0;
    bool ok = false;
    std::string error;
};

static uint64_t QpcNow() {
#ifdef _WIN32
    LARGE_INTEGER t{};
    QueryPerformanceCounter(&t);
    return static_cast<uint64_t>(t.QuadPart);
#else
    return 0;
#endif
}

static uint64_t QpcFreq() {
#ifdef _WIN32
    LARGE_INTEGER f{};
    QueryPerformanceFrequency(&f);
    return static_cast<uint64_t>(f.QuadPart);
#else
    return 1;
#endif
}

static uint64_t ElapsedUs(uint64_t t0, uint64_t t1, uint64_t freq) {
    if (freq == 0) return 0;
    return static_cast<uint64_t>((t1 - t0) * 1000000ULL / freq);
}

static uint64_t SampleProcessPeakWorkingSet() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(GetCurrentProcess(),
                             reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
                             sizeof(pmc))) {
        return pmc.PeakWorkingSetSize;
    }
#endif
    return 0;
}

static void QueryGpuVram(K2BaselineReport& r) {
#ifdef _WIN32
    IDXGIFactory6* factory = nullptr;
    if (FAILED(CreateDXGIFactory1(__uuidof(IDXGIFactory6), reinterpret_cast<void**>(&factory))))
        return;

    UINT i = 0;
    IDXGIAdapter4* adapter = nullptr;
    while (factory->EnumAdapterByGpuPreference(i, DXGI_GPU_PREFERENCE_HIGH_PERFORMANCE,
                                               __uuidof(IDXGIAdapter4),
                                               reinterpret_cast<void**>(&adapter)) == S_OK) {
        DXGI_ADAPTER_DESC3 desc{};
        if (SUCCEEDED(adapter->GetDesc3(&desc)) && !(desc.Flags & DXGI_ADAPTER_FLAG3_SOFTWARE)) {
            if (i == 0) {
                r.gpu0DedicatedBytes = desc.DedicatedVideoMemory;
                r.gpu0SharedBytes = desc.SharedSystemMemory;
            } else if (i == 1) {
                r.gpu1DedicatedBytes = desc.DedicatedVideoMemory;
                r.gpu1SharedBytes = desc.SharedSystemMemory;
            }
        }
        adapter->Release();
        ++i;
        if (i >= 2) break;
    }
    factory->Release();
#else
    (void)r;
#endif
}

static bool DiscoverK2Shards(const fs::path& dir, std::vector<fs::path>& shards) {
    for (int i = 1; i <= 13; ++i) {
        char name[256];
        std::snprintf(name, sizeof(name),
                      "Kimi-K2-Instruct-0905-Q4_K_M-%05d-of-00013.gguf", i);
        fs::path candidate = dir / name;
        if (fs::exists(candidate)) {
            shards.push_back(candidate);
            continue;
        }
        std::snprintf(name, sizeof(name),
                      "kimi-k2-instruct-0905-q4_k_m-%05d-of-00013.gguf", i);
        candidate = dir / name;
        if (fs::exists(candidate)) shards.push_back(candidate);
    }
    return !shards.empty();
}

static K2BaselineReport MeasureK2Baseline(const fs::path& shardDir, uint32_t streamTokens,
                                          uint32_t layerDepth, uint64_t budgetBytes) {
    K2BaselineReport report;
    QueryGpuVram(report);

    std::vector<fs::path> shards;
    if (!DiscoverK2Shards(shardDir, shards)) {
        report.error = "No K2 shards discovered; baseline requires Kimi-K2 shards in " + shardDir.string();
        return report;
    }
    report.shardsDiscovered = static_cast<uint32_t>(shards.size());

    Deep2::KimiK2Config k2cfg;
    k2cfg.family = Deep2::ArchitectureFamily::KimiK2;
    k2cfg.modelType = "kimi_k2";
    k2cfg.architecture = "kimi_k2";
    k2cfg.version = 905;
    k2cfg.hiddenDim = 7168;
    k2cfg.numLayers = 61;
    k2cfg.numHeads = 64;
    k2cfg.numKVHeads = 1;
    k2cfg.qLoraRank = 1536;
    k2cfg.kvLoraRank = 512;
    k2cfg.qkNopeHeadDim = 128;
    k2cfg.qkRopeHeadDim = 64;
    k2cfg.vHeadDim = 128;
    k2cfg.numExperts = 384;
    k2cfg.expertsPerToken = 8;
    k2cfg.sharedExperts = 1;
    k2cfg.moeIntermediateSize = 2048;
    k2cfg.vocabSize = 163840;
    k2cfg.maxPosition = 262144;
    k2cfg.routedScalingFactor = 2.827f;

    Deep2::GlobalTensorIndex index;
    std::string indexError;
    if (!index.BuildFromShardDirectory(shardDir, k2cfg, indexError)) {
        report.error = "Tensor index build failed: " + indexError;
        return report;
    }

    K2NativeStreamGate::Config cfg;
    cfg.prompt = "hello";
    cfg.streamTokens = streamTokens;
    cfg.layerDepth = layerDepth;
    cfg.budgetBytes = budgetBytes;
    cfg.enableMlaComplete = false;

    const uint64_t t0 = QpcNow();
    const auto result = K2NativeStreamGate::Run(shardDir, index, k2cfg, shards, cfg);
    const uint64_t t1 = QpcNow();

    report.wallUs = ElapsedUs(t0, t1, QpcFreq());
    report.hostRamPeakBytes = result.peakResidencyBytes;
    report.layerDepth = result.layerDepth;
    report.streamTokens = streamTokens;
    if (streamTokens > 0 && report.wallUs > 0) {
        report.msPerToken = static_cast<double>(report.wallUs) / 1000.0 / static_cast<double>(streamTokens);
        report.tokensPerSecond = 1.0e6 / (static_cast<double>(report.wallUs) / static_cast<double>(streamTokens));
    }
    report.ok = result.ok;
    if (!result.ok) report.error = result.error;

    // Update host RAM peak with OS process peak if larger than gate's tracked peak.
    const uint64_t osPeak = SampleProcessPeakWorkingSet();
    if (osPeak > report.hostRamPeakBytes) report.hostRamPeakBytes = osPeak;

    return report;
}

static void PrintReport(const K2BaselineReport& r) {
    std::printf("\n╔════════════════════════════════════════════════════════════╗\n");
    std::printf("║  K2-001 Residency / TPS Baseline                           ║\n");
    std::printf("╠════════════════════════════════════════════════════════════╣\n");
    std::printf("  OK                     = %s\n", r.ok ? "YES" : "NO");
    std::printf("  SHARDS_DISCOVERED      = %u\n", r.shardsDiscovered);
    std::printf("  LAYER_DEPTH            = %u\n", r.layerDepth);
    std::printf("  STREAM_TOKENS          = %u\n", r.streamTokens);
    std::printf("  WALL_TIME_US           = %llu\n", static_cast<unsigned long long>(r.wallUs));
    std::printf("  TOKENS_PER_SECOND      = %.2f\n", r.tokensPerSecond);
    std::printf("  MS_PER_TOKEN           = %.2f\n", r.msPerToken);
    std::printf("  HOST_RAM_PEAK_MIB      = %.1f\n", r.hostRamPeakBytes / (1024.0 * 1024.0));
    std::printf("  GPU0_DEDICATED_MIB     = %.0f\n", r.gpu0DedicatedBytes / (1024.0 * 1024.0));
    std::printf("  GPU0_SHARED_MIB        = %.0f\n", r.gpu0SharedBytes / (1024.0 * 1024.0));
    std::printf("  GPU1_DEDICATED_MIB     = %.0f\n", r.gpu1DedicatedBytes / (1024.0 * 1024.0));
    std::printf("  GPU1_SHARED_MIB        = %.0f\n", r.gpu1SharedBytes / (1024.0 * 1024.0));
    if (!r.error.empty())
        std::printf("  ERROR                  = %s\n", r.error.c_str());
    std::printf("╚════════════════════════════════════════════════════════════╝\n");
}

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("K2-001 Residency / TPS Baseline\n");

    fs::path shardDir = fs::current_path();
    uint32_t streamTokens = 1;
    uint32_t layerDepth = 4;
    uint64_t budgetBytes = 256ULL * 1024 * 1024;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--tokens" && i + 1 < argc) streamTokens = static_cast<uint32_t>(std::atoi(argv[++i]));
        else if (arg == "--layers" && i + 1 < argc) layerDepth = static_cast<uint32_t>(std::atoi(argv[++i]));
        else if (arg == "--budget" && i + 1 < argc) budgetBytes = static_cast<uint64_t>(std::strtoull(argv[++i], nullptr, 10));
        else if (!arg.empty() && arg[0] != '-') shardDir = arg;
    }

    const auto report = MeasureK2Baseline(shardDir, streamTokens, layerDepth, budgetBytes);
    PrintReport(report);
    return report.ok ? 0 : (report.shardsDiscovered == 0 ? 0 : 1);
}
