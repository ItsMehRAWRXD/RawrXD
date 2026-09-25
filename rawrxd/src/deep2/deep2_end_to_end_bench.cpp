// ============================================================================
// deep2_end_to_end_bench.cpp
// DEEP2_E2E_STREAMING_BENCHMARK_001 — End-to-end streaming benchmark
// Non-blocking, event-driven, time-agnostic streaming generation.
// Integrates TimeReverseDigest, VramStreamingController, Beaconism.
// Never freezes regardless of materialization timing.
// ============================================================================

#include "Deep2Engine.h"
#include "TimeReverseDigest.hpp"
#include "Beaconism.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <string>
#include <vector>
#include <cmath>

namespace {

struct BenchConfig {
    std::string modelPath;
    std::string prompt;
    bool vulkan = false;
    bool strictVulkan = false;
    uint32_t maxTokens = 512;
    uint32_t streamTokens = 0;   // 0 = same as maxTokens
    bool useTimeReverse = true;
    bool useVramStreaming = true;
    uint32_t vramCeilingGiB = 24;
    uint64_t horizonNs = 5'000'000; // 5 ms
    std::string format = "text";
};

struct TokenReceipt {
    uint64_t tokenIndex = 0;
    double elapsedMs = 0.0;
    bool gpuCommitted = false;
    bool residentForward = false;
    uint64_t bytesMoved = 0;
    int64_t slackNs = 0;
};

static void printUsage(const char* exe) {
    std::fprintf(stderr,
        "Usage: %s [options] <model.gguf> <prompt>\n"
        "Options:\n"
        "  --vulkan                Enable Vulkan GPU acceleration\n"
        "  --strict-vulkan         Require GPU; fail if not initialized\n"
        "  --max-tokens <n>        Max tokens to generate (default: 512)\n"
        "  --stream-tokens <n>      Tokens to stream before early stop (0=unlimited)\n"
        "  --no-time-reverse       Disable TimeReverseDigest scheduling\n"
        "  --no-vram-stream        Disable VRAM streaming controller\n"
        "  --vram-ceiling <gi>     VRAM ceiling in GiB (default: 24)\n"
        "  --horizon <ms>          Materialization horizon in ms (default: 5)\n"
        "  --format <fmt>          Output: text | json | receipt (default: text)\n"
        "\nAuthority: Deep2Engine -> generateStream -> TimeReverseDigest -> TPS\n",
        exe);
}

static BenchConfig parseArgs(int argc, char** argv) {
    BenchConfig cfg{};
    int i = 1;
    for (; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--vulkan" || arg == "-vulkan") {
            cfg.vulkan = true;
        } else if (arg == "--strict-vulkan" || arg == "-strict-vulkan") {
            cfg.strictVulkan = true;
            cfg.vulkan = true;
        } else if (arg == "--max-tokens" || arg == "-max-tokens") {
            if (i + 1 < argc) cfg.maxTokens = static_cast<uint32_t>(std::atoi(argv[++i]));
        } else if (arg == "--stream-tokens" || arg == "-stream-tokens") {
            if (i + 1 < argc) cfg.streamTokens = static_cast<uint32_t>(std::atoi(argv[++i]));
        } else if (arg == "--no-time-reverse") {
            cfg.useTimeReverse = false;
        } else if (arg == "--no-vram-stream") {
            cfg.useVramStreaming = false;
        } else if (arg == "--vram-ceiling" || arg == "-vram-ceiling") {
            if (i + 1 < argc) cfg.vramCeilingGiB = static_cast<uint32_t>(std::atoi(argv[++i]));
        } else if (arg == "--horizon" || arg == "-horizon") {
            if (i + 1 < argc) cfg.horizonNs = static_cast<uint64_t>(std::atof(argv[++i]) * 1e6);
        } else if (arg == "--format" || arg == "-format") {
            if (i + 1 < argc) cfg.format = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            std::exit(0);
        } else if (arg[0] == '-') {
            std::fprintf(stderr, "Unknown option: %s\n", arg.c_str());
            std::exit(1);
        } else {
            break;
        }
    }
    if (i >= argc) { std::fprintf(stderr, "ERROR: no model specified\n"); printUsage(argv[0]); std::exit(1); }
    cfg.modelPath = argv[i++];
    if (i >= argc) { std::fprintf(stderr, "ERROR: no prompt specified\n"); printUsage(argv[0]); std::exit(1); }
    for (; i < argc; ++i) {
        if (!cfg.prompt.empty()) cfg.prompt += ' ';
        cfg.prompt += argv[i];
    }
    if (cfg.streamTokens == 0) cfg.streamTokens = cfg.maxTokens;
    return cfg;
}

} // anonymous namespace

int main(int argc, char** argv) {
    const BenchConfig cfg = parseArgs(argc, argv);

    // -------------------------------------------------------------------------
    // Authority receipt header
    // -------------------------------------------------------------------------
    std::fprintf(stderr,
        "========================================\n"
        "  DEEP2_E2E_STREAMING_BENCHMARK_001\n"
        "========================================\n"
        "ENGINE=Deep2Engine\n"
        "VULKAN_REQUESTED=%d\n"
        "STRICT_VULKAN=%d\n"
        "TIME_REVERSE=%d\n"
        "VRAM_STREAM=%d\n"
        "VRAM_CEILING_GIB=%u\n"
        "HORIZON_MS=%.3f\n",
        cfg.vulkan ? 1 : 0,
        cfg.strictVulkan ? 1 : 0,
        cfg.useTimeReverse ? 1 : 0,
        cfg.useVramStreaming ? 1 : 0,
        cfg.vramCeilingGiB,
        cfg.horizonNs / 1e6);

    // -------------------------------------------------------------------------
    // Beaconism init
    // -------------------------------------------------------------------------
    if (Deep2::BeaconismAuthority::enabledGlobally()) {
        Deep2::BeaconismAuthority::Instance().open("bench_beacons.csv", "bench_beacons.jsonl");
    }
    auto& beacon = Deep2::BeaconismAuthority::Instance();
    uint64_t benchSeq = beacon.nextSeq();
    beacon.emit(Deep2::BeaconEvent::TOKEN_BEGIN, benchSeq, "PASS", "benchmark_start");

    // -------------------------------------------------------------------------
    // Engine init
    // -------------------------------------------------------------------------
    Deep2::Deep2Engine engine;
    Deep2::EngineConfig ecfg{};
    ecfg.maxSeqLen = 4096;
    ecfg.useKVCache = true;
    ecfg.useThreadPool = true;
    ecfg.numThreads = 0;

    const auto tInit0 = std::chrono::steady_clock::now();
    if (!engine.initialize(ecfg)) {
        beacon.emit(Deep2::BeaconEvent::TOOL_CALL_FAIL, benchSeq, "FAIL", "engine_initialize");
        std::fprintf(stderr, "FAIL=initialize\n");
        return 1;
    }
    const double initMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - tInit0).count();
    std::fprintf(stderr, "ENGINE_INIT=PASS %.1f ms\n", initMs);

    // -------------------------------------------------------------------------
    // Vulkan
    // -------------------------------------------------------------------------
    if (cfg.vulkan) {
        engine.enableVulkan(true);
        engine.setVulkanStrictNoCpuFallback(cfg.strictVulkan);
        std::fprintf(stderr, "VULKAN_ENABLED=1\n");
    } else {
        std::fprintf(stderr, "VULKAN_ENABLED=0\n");
    }
    if (cfg.strictVulkan) {
        if (!engine.isVulkanInitialized()) {
            std::fprintf(stderr,
                "STRICT_GPU_VIOLATION enabled=%d initialized=%d\n",
                engine.isVulkanEnabled() ? 1 : 0,
                engine.isVulkanInitialized() ? 1 : 0);
            return 1;
        }
        std::fprintf(stderr, "STRICT_VULKAN_PASS=1\n");
    }

    // -------------------------------------------------------------------------
    // VRAM streaming controller
    // -------------------------------------------------------------------------
    if (cfg.useVramStreaming) {
        engine.enableVramStreaming(true);
        if (auto* vsc = engine.getVramStreamingController()) {
            vsc->setVramCeilingGiB(cfg.vramCeilingGiB);
            vsc->setHostSpillEnabled(true);
            vsc->setSpillTier(Deep2::SpillTier::HostRAM);
            vsc->setTokenBytesLimit(512 * 1024 * 1024); // 512 MiB/token
            std::fprintf(stderr, "VRAM_STREAM_INIT=PASS ceiling=%uGiB\n", cfg.vramCeilingGiB);
        }
    }

    // -------------------------------------------------------------------------
    // TimeReverseDigest init
    // -------------------------------------------------------------------------
    std::unique_ptr<Deep2::TimeReverseDigest> trd;
    if (cfg.useTimeReverse) {
        trd = std::make_unique<Deep2::TimeReverseDigest>();
        trd->setHorizonNs(cfg.horizonNs);
        std::fprintf(stderr, "TIME_REVERSE_INIT=PASS\n");
    }

    // -------------------------------------------------------------------------
    // Model load
    // -------------------------------------------------------------------------
    std::fprintf(stderr, "MODEL_LOAD: loading %s ...\n", cfg.modelPath.c_str());
    const auto tLoad0 = std::chrono::steady_clock::now();
    Deep2::ModelLoadDiag diag{};
    if (!engine.loadModel(cfg.modelPath, &diag)) {
        beacon.emit(Deep2::BeaconEvent::TOOL_CALL_FAIL, benchSeq, "FAIL", "loadModel");
        std::fprintf(stderr, "FAIL=loadModel stage=%s msg=%s\n",
            diag.stageName.c_str(), diag.message.c_str());
        return 1;
    }
    const double loadMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - tLoad0).count();
    std::fprintf(stderr, "MODEL_LOAD=PASS %.0f ms\n", loadMs);

    const Deep2::EngineConfig& loadedCfg = engine.getConfig();
    std::fprintf(stderr,
        "MODEL_ARCH=%s\n"
        "MODEL_LAYERS=%zu\n"
        "MODEL_HIDDEN=%zu\n"
        "MODEL_HEADS=%zu\n"
        "MODEL_KV_HEADS=%zu\n",
        engine.modelArchitecture().empty() ? "unknown" : engine.modelArchitecture().c_str(),
        loadedCfg.numLayers,
        loadedCfg.hiddenDim,
        loadedCfg.numHeads,
        loadedCfg.numKVHeads);

    // -------------------------------------------------------------------------
    // Generation
    // -------------------------------------------------------------------------
    Deep2::GenerationOptions opts{};
    opts.maxTokens = cfg.maxTokens;
    opts.temperature = 0.0f;
    opts.topK = 1;

    std::vector<TokenReceipt> tokenReceipts;
    tokenReceipts.reserve(cfg.maxTokens);
    uint64_t tokenCount = 0;
    uint64_t promptTokens = 0;
    const auto tGen0 = std::chrono::steady_clock::now();

    Deep2::GenerationResult result = engine.generateStream(
        cfg.prompt.c_str(), opts,
        [&](int32_t /*tokenId*/, const std::string& piece) -> bool {
            const auto now = std::chrono::steady_clock::now();
            const double elapsedMs = std::chrono::duration<double, std::milli>(now - tGen0).count();

            if (tokenCount == 0) {
                // First callback = end of prefill
                promptTokens = result.promptTokens;
                beacon.emit(Deep2::BeaconEvent::TOKEN_END, benchSeq, "PASS",
                            "prefill_complete", 0,
                            static_cast<uint64_t>(elapsedMs * 1e6));
            }

            if (cfg.format == "text") {
                std::fputs(piece.c_str(), stdout);
                std::fflush(stdout);
            }

            TokenReceipt rec{};
            rec.tokenIndex = tokenCount;
            rec.elapsedMs = elapsedMs;
            rec.gpuCommitted = engine.isRealGpuForward();
            rec.residentForward = engine.gpuForwardCounters().liveDecodeResidentTokens > 0;

            // Per-token VRAM measurement
            if (cfg.useVramStreaming) {
                if (auto* vsc = engine.getVramStreamingController()) {
                    uint64_t bytesMoved = 0;
                    vsc->endTokenMeasurement(bytesMoved);
                    rec.bytesMoved = bytesMoved;
                }
            }

            // Per-token TimeReverseDigest slack
            if (trd) {
                auto slacks = trd->computeSlack(
                    static_cast<uint64_t>(elapsedMs * 1e6));
                if (!slacks.empty()) {
                    rec.slackNs = slacks[0].slackNs;
                }
                trd->beginToken(tokenCount);
            }

            tokenReceipts.push_back(rec);

            // Beacon per token (throttled to every 10 tokens to avoid flooding)
            if ((tokenCount % 10) == 0) {
                beacon.emit(Deep2::BeaconEvent::TOKEN_LAYER_END, benchSeq, "PASS",
                            "decode_token", 0,
                            static_cast<uint64_t>(elapsedMs * 1e6));
            }

            ++tokenCount;

            // Early-stop if stream token limit reached (non-blocking)
            if (cfg.streamTokens > 0 && tokenCount >= cfg.streamTokens) {
                return false; // signals cancellation to generateStream
            }
            return true;
        });

    const auto tGen1 = std::chrono::steady_clock::now();
    const double genMs = std::chrono::duration<double, std::milli>(tGen1 - tGen0).count();

    if (cfg.format == "text") {
        std::fputc('\n', stdout);
    }

    // -------------------------------------------------------------------------
    // Receipt
    // -------------------------------------------------------------------------
    const double prefillMs = tokenReceipts.empty() ? 0.0 : tokenReceipts[0].elapsedMs;
    const double decodeMs = genMs - prefillMs;
    const uint64_t decodeTokens = tokenCount > 0 ? tokenCount - 1 : 0; // token 0 = prefill end
    const double decodeTps = decodeMs > 0.0 ? (decodeTokens / (decodeMs / 1000.0)) : 0.0;
    const double overallTps = genMs > 0.0 ? (tokenCount / (genMs / 1000.0)) : 0.0;

    uint64_t totalBytesMoved = 0;
    uint64_t gpuCommittedTokens = 0;
    uint64_t residentTokens = 0;
    int64_t minSlackNs = INT64_MAX;
    int64_t maxSlackNs = INT64_MIN;
    for (const auto& r : tokenReceipts) {
        totalBytesMoved += r.bytesMoved;
        if (r.gpuCommitted) ++gpuCommittedTokens;
        if (r.residentForward) ++residentTokens;
        if (r.slackNs < minSlackNs) minSlackNs = r.slackNs;
        if (r.slackNs > maxSlackNs) maxSlackNs = r.slackNs;
    }

    std::fprintf(stderr,
        "\n========================================\n"
        "  RECEIPT\n"
        "========================================\n"
        "GATE=DEEP2_E2E_STREAMING_BENCHMARK_001\n"
        "ENGINE=Deep2Engine\n"
        "EXECUTION_BACKEND=%s\n"
        "VULKAN_REQUESTED=%d\n"
        "VULKAN_INITIALIZED=%d\n"
        "GPU_FORWARD=%d\n"
        "CPU_FORWARD=%d\n"
        "MODEL=%s\n"
        "PROMPT_TOKENS=%llu\n"
        "GENERATED_TOKENS=%llu\n"
        "PREFILL_MS=%.1f\n"
        "DECODE_MS=%.1f\n"
        "OVERALL_TPS=%.3f\n"
        "DECODE_TPS=%.3f\n"
        "GPU_COMMITTED_TOKENS=%llu\n"
        "RESIDENT_TOKENS=%llu\n"
        "TOTAL_BYTES_MOVED=%llu\n"
        "AVG_BYTES_PER_TOKEN=%.0f\n"
        "MIN_SLACK_NS=%lld\n"
        "MAX_SLACK_NS=%lld\n"
        "VERDICT=%s\n",
        (cfg.vulkan && engine.isVulkanInitialized()) ? "GPU" : "CPU",
        cfg.vulkan ? 1 : 0,
        engine.isVulkanInitialized() ? 1 : 0,
        (cfg.vulkan && engine.isVulkanInitialized()) ? 1 : 0,
        (cfg.vulkan && engine.isVulkanInitialized()) ? 0 : 1,
        cfg.modelPath.c_str(),
        static_cast<unsigned long long>(promptTokens),
        static_cast<unsigned long long>(tokenCount),
        prefillMs,
        decodeMs,
        overallTps,
        decodeTps,
        static_cast<unsigned long long>(gpuCommittedTokens),
        static_cast<unsigned long long>(residentTokens),
        static_cast<unsigned long long>(totalBytesMoved),
        tokenCount > 0 ? static_cast<double>(totalBytesMoved) / tokenCount : 0.0,
        static_cast<long long>(minSlackNs),
        static_cast<long long>(maxSlackNs),
        (tokenCount > 0) ? "PASS" : "FAIL");

    if (trd) {
        std::fprintf(stderr, "TIME_REVERSE_DIGEST=%s\n", trd->summary().c_str());
    }

    if (cfg.useVramStreaming) {
        auto stats = engine.getVramStreamingStats();
        std::fprintf(stderr,
            "VRAM_CEILING_BYTES=%llu\n"
            "VRAM_PEAK_BYTES=%llu\n"
            "HOST_RAM_USED_BYTES=%llu\n"
            "VRAM_STREAM_TOKENS_MEASURED=%llu\n",
            static_cast<unsigned long long>(stats.vramCeilingBytes),
            static_cast<unsigned long long>(stats.vramPeakBytes),
            static_cast<unsigned long long>(stats.hostRamUsedBytes),
            static_cast<unsigned long long>(stats.tokensMeasured));
    }

    // Final beacon
    beacon.emit(Deep2::BeaconEvent::TOKEN_END, benchSeq, "PASS",
                "benchmark_complete", 0,
                static_cast<uint64_t>(genMs * 1e6));

    return (tokenCount > 0) ? 0 : 1;
}

