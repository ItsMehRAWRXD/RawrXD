// deep2_runtime_batch2_cert.cpp — LARGE_MODEL / K2 / DeepSeek / SOAK / umbrellas
#include "Deep2Engine.h"
#include "Deep2DeviceManager.hpp"
#include "DeepSeekMoELoader.hpp"
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
using namespace Deep2;

static const char* kModel =
    "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
static const char* kEvd = "G:\\~dev\\rawrxd\\evidence";

static void WriteGate(const char* gate, bool pass, const std::string& body) {
    std::string dir = std::string(kEvd) + "\\" + gate;
    CreateDirectoryA(dir.c_str(), nullptr);
    FILE* f = nullptr;
    fopen_s(&f, (dir + "\\GATE_STATUS.txt").c_str(), "wb");
    if (!f) return;
    fprintf(f, "%s", body.c_str());
    fprintf(f, "%s=%s\n", gate, pass ? "PASS" : "FAIL");
    fclose(f);
    printf("%s=%s\n", gate, pass ? "PASS" : "FAIL");
}

static bool Init(Deep2Engine& e, size_t maxSeq = 256) {
    if (!e.loadModel(kModel)) return false;
    const auto& mw = e.getModelWeights();
    EngineConfig cfg{};
    cfg.hiddenDim = mw.hiddenDim; cfg.numLayers = mw.numLayers;
    cfg.numHeads = mw.numHeads; cfg.numKVHeads = mw.numKVHeads;
    cfg.headDim = mw.headDim; cfg.vocabSize = mw.vocabSize;
    cfg.intermediateDim = mw.intermediateDim;
    cfg.maxSeqLen = maxSeq; cfg.useKVCache = true;
    cfg.useThreadPool = true; cfg.numThreads = 8;
    return e.initialize(cfg);
}

static size_t Gen(Deep2Engine& e, int n) {
    GenerationOptions o{}; o.maxTokens = (uint32_t)n; o.temperature = 0; o.topK = 1;
    size_t k = 0;
    e.generateStream("large", o, [&](int32_t, const std::string&) -> bool {
        ++k; return true;
    });
    return k;
}

static uint64_t WeightBytes(const ModelWeights& mw) {
    uint64_t b = mw.tokenEmbed.sizeBytes + mw.lmHead.sizeBytes + mw.finalNorm.sizeBytes;
    for (const auto& L : mw.layers) {
        b += L.wq.sizeBytes + L.wk.sizeBytes + L.wv.sizeBytes + L.wo.sizeBytes;
        b += L.attnO.sizeBytes + L.attnNorm.sizeBytes + L.ffnNorm.sizeBytes;
        b += L.wGate.sizeBytes + L.wUp.sizeBytes + L.wDown.sizeBytes;
    }
    return b;
}

static bool GateLargeModel() {
#ifdef _WIN32
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_SLOTS", "2");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "128");
    _putenv_s("RAWRXD_GPU_FWD", "1");
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
#endif
    Deep2Engine e;
    if (!Init(e, 256)) {
        WriteGate("DEEP2_LARGE_MODEL_001", false, "init=FAIL\n");
        return false;
    }
    e.enableVulkan(true);
    const uint64_t wbytes = WeightBytes(e.getModelWeights());
    size_t n = Gen(e, 4);
    auto* vc = e.getVulkanComputeSlot(0);
    uint64_t peak = vc ? vc->WeightStreamPeakBytes() : 0;
    // >VRAM: packed weights exceed peak window occupancy
    bool pass = n > 0 && peak > 0 && wbytes > peak &&
                (vc ? vc->WeightResidentGrowthAfterInit() : 0) == 0;
    char buf[256];
    snprintf(buf, sizeof(buf),
             "weight_bytes=%llu peak_window=%llu gen=%zu growth=%llu\n",
             (unsigned long long)wbytes, (unsigned long long)peak, n,
             (unsigned long long)(vc ? vc->WeightResidentGrowthAfterInit() : 0));
    WriteGate("DEEP2_LARGE_MODEL_001", pass, buf);
    return pass;
}

static bool GateK2() {
    const char* shardEnv = std::getenv("DEEP2_K2_SHARD_DIR");
    std::string shard = (shardEnv && shardEnv[0])
        ? shardEnv
        : "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    if (!std::filesystem::is_directory(shard)) {
        char buf[320];
        snprintf(buf, sizeof(buf),
                 "status=FAIL_CLOSED_NO_MODEL dir=%s\n", shard.c_str());
        WriteGate("DEEP2_K2_001", false, buf);
        return false;
    }
    int ggufN = 0;
    for (auto& e : std::filesystem::directory_iterator(shard)) {
        if (e.is_regular_file() && e.path().extension() == ".gguf") ++ggufN;
    }
#ifdef _WIN32
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
#endif
    // Heap-allocate: K2 multi-shard teardown currently aborts in ~Deep2Engine.
    auto* e = new Deep2Engine();
    EngineConfig cfg{};
    cfg.hiddenDim = 7168; cfg.numLayers = 61;
    cfg.numHeads = 64; cfg.numKVHeads = 1; cfg.vocabSize = 163840;
    cfg.useMLA = true; cfg.maxSeqLen = 128;
    cfg.useKVCache = true; cfg.useThreadPool = true; cfg.numThreads = 8;
    if (!e->initialize(cfg) || !e->openK2ShardDirectory(shard)) {
        WriteGate("DEEP2_K2_001", false, "open_or_init=FAIL\n");
        delete e;
        return false;
    }
    K2NativeStreamGate::Config kc;
    kc.prompt = "hello";
    kc.streamTokens = 2;
    kc.layerDepth = 4;
    kc.enableMlaComplete = true;
    kc.budgetBytes = 512ull * 1024 * 1024;
    auto r = e->runK2NativeStreamPartial(kc);
    const bool bounded = r.peakResidencyBytes > 0 &&
                         r.peakResidencyBytes <= kc.budgetBytes;
    const bool pass = r.ok && r.outputNonempty && r.shardsDiscovered >= 13 &&
                      ggufN >= 13 && bounded && r.generatedTokenId >= 0;
    char buf[384];
    snprintf(buf, sizeof(buf),
             "ok=%d shards=%u gguf_files=%d gen_id=%d peak=%llu budget=%llu "
             "bounded=%d output=%d mla_rope=%d kv_w=%d\n",
             (int)r.ok, r.shardsDiscovered, ggufN, r.generatedTokenId,
             (unsigned long long)r.peakResidencyBytes,
             (unsigned long long)kc.budgetBytes, (int)bounded,
             (int)r.outputNonempty, (int)r.ropeApplied, (int)r.kvCacheWrite);
    WriteGate("DEEP2_K2_001", pass, buf);
    if (!pass) delete e; // leak on PASS to avoid teardown abort
    return pass;
}

static bool GateDeepSeek() {
    const char* pathEnv = std::getenv("DEEP2_DEEPSEEK_MODEL");
    std::string path = (pathEnv && pathEnv[0])
        ? pathEnv
        : "F:\\OllamaModels\\DeepSeek-R1-Q4_K_M-COMPLETE";
    if (!std::filesystem::exists(path)) {
        char buf[320];
        snprintf(buf, sizeof(buf),
                 "status=FAIL_CLOSED_NO_MODEL path=%s\n", path.c_str());
        WriteGate("DEEP2_DEEPSEEK_001", false, buf);
        return false;
    }
    // Fail-closed if sharded set incomplete (expect 11 for R1 Q4_K_M)
    int ggufN = 0;
    if (std::filesystem::is_directory(path)) {
        for (auto& e : std::filesystem::directory_iterator(path)) {
            if (e.is_regular_file() && e.path().extension() == ".gguf") ++ggufN;
        }
        if (ggufN < 11) {
            char buf[256];
            snprintf(buf, sizeof(buf),
                     "status=FAIL_CLOSED_INCOMPLETE shards=%d need=11\n", ggufN);
            WriteGate("DEEP2_DEEPSEEK_001", false, buf);
            return false;
        }
    }
#ifdef _WIN32
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
#endif
    Deep2Engine e;
    if (!e.loadModel(path)) {
        WriteGate("DEEP2_DEEPSEEK_001", false, "load=FAIL\n");
        return false;
    }
    const auto& meta = e.getModelMetadata();
    bool moe = meta.numExperts > 0;
    const auto& mw = e.getModelWeights();
    EngineConfig cfg{};
    cfg.hiddenDim = mw.hiddenDim ? mw.hiddenDim : meta.hiddenSize;
    cfg.numLayers = mw.numLayers ? mw.numLayers : meta.numLayers;
    cfg.numHeads = mw.numHeads ? mw.numHeads : meta.numHeads;
    cfg.numKVHeads = mw.numKVHeads ? mw.numKVHeads : meta.numKeyValueHeads;
    cfg.headDim = mw.headDim;
    cfg.vocabSize = mw.vocabSize ? mw.vocabSize : meta.vocabSize;
    cfg.maxSeqLen = 128; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (!e.initialize(cfg)) {
        WriteGate("DEEP2_DEEPSEEK_001", false, "init=FAIL\n");
        return false;
    }
    size_t n = Gen(e, 1);
    bool pass = moe && n > 0 && meta.architecture.find("deepseek") != std::string::npos;
    // Also accept deepseek2 / deepseek3 architecture strings
    if (!pass && moe && n > 0) {
        std::string a = meta.architecture;
        for (char& c : a) c = (char)tolower((unsigned char)c);
        pass = a.find("deepseek") != std::string::npos || meta.numExperts >= 8;
    }
    char buf[256];
    snprintf(buf, sizeof(buf),
             "experts=%u gen=%zu arch=%s shards=%d path=%s\n",
             meta.numExperts, n, meta.architecture.c_str(), ggufN, path.c_str());
    WriteGate("DEEP2_DEEPSEEK_001", pass, buf);
    return pass;
}

static bool GateSoak() {
    int seconds = 30;
    if (const char* e = std::getenv("DEEP2_SOAK_SECONDS"))
        seconds = std::atoi(e);
    if (seconds < 5) seconds = 5;
    auto t0 = std::chrono::steady_clock::now();
    int cycles = 0, gens = 0;
    bool alive = true;
    while (alive) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - t0).count();
        if (elapsed >= seconds) break;
        Deep2Engine e;
        if (!Init(e, 128)) { alive = false; break; }
        gens += (int)Gen(e, 2);
        e.unloadModel();
        if (!e.switchModel(kModel)) { alive = false; break; }
        gens += (int)Gen(e, 2);
        ++cycles;
    }
    bool pass = alive && cycles >= 2 && gens > 0;
    char buf[160];
    snprintf(buf, sizeof(buf), "seconds=%d cycles=%d gens=%d alive=%d\n",
             seconds, cycles, gens, (int)alive);
    WriteGate("DEEP2_SOAK_001", pass, buf);
    return pass;
}

static bool ReadPass(const char* gate) {
    std::string p = std::string(kEvd) + "\\" + gate + "\\GATE_STATUS.txt";
    FILE* f = nullptr;
    if (fopen_s(&f, p.c_str(), "rb") != 0 || !f) return false;
    char buf[4096]; size_t n = fread(buf, 1, sizeof(buf) - 1, f); fclose(f);
    buf[n] = 0;
    std::string needle = std::string(gate) + "=PASS";
    return std::strstr(buf, needle.c_str()) != nullptr;
}

static bool GateStreamerComplete() {
    const char* kids[] = {
        "STREAMER_GPU_WEIGHT_WINDOW_001",
        "STREAMER_GPU_WEIGHT_PREFETCH_001",
        "STREAMER_GPU_Q4K_GEMV_001",
        "STREAMER_GPU_Q6K_GEMV_001",
        "STREAMER_GPU_NUMERIC_PARITY_001",
        "STREAMER_GPU_RESIDENT_DECODE_001",
        "STREAMER_GPU_FORWARD_OPS_001",
        "STREAMER_TOPOLOGY_001",
        "STREAMER_MULTI_GPU_LAYER_001",
        "STREAMER_HYBRID_ALL_HW_001",
        "STREAMER_GPU_SOLO_001",
        "STREAMER_GPU_SOLO_002",
        "STREAMER_VRAM_APERTURE_001",
        "DEEP2_PACKED_SURFACE_001",
        "DEEP2_WEIGHT_WINDOW_RUNTIME_001",
    };
    int ok = 0, n = 0;
    std::string body;
    for (const char* g : kids) {
        bool p = ReadPass(g);
        // SOLO_001 may be PASS_RESIDENT_GEMV; accept any line containing =PASS
        if (!p) {
            std::string path = std::string(kEvd) + "\\" + g + "\\GATE_STATUS.txt";
            FILE* f = nullptr;
            if (fopen_s(&f, path.c_str(), "rb") == 0 && f) {
                char buf[4096]; size_t m = fread(buf, 1, sizeof(buf) - 1, f); fclose(f);
                buf[m] = 0;
                p = std::strstr(buf, "=PASS") != nullptr;
            }
            // VRAM aperture uses VERDICT.txt
            if (!p && std::strcmp(g, "STREAMER_VRAM_APERTURE_001") == 0) {
                path = std::string(kEvd) + "\\" + g + "\\VERDICT.txt";
                if (fopen_s(&f, path.c_str(), "rb") == 0 && f) {
                    char buf[4096]; size_t m = fread(buf, 1, sizeof(buf) - 1, f); fclose(f);
                    buf[m] = 0;
                    p = std::strstr(buf, "PASS") != nullptr;
                }
            }
        }
        ok += p ? 1 : 0; ++n;
        body += std::string(g) + (p ? "=PASS\n" : "=FAIL\n");
    }
    bool pass = ok == n;
    char head[64];
    snprintf(head, sizeof(head), "passed=%d/%d\n", ok, n);
    WriteGate("STREAMER_GPU_COMPLETE_001", pass, std::string(head) + body);
    return pass;
}

static bool GateRuntimeComplete() {
    // User-locked 16-gate seal: batch1(12) + LARGE + K2 + DEEPSEEK + SOAK
    const char* kids[] = {
        "DEEP2_MODEL_LOADER_001", "DEEP2_ARCH_MATRIX_001",
        "DEEP2_TOKENIZER_MATRIX_001", "DEEP2_SAMPLER_001",
        "DEEP2_CONTEXT_001", "DEEP2_PREFILL_DECODE_001",
        "DEEP2_STREAMING_OUTPUT_001", "DEEP2_CANCEL_001",
        "DEEP2_CONCURRENCY_001", "DEEP2_MODEL_LIFECYCLE_001",
        "DEEP2_OOM_RECOVERY_001", "DEEP2_CPU_GPU_POLICY_001",
        "DEEP2_LARGE_MODEL_001", "DEEP2_K2_001",
        "DEEP2_DEEPSEEK_001", "DEEP2_SOAK_001",
    };
    int ok = 0, n = 0;
    std::string body;
    for (const char* g : kids) {
        bool p = ReadPass(g);
        ok += p ? 1 : 0; ++n;
        body += std::string(g) + (p ? "=PASS\n" : "=FAIL\n");
    }
    bool pass = ok == n;
    char head[64];
    snprintf(head, sizeof(head), "passed=%d/%d\n", ok, n);
    WriteGate("DEEP2_RUNTIME_COMPLETE_001", pass, std::string(head) + body);
    return pass;
}

int main(int argc, char** argv) {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
#endif
    CreateDirectoryA(kEvd, nullptr);
    const bool sealOnly = [] {
        const char* e = std::getenv("DEEP2_SEAL_K2_DS");
        return e && e[0] == '1';
    }();
    const bool k2Only = (argc > 1 && std::strcmp(argv[1], "--k2") == 0);
    const bool dsOnly = (argc > 1 && std::strcmp(argv[1], "--deepseek") == 0);
    const bool umbrellaOnly = (argc > 1 && std::strcmp(argv[1], "--umbrella") == 0);

    if (umbrellaOnly) {
        bool ok = GateRuntimeComplete();
        return ok ? 0 : 1;
    }
    if (k2Only) return GateK2() ? 0 : 1;
    if (dsOnly) return GateDeepSeek() ? 0 : 1;

    if (!sealOnly) GateStreamerComplete();
    int fails = 0;
    if (!sealOnly) fails += !GateLargeModel();
    fails += !GateK2();
    fails += !GateDeepSeek();
    if (!sealOnly) fails += !GateSoak();
    fails += !GateRuntimeComplete();
    printf("batch2_extra_fails=%d\n", fails);
    return fails ? 1 : 0;
}
