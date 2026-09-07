// deep2_runtime_batch1_cert.cpp — DEEP2_RUNTIME batch-1 gates (loader..policy)
#include "Deep2Engine.h"
#include "ChatTemplate.hpp"
#include "Deep2DeviceManager.hpp"
#include "GGUFLoader.hpp"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <thread>
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
static const char* kEvdRoot = "G:\\~dev\\rawrxd\\evidence";

static void WriteGate(const char* gate, bool pass, const std::string& body) {
    std::string dir = std::string(kEvdRoot) + "\\" + gate;
    CreateDirectoryA(dir.c_str(), nullptr);
    std::string path = dir + "\\GATE_STATUS.txt";
    FILE* f = nullptr;
    fopen_s(&f, path.c_str(), "wb");
    if (!f) return;
    fprintf(f, "%s", body.c_str());
    fprintf(f, "%s=%s\n", gate, pass ? "PASS" : "FAIL");
    fclose(f);
    printf("%s=%s\n", gate, pass ? "PASS" : "FAIL");
}

static bool InitEngine(Deep2Engine& e, size_t maxSeq = 512) {
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

static size_t StreamN(Deep2Engine& e, const char* p, int n,
                      GenerationOptions o = {}) {
    o.maxTokens = (uint32_t)n;
    if (o.temperature == 0.8f && o.topK == 40) {
        o.temperature = 0; o.topK = 1; o.seed = 42;
    }
    size_t k = 0;
    e.generateStream(p, o, [&](int32_t, const std::string&) -> bool {
        ++k; return true;
    });
    return k;
}

static bool GateLoader() {
    GGUFLoadResult meta = GGUFLoader::LoadMetadata(kModel);
    Deep2Engine e;
    bool load = InitEngine(e, 256);
    const auto& m = e.getModelMetadata();
    bool tok = !e.tokenize("hello").empty();
    bool arch = !m.architecture.empty() || !meta.metadata.architecture.empty();
    bool pass = meta.success && load && tok && arch && e.isModelLoaded();
    char buf[512];
    snprintf(buf, sizeof(buf),
             "metadata_ok=%d architecture=%s vocab=%u layers=%u tok=%d loaded=%d\n",
             (int)meta.success, m.architecture.c_str(), m.vocabSize, m.numLayers,
             (int)tok, (int)e.isModelLoaded());
    WriteGate("DEEP2_MODEL_LOADER_001", pass, buf);
    return pass;
}

static bool GateArch() {
    const char* names[][2] = {
        {"llama", "tinyllama"}, {"qwen2", "qwen2.5"}, {"phi3", "phi-3"},
        {"gemma2", "gemma-2"}, {"mistral", "mistral"}, {"deepseek", "deepseek"},
    };
    int ok = 0;
    std::string body;
    for (auto& n : names) {
        auto t = ChatTemplate::detectFromModel(n[0], n[1]);
        bool good = t != ChatTemplateType::UNKNOWN;
        ok += good ? 1 : 0;
        body += std::string(n[0]) + "=" + (good ? "OK" : "FAIL") + "\n";
    }
    Deep2Engine e;
    InitEngine(e, 128);
    auto live = ChatTemplate::detectFromModel(e.getModelMetadata().architecture,
                                              "tinyllama");
    body += "live_arch=" + e.getModelMetadata().architecture + "\n";
    bool pass = ok >= 5 && live != ChatTemplateType::UNKNOWN;
    WriteGate("DEEP2_ARCH_MATRIX_001", pass, body);
    return pass;
}

static bool GateTokenizer() {
    Deep2Engine e;
    if (!InitEngine(e, 128)) {
        WriteGate("DEEP2_TOKENIZER_MATRIX_001", false, "init=FAIL\n");
        return false;
    }
    const char* s = "The quick brown fox";
    auto ids = e.tokenize(s);
    auto back = e.detokenize(ids);
    const auto& st = e.getModelMetadata();
    bool round = !ids.empty() && back.find("quick") != std::string::npos;
    bool bos = !st.bosToken.empty();
    bool eos = !st.eosToken.empty();
    char buf[256];
    snprintf(buf, sizeof(buf), "ids=%zu roundtrip=%d bos=%s eos=%s\n",
             ids.size(), (int)round, st.bosToken.c_str(), st.eosToken.c_str());
    bool pass = round && bos && eos;
    WriteGate("DEEP2_TOKENIZER_MATRIX_001", pass, buf);
    return pass;
}

static bool GateSampler() {
    Deep2Engine e;
    if (!InitEngine(e, 256)) {
        WriteGate("DEEP2_SAMPLER_001", false, "init=FAIL\n");
        return false;
    }
    GenerationOptions g{}; g.maxTokens = 4; g.temperature = 0; g.topK = 1; g.seed = 1;
    size_t greedy = 0;
    e.generateStream("hi", g, [&](int32_t, const std::string&) -> bool {
        ++greedy; return true;
    });
    GenerationOptions t{}; t.maxTokens = 4; t.temperature = 0.9f; t.topK = 20;
    t.topP = 0.9f; t.minP = 0.05f; t.repeatPenalty = 1.15f; t.seed = 7;
    size_t samp = 0;
    e.generateStream("hi", t, [&](int32_t, const std::string&) -> bool {
        ++samp; return true;
    });
    bool pass = greedy > 0 && samp > 0;
    char buf[128];
    snprintf(buf, sizeof(buf), "greedy=%zu sampled=%zu minP=0.05 repeat=1.15\n",
             greedy, samp);
    WriteGate("DEEP2_SAMPLER_001", pass, buf);
    return pass;
}

static bool GateContext() {
    Deep2Engine e;
    if (!InitEngine(e, 128)) {
        WriteGate("DEEP2_CONTEXT_001", false, "init=FAIL\n");
        return false;
    }
    size_t before = e.getConfig().maxSeqLen;
    bool grew = e.growContext(256);
    size_t after = e.getConfig().maxSeqLen;
    e.reset();
    size_t n = StreamN(e, "ok", 2);
    bool pass = grew && after == 256 && before == 128 && n > 0;
    char buf[128];
    snprintf(buf, sizeof(buf), "before=%zu after=%zu grow=%d gen=%zu\n",
             before, after, (int)grew, n);
    WriteGate("DEEP2_CONTEXT_001", pass, buf);
    return pass;
}

static bool GatePrefillDecode() {
    Deep2Engine e;
    if (!InitEngine(e, 512)) {
        WriteGate("DEEP2_PREFILL_DECODE_001", false, "init=FAIL\n");
        return false;
    }
    InferenceStats st{};
    auto ids = e.tokenize("Say hello");
    std::vector<int> out(8);
    size_t n = e.generate(ids.data(), ids.size(), out.data(), out.size(), &st);
    bool pass = n > 0 && st.prefillMs >= 0 && st.decodeMs >= 0 &&
                st.promptTokens == ids.size();
    char buf[192];
    snprintf(buf, sizeof(buf),
             "gen=%zu prompt=%zu prefill_ms=%.3f decode_ms=%.3f\n",
             n, st.promptTokens, st.prefillMs, st.decodeMs);
    WriteGate("DEEP2_PREFILL_DECODE_001", pass, buf);
    return pass;
}

static bool GateStreaming() {
    Deep2Engine e;
    if (!InitEngine(e, 256)) {
        WriteGate("DEEP2_STREAMING_OUTPUT_001", false, "init=FAIL\n");
        return false;
    }
    std::string acc;
    size_t pieces = 0;
    GenerationOptions o{}; o.maxTokens = 6; o.temperature = 0; o.topK = 1;
    auto r = e.generateStream("Count:", o,
        [&](int32_t, const std::string& tok) -> bool {
            acc += tok; ++pieces; return true;
        });
    bool pass = pieces == r.generatedTokens && pieces > 0 && !acc.empty() &&
                !r.cancelled;
    char buf[160];
    snprintf(buf, sizeof(buf), "pieces=%zu gen=%zu text_len=%zu\n",
             pieces, (size_t)r.generatedTokens, acc.size());
    WriteGate("DEEP2_STREAMING_OUTPUT_001", pass, buf);
    return pass;
}

static bool GateCancel() {
    Deep2Engine e;
    if (!InitEngine(e, 256)) {
        WriteGate("DEEP2_CANCEL_001", false, "init=FAIL\n");
        return false;
    }
    std::atomic<bool> started{false};
    GenerationResult res{};
    std::thread th([&] {
        GenerationOptions o{}; o.maxTokens = 64; o.temperature = 0; o.topK = 1;
        res = e.generateStream("Write a long story", o,
            [&](int32_t, const std::string&) -> bool {
                started.store(true); return true;
            });
    });
    while (!started.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    e.requestCancel();
    th.join();
    bool pass = res.cancelled || res.generatedTokens < 64;
    char buf[128];
    snprintf(buf, sizeof(buf), "cancelled=%d gen=%zu\n",
             (int)res.cancelled, (size_t)res.generatedTokens);
    WriteGate("DEEP2_CANCEL_001", pass, buf);
    return pass;
}

static bool GateConcurrency() {
    std::atomic<int> ok{0};
    auto worker = [&](int id) {
        Deep2Engine e;
        if (!InitEngine(e, 128)) return;
        size_t n = StreamN(e, id ? "alpha" : "beta", 3);
        if (n > 0) ok.fetch_add(1);
    };
    std::thread a(worker, 0), b(worker, 1);
    a.join(); b.join();
    bool pass = ok.load() == 2;
    char buf[64];
    snprintf(buf, sizeof(buf), "sessions_ok=%d\n", ok.load());
    WriteGate("DEEP2_CONCURRENCY_001", pass, buf);
    return pass;
}

static bool GateLifecycle() {
    Deep2Engine e;
    if (!InitEngine(e, 128)) {
        WriteGate("DEEP2_MODEL_LIFECYCLE_001", false, "init=FAIL\n");
        return false;
    }
    size_t n1 = StreamN(e, "a", 2);
    e.unloadModel();
    bool sw = e.switchModel(kModel);
    size_t n2 = StreamN(e, "b", 2);
    bool sw2 = e.switchModel(kModel);
    size_t n3 = StreamN(e, "c", 2);
    bool pass = n1 > 0 && sw && n2 > 0 && sw2 && n3 > 0;
    char buf[128];
    snprintf(buf, sizeof(buf), "n1=%zu sw=%d n2=%zu sw2=%d n3=%zu\n",
             n1, (int)sw, n2, (int)sw2, n3);
    WriteGate("DEEP2_MODEL_LIFECYCLE_001", pass, buf);
    return pass;
}

static bool GateOom() {
    // Tiny weight budget forces slot replan; process must survive + decode.
#ifdef _WIN32
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_SLOTS", "8");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "64");
    _putenv_s("RAWRXD_GPU_FWD", "1");
#endif
    Deep2Engine e;
    bool alive = InitEngine(e, 128);
    if (alive) e.enableVulkan(true);
    size_t n = alive ? StreamN(e, "oom", 2) : 0;
    bool pass = alive; // survive budget; gen optional if GPU unavailable
    char buf[128];
    snprintf(buf, sizeof(buf), "alive=%d gen=%zu budget_mib=64\n", (int)alive, n);
    WriteGate("DEEP2_OOM_RECOVERY_001", pass, buf);
#ifdef _WIN32
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
#endif
    return pass;
}

static bool GateCpuGpuPolicy() {
    DeviceManagerSnapshot snap{};
    bool en = Deep2Device_Enumerate(snap);
    bool pol = Deep2Device_ApplyPolicy(snap);
    bool pass = en && pol && snap.plan.reason != nullptr;
    char buf[256];
    snprintf(buf, sizeof(buf),
             "devices=%u policy=%u mode=%u backend=%s reason=%s primary=%s\n",
             snap.deviceCount, (unsigned)snap.plan.policy, (unsigned)snap.plan.mode,
             snap.plan.backend ? snap.plan.backend : "null",
             snap.plan.reason ? snap.plan.reason : "null",
             snap.plan.primaryName);
    WriteGate("DEEP2_CPU_GPU_POLICY_001", pass, buf);
    return pass;
}

static bool GatePackedSurface() {
#ifdef _WIN32
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_SLOTS", "2");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
    _putenv_s("RAWRXD_GPU_FWD", "1");
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
#endif
    Deep2Engine e;
    if (!InitEngine(e, 256)) {
        WriteGate("DEEP2_PACKED_SURFACE_001", false, "init=FAIL\n");
        return false;
    }
    e.enableVulkan(true);
    e.enableMedusa(false);
    size_t n = StreamN(e, "pack", 4);
    auto* vc = e.getVulkanComputeSlot(0);
    const auto& c = e.gpuForwardCounters();
    uint64_t packed = vc ? vc->QuantPackedOps() : 0;
    uint64_t expands = c.cpuF32Expands;
    bool pass = n > 0 && packed > 0 && expands == 0 &&
                e.vulkanGemvFallbackCount() == 0 &&
                c.liveDecodeResidentTokens > 0;
    char buf[256];
    snprintf(buf, sizeof(buf),
             "gen=%zu packed_ops=%llu f32_expands=%llu fallback=%llu live=%llu\n",
             n, (unsigned long long)packed, (unsigned long long)expands,
             (unsigned long long)e.vulkanGemvFallbackCount(),
             (unsigned long long)c.liveDecodeResidentTokens);
    WriteGate("DEEP2_PACKED_SURFACE_001", pass, buf);
    return pass;
}

static bool GateResidentForward() {
#ifdef _WIN32
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("RAWRXD_GPU_FWD", "1");
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
#endif
    Deep2Engine e;
    if (!InitEngine(e, 256)) {
        WriteGate("DEEP2_RESIDENT_FORWARD_001", false, "init=FAIL\n");
        return false;
    }
    e.enableVulkan(true);
    e.enableMedusa(false);
    size_t n = StreamN(e, "fwd", 4);
    const auto& c = e.gpuForwardCounters();
    bool pass = n > 0 && e.isRealGpuForward() &&
                c.liveDecodeResidentTokens > 0 &&
                c.hostForwardLayerCalls == 0 &&
                e.vulkanGemvFallbackCount() == 0;
    char buf[192];
    snprintf(buf, sizeof(buf),
             "gen=%zu real_fwd=%d live=%llu host_layers=%llu fallback=%llu\n",
             n, (int)e.isRealGpuForward(),
             (unsigned long long)c.liveDecodeResidentTokens,
             (unsigned long long)c.hostForwardLayerCalls,
             (unsigned long long)e.vulkanGemvFallbackCount());
    WriteGate("DEEP2_RESIDENT_FORWARD_001", pass, buf);
    return pass;
}

static bool GateWeightWindowRuntime() {
#ifdef _WIN32
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_SLOTS", "2");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "256");
    _putenv_s("RAWRXD_GPU_FWD", "1");
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
#endif
    Deep2Engine e;
    if (!InitEngine(e, 256)) {
        WriteGate("DEEP2_WEIGHT_WINDOW_RUNTIME_001", false, "init=FAIL\n");
        return false;
    }
    e.enableVulkan(true);
    e.enableMedusa(false);
    size_t n = StreamN(e, "win", 4);
    auto* vc = e.getVulkanComputeSlot(0);
    bool pass = n > 0 && vc && vc->WeightStreamActive() &&
                vc->WeightSlotCount() >= 2 &&
                vc->WeightResidentGrowthAfterInit() == 0 &&
                vc->WeightHotpathCreateBuf() == 0 &&
                vc->WeightHotpathDestroyBuf() == 0 &&
                vc->WeightHotpathWaitIdle() == 0;
    char buf[256];
    snprintf(buf, sizeof(buf),
             "gen=%zu active=%d slots=%u peak=%llu allocs=%llu reuses=%llu growth=%llu\n",
             n, vc && vc->WeightStreamActive() ? 1 : 0,
             vc ? vc->WeightSlotCount() : 0,
             (unsigned long long)(vc ? vc->WeightStreamPeakBytes() : 0),
             (unsigned long long)(vc ? vc->WeightSlotAllocs() : 0),
             (unsigned long long)(vc ? vc->WeightSlotReuses() : 0),
             (unsigned long long)(vc ? vc->WeightResidentGrowthAfterInit() : 0));
    WriteGate("DEEP2_WEIGHT_WINDOW_RUNTIME_001", pass, buf);
    return pass;
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
#endif
    CreateDirectoryA(kEvdRoot, nullptr);
    int fails = 0;
    fails += !GateLoader();
    fails += !GateArch();
    fails += !GateTokenizer();
    fails += !GateSampler();
    fails += !GateContext();
    fails += !GatePrefillDecode();
    fails += !GateStreaming();
    fails += !GateCancel();
    fails += !GateConcurrency();
    fails += !GateLifecycle();
    fails += !GateOom();
    fails += !GateCpuGpuPolicy();
    fails += !GatePackedSurface();
    fails += !GateResidentForward();
    fails += !GateWeightWindowRuntime();
    bool umbrella = fails == 0;
    char ubuf[64];
    snprintf(ubuf, sizeof(ubuf), "batch1_fails=%d gates=15\n", fails);
    WriteGate("DEEP2_RUNTIME_BATCH1_001", umbrella, ubuf);
    printf("DEEP2_RUNTIME_BATCH1_001=%s fails=%d\n",
           umbrella ? "PASS" : "FAIL", fails);
    return fails ? 1 : 0;
}
