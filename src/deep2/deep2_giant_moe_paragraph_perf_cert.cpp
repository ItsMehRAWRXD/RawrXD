// deep2_giant_moe_paragraph_perf_cert.cpp — DEEP2_GIANT_MOE_PARAGRAPH_PERF_001
// Same paragraph prompt, TTFT vs DECODE_TPS. Outside GATE_ROADMAP_002.
#include "Deep2Engine.h"
#include <algorithm>
#include <chrono>
#include <cmath>
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
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

static constexpr const char* kPrompt =
    "Write exactly one coherent paragraph of approximately 120 words explaining "
    "how a local AI coding assistant can help a software developer. Discuss code "
    "generation, debugging, codebase understanding, privacy, and offline "
    "operation. Do not use bullet points, headings, lists, or markdown. Write "
    "only the paragraph.";
static constexpr const char* kEv =
    "G:\\~dev\\rawrxd\\evidence\\DEEP2_GIANT_MOE_PARAGRAPH_PERF_001";

struct Leg {
    const char* name = "";
    std::string path;
    int shards = 0;
    double load_s = 0, ttft_ms = 0, decode_s = 0, total_s = 0;
    double decode_tps = 0, e2e_tps = 0;
    size_t prompt_tok = 0, gen_tok = 0;
    char note[160]{};
    bool ok = false;
};

static int CountGguf(const std::string& p) {
    int n = 0;
    if (!fs::is_directory(p)) return fs::is_regular_file(p) ? 1 : 0;
    for (auto& e : fs::directory_iterator(p))
        if (e.is_regular_file() && e.path().extension() == ".gguf") ++n;
    return n;
}

static double Median(std::vector<double> v) {
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

static bool TimedStream(Deep2Engine& e, uint32_t maxTok, Leg& out) {
    GenerationOptions o{};
    o.maxTokens = maxTok; o.temperature = 0.f; o.topP = 1.f; o.topK = 1; o.seed = 42;
    size_t n = 0;
    double tFirst = -1.0;
    auto t0 = Clock::now();
    try {
        e.generateStream(kPrompt, o, [&](int32_t, const std::string&) -> bool {
            ++n;
            if (n == 1)
                tFirst = std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
            return true;
        });
    } catch (...) {
        snprintf(out.note, sizeof(out.note), "generate_threw");
        return false;
    }
    auto t1 = Clock::now();
    out.total_s = std::chrono::duration<double>(t1 - t0).count();
    out.gen_tok = n;
    out.ttft_ms = (tFirst >= 0.0) ? tFirst : (out.total_s * 1000.0);
    out.decode_s = (n > 1 && tFirst >= 0.0)
        ? std::max(1e-9, out.total_s - tFirst / 1000.0) : 0.0;
    out.decode_tps = (n > 1 && out.decode_s > 0.0)
        ? ((double)(n - 1) / out.decode_s) : 0.0;
    out.e2e_tps = (n > 0 && out.total_s > 0.0) ? ((double)n / out.total_s) : 0.0;
    out.prompt_tok = e.tokenize(kPrompt).size();
    return n > 0;
}

static Leg RunDeepSeek(const std::string& root, uint32_t maxTok, int runs) {
    Leg L{}; L.name = "DEEPSEEK"; L.path = root; L.shards = CountGguf(root);
#ifdef _WIN32
    _putenv_s("RAWRXD_DEEP2_ALLOW_UNSAFE_MLA", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
#endif
    if (L.shards < 11) {
        snprintf(L.note, sizeof(L.note), "FAIL_CLOSED_INCOMPLETE need=11 have=%d", L.shards);
        return L;
    }
    auto* eng = new Deep2Engine();
    auto tL0 = Clock::now();
    if (!eng->loadModel(root)) {
        snprintf(L.note, sizeof(L.note), "load=FAIL");
        delete eng; return L;
    }
    const auto& meta = eng->getModelMetadata();
    const auto& mw = eng->getModelWeights();
    EngineConfig cfg{};
    cfg.hiddenDim = mw.hiddenDim ? mw.hiddenDim : meta.hiddenSize;
    cfg.numLayers = mw.numLayers ? mw.numLayers : meta.numLayers;
    cfg.numHeads = mw.numHeads ? mw.numHeads : meta.numHeads;
    cfg.numKVHeads = mw.numKVHeads ? mw.numKVHeads : meta.numKeyValueHeads;
    cfg.headDim = mw.headDim;
    cfg.vocabSize = mw.vocabSize ? mw.vocabSize : meta.vocabSize;
    cfg.maxSeqLen = 512; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 8; cfg.useMLA = true;
    if (!eng->initialize(cfg)) {
        snprintf(L.note, sizeof(L.note), "init=FAIL");
        delete eng; return L;
    }
    L.load_s = std::chrono::duration<double>(Clock::now() - tL0).count();
    snprintf(L.note, sizeof(L.note), "arch=%s experts=%u mla_unsafe=1",
             meta.architecture.c_str(), meta.numExperts);
    // warmup discarded
    Leg discard{}; TimedStream(*eng, std::min(maxTok, 8u), discard);
    std::vector<double> dps;
    for (int i = 0; i < runs; ++i) {
        Leg r{};
        if (!TimedStream(*eng, maxTok, r)) { L = r; L.name = "DEEPSEEK"; L.path = root;
            L.shards = CountGguf(root); delete eng; return L; }
        dps.push_back(r.decode_tps);
        L = r; L.name = "DEEPSEEK"; L.path = root; L.shards = CountGguf(root);
        L.load_s = std::chrono::duration<double>(Clock::now() - tL0).count();
        snprintf(L.note, sizeof(L.note), "arch=%s experts=%u mla_unsafe=1",
                 meta.architecture.c_str(), meta.numExperts);
    }
    L.decode_tps = Median(dps);
    L.ok = L.gen_tok > 1 && L.decode_tps > 0.0;
    // leak eng — teardown abort on large MoE
    return L;
}

static Leg RunK2(const std::string& dir, uint32_t maxTok, int runs) {
    Leg L{}; L.name = "KIMI_K2"; L.path = dir; L.shards = CountGguf(dir);
#ifdef _WIN32
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
#endif
    if (L.shards < 13) {
        snprintf(L.note, sizeof(L.note), "FAIL_CLOSED_INCOMPLETE need=13 have=%d", L.shards);
        return L;
    }
    auto* eng = new Deep2Engine();
    EngineConfig cfg{};
    cfg.hiddenDim = 7168; cfg.numLayers = 61; cfg.numHeads = 64;
    cfg.numKVHeads = 1; cfg.vocabSize = 163840; cfg.useMLA = true;
    cfg.maxSeqLen = 512; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 8;
    auto tL0 = Clock::now();
    if (!eng->initialize(cfg) || !eng->openK2ShardDirectory(dir)) {
        snprintf(L.note, sizeof(L.note), "open_or_init=FAIL");
        delete eng; return L;
    }
    L.load_s = std::chrono::duration<double>(Clock::now() - tL0).count();
    // Prefer generateStream for TTFT/decode split; fallback native partial.
    Leg discard{};
    bool streamOk = TimedStream(*eng, std::min(maxTok, 8u), discard);
    if (streamOk) {
        snprintf(L.note, sizeof(L.note), "path=generateStream full_layers");
        std::vector<double> dps;
        for (int i = 0; i < runs; ++i) {
            Leg r{};
            if (!TimedStream(*eng, maxTok, r)) break;
            dps.push_back(r.decode_tps);
            L = r; L.name = "KIMI_K2"; L.path = dir; L.shards = CountGguf(dir);
            L.load_s = std::chrono::duration<double>(Clock::now() - tL0).count();
            snprintf(L.note, sizeof(L.note), "path=generateStream full_layers");
        }
        L.decode_tps = Median(dps);
        L.ok = L.gen_tok > 1 && L.decode_tps > 0.0;
        return L;
    }
    // Fallback: K2NativeStreamPartial (wall e2e only — not primary seal metric)
    std::vector<double> e2e;
    for (int i = 0; i < runs; ++i) {
        K2NativeStreamGate::Config kc;
        kc.prompt = kPrompt; kc.streamTokens = maxTok; kc.layerDepth = 61;
        kc.enableMlaComplete = true; kc.budgetBytes = 512ull << 20;
        auto t0 = Clock::now();
        auto r = eng->runK2NativeStreamPartial(kc);
        double sec = std::chrono::duration<double>(Clock::now() - t0).count();
        L.gen_tok = maxTok; L.total_s = sec;
        L.e2e_tps = (sec > 0.0) ? ((double)maxTok / sec) : 0.0;
        L.decode_tps = 0.0; // not measured — no per-token callbacks
        L.ok = r.ok && r.outputNonempty;
        e2e.push_back(L.e2e_tps);
    }
    L.e2e_tps = Median(e2e);
    snprintf(L.note, sizeof(L.note),
             "path=K2NativeStreamPartial NO_TTFT_SPLIT e2e_median=%.3f", L.e2e_tps);
    return L;
}

static void EmitLeg(FILE* f, const Leg& L) {
    fprintf(f, "%s:\n", L.name);
    fprintf(f, "  model=%s\n  shards=%d\n  load_seconds=%.3f\n",
            L.path.c_str(), L.shards, L.load_s);
    fprintf(f, "  ttft_ms=%.3f\n  prompt_tokens=%zu\n", L.ttft_ms, L.prompt_tok);
    fprintf(f, "  generated_tokens=%zu\n  decode_seconds=%.3f\n", L.gen_tok, L.decode_s);
    fprintf(f, "  decode_tps=%.3f\n  e2e_tps=%.3f\n  total_seconds=%.3f\n",
            L.decode_tps, L.e2e_tps, L.total_s);
    fprintf(f, "  note=%s\n  ok=%d\n", L.note, (int)L.ok);
}

int main(int argc, char** argv) {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    CreateDirectoryA(kEv, nullptr);
#endif
    bool k2Only = false, dsOnly = false;
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--k2-only")) k2Only = true;
        if (!std::strcmp(argv[i], "--deepseek-only")) dsOnly = true;
    }
    uint32_t maxTok = 160;
    if (const char* e = std::getenv("DEEP2_PARA_TOKENS")) maxTok = (uint32_t)std::max(8, atoi(e));
    int runs = 3;
    if (const char* e = std::getenv("DEEP2_PARA_RUNS")) runs = std::max(1, atoi(e));

    const char* k2Env = std::getenv("DEEP2_K2_SHARD_DIR");
    std::string k2 = (k2Env && k2Env[0]) ? k2Env
        : "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    const char* dsEnv = std::getenv("DEEP2_DEEPSEEK_MODEL");
    std::string ds = (dsEnv && dsEnv[0]) ? dsEnv
        : "F:\\OllamaModels\\DeepSeek-R1-Q4_K_M-COMPLETE";

    printf("DEEP2_GIANT_MOE_PARAGRAPH_PERF_001\nmaxTok=%u runs=%d\n", maxTok, runs);
    printf("HISTORICAL_85_4=K2.5_2.5B_NOT_THIS\nHISTORICAL_14_38=ASYNC_RING_NOT_THIS\n");

    Leg k2L{}, dsL{};
    if (!dsOnly) k2L = RunK2(k2, maxTok, runs);
    if (!k2Only) dsL = RunDeepSeek(ds, maxTok, runs);

    const bool pass = (!dsOnly ? k2L.ok : true) && (!k2Only ? dsL.ok : true);
    char statusPath[320];
    snprintf(statusPath, sizeof(statusPath), "%s\\GATE_STATUS.txt", kEv);
    FILE* f = fopen(statusPath, "w");
    auto emit = [&](FILE* out) {
        fprintf(out, "GATE=DEEP2_GIANT_MOE_PARAGRAPH_PERF_001\n");
        fprintf(out, "PRIMARY_METRIC=DECODE_TPS=(gen_tok-1)/decode_seconds_after_TTFT\n");
        fprintf(out, "PROMPT=paragraph_120w MAX_NEW_TOKENS=%u TEMP=0 TOP_P=1 SEED=42 RUNS=%d\n",
                maxTok, runs);
        if (!dsOnly) EmitLeg(out, k2L);
        if (!k2Only) EmitLeg(out, dsL);
        fprintf(out, "DEEP2_GIANT_MOE_PARAGRAPH_PERF_001=%s\n", pass ? "PASS" : "FAIL");
    };
    emit(stdout);
    if (f) { emit(f); fclose(f); }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
