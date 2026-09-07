// deep2_deepseek_live_gen_perf_cert.cpp — DEEP2_DEEPSEEK_LIVE_GEN_PERF_001
// Fresh seal on modern Deep2 path. Does NOT inherit historical 14.38 TPS claims.
// DeepSeek-R1 Q4_K_M-COMPLETE is deepseek2/MLA — use K2NativeStreamPartial
// (same family path as Kimi K2), not full loadModel (MLA refuse without unsafe flag).
#include "Deep2Engine.h"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
using namespace Deep2;
namespace fs = std::filesystem;

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
#endif
    const char* dirEnv = std::getenv("DEEP2_DEEPSEEK_MODEL");
    const char* dir = (dirEnv && dirEnv[0])
        ? dirEnv : "F:\\OllamaModels\\DeepSeek-R1-Q4_K_M-COMPLETE";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\DEEP2_DEEPSEEK_LIVE_GEN_PERF_001", nullptr);
    printf("DEEP2_DEEPSEEK_LIVE_GEN_PERF_001\n");
    printf("HISTORICAL_14_38_TPS=SOVEREIGN_ASYNC_RING_E2E_001_NOT_THIS_GATE\n");
    printf("PATH=K2NativeStreamPartial (deepseek2 family)\n");

    if (!fs::is_directory(dir)) {
        FILE* f = fopen("G:\\~dev\\rawrxd\\evidence\\DEEP2_DEEPSEEK_LIVE_GEN_PERF_001\\GATE_STATUS.txt", "w");
        if (f) {
            fprintf(f, "status=SKIP_NO_MODEL\nDEEP2_DEEPSEEK_LIVE_GEN_PERF_001=SKIP\n");
            fclose(f);
        }
        printf("SKIP_NO_MODEL\n");
        return 0;
    }

    uint32_t ggufN = 0;
    unsigned long long bytes = 0;
    for (auto& e : fs::directory_iterator(dir)) {
        if (e.is_regular_file() && e.path().extension() == ".gguf") {
            ++ggufN;
            bytes += (unsigned long long)e.file_size();
        }
    }

    uint32_t nTok = 96;
    if (const char* t = std::getenv("DEEP2_LIVE_TOKENS"))
        nTok = (uint32_t)std::max(1, atoi(t));
    uint32_t depth = 4;
    if (const char* d = std::getenv("DEEP2_LIVE_LAYER_DEPTH"))
        depth = (uint32_t)std::max(1, atoi(d));
    static const char* kPrompt =
        "Write one short paragraph explaining why tokens-per-second (tok/s) "
        "improvement matters for local LLM inference, and name one concrete "
        "technique that raises decode tok/s without silently falling back to CPU.";

    // Heap-allocate: multi-shard teardown currently aborts in ~Deep2Engine.
    auto* e = new Deep2Engine();
    EngineConfig cfg{};
    cfg.hiddenDim = 7168; cfg.numLayers = 61;
    cfg.numHeads = 128; cfg.numKVHeads = 128; cfg.vocabSize = 129280;
    cfg.useMLA = true; cfg.maxSeqLen = 512;
    cfg.useKVCache = true; cfg.useThreadPool = true; cfg.numThreads = 8;
    if (!e->initialize(cfg) || !e->openK2ShardDirectory(dir)) {
        FILE* f = fopen("G:\\~dev\\rawrxd\\evidence\\DEEP2_DEEPSEEK_LIVE_GEN_PERF_001\\GATE_STATUS.txt", "w");
        if (f) {
            fprintf(f, "open_or_init=FAIL shards=%u\n", ggufN);
            fprintf(f, "DEEP2_DEEPSEEK_LIVE_GEN_PERF_001=FAIL\n");
            fclose(f);
        }
        delete e;
        return 2;
    }

    K2NativeStreamGate::Config kc;
    kc.prompt = kPrompt;
    kc.streamTokens = nTok;
    kc.layerDepth = depth;
    kc.enableMlaComplete = true;
    kc.budgetBytes = 512ull * 1024 * 1024;

    auto t0 = std::chrono::steady_clock::now();
    auto r = e->runK2NativeStreamPartial(kc);
    auto t1 = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    double tps = (r.ok && ms > 0.0) ? ((double)nTok * 1000.0 / ms) : 0.0;
    const bool bounded = r.peakResidencyBytes > 0 && r.peakResidencyBytes <= kc.budgetBytes;
    const bool pass = r.ok && r.outputNonempty && ggufN >= 11 &&
                      r.shardsDiscovered >= 11 && bounded && tps > 0.0;
    if (!r.ok)
        fprintf(stderr, "[DS_LIVE_ERR] %s\n", r.error.c_str());

    auto emit = [&](FILE* o) {
        if (!o) return;
        fprintf(o, "HISTORICAL_14_38_TPS=SOVEREIGN_ASYNC_RING_E2E_001_NOT_THIS_GATE\n");
        fprintf(o, "PATH=K2NativeStreamPartial\n");
        fprintf(o, "MODEL=%s\n", dir);
        fprintf(o, "SHARDS=%u BYTES=%llu\n", ggufN, bytes);
        fprintf(o, "PROMPT=tok_s_improvement_paragraph\n");
        fprintf(o, "LAYER_DEPTH=%u TOKENS=%u GEN_ID=%d PEAK=%llu\n",
                depth, nTok, r.generatedTokenId,
                (unsigned long long)r.peakResidencyBytes);
        fprintf(o, "WALL_MS=%.3f DECODE_TPS=%.3f bounded=%d ok=%d\n",
                ms, tps, (int)bounded, (int)r.ok);
        fputs("GENERATED_TEXT=", o);
        for (char c : r.generatedText) {
            if (c == '\n' || c == '\r') fputc(' ', o);
            else fputc(c, o);
        }
        fputc('\n', o);
        fprintf(o, "BLOCKER=%s\n",
                pass ? "NONE"
                     : (!r.ok ? "K2_NATIVE_STREAM_PARTIAL_FAIL_ON_R1_TOPOLOGY"
                              : (ggufN < 11 ? "INCOMPLETE_SHARDS" : "NO_TOKENS")));
        fprintf(o, "DEEP2_DEEPSEEK_LIVE_GEN_PERF_001=%s\n", pass ? "PASS" : "FAIL");
    };
    emit(stdout);
    FILE* f = fopen("G:\\~dev\\rawrxd\\evidence\\DEEP2_DEEPSEEK_LIVE_GEN_PERF_001\\GATE_STATUS.txt", "w");
    if (f) { emit(f); fclose(f); }
    fflush(stdout);
    // Always _exit — ~Deep2Engine aborts / heap-corrupts on multi-shard teardown.
    _exit(pass ? 0 : 2);
}
