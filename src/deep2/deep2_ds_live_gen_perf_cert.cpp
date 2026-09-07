// deep2_ds_live_gen_perf_cert.cpp — DEEP2_DEEPSEEK_LIVE_GEN_PERF_001
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
    SetEnvironmentVariableA("RAWRXD_DEEP2_ALLOW_UNSAFE_MLA", nullptr);
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
#endif
    const char* pathEnv = std::getenv("DEEP2_DEEPSEEK_MODEL");
    const char* path = (pathEnv && pathEnv[0])
        ? pathEnv : "F:\\OllamaModels\\DeepSeek-R1-Q4_K_M-COMPLETE";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\DEEP2_DEEPSEEK_LIVE_GEN_PERF_001", nullptr);
    printf("DEEP2_DEEPSEEK_LIVE_GEN_PERF_001\n");
    printf("HISTORICAL_14_38_TPS=SOVEREIGN_ASYNC_RING_E2E_001_NOT_THIS_MODEL\n");
    uint32_t ggufN = 0;
    unsigned long long bytes = 0;
    if (fs::is_directory(path)) {
        for (auto& e : fs::directory_iterator(path)) {
            if (e.is_regular_file() && e.path().extension() == ".gguf") {
                ++ggufN;
                bytes += (unsigned long long)e.file_size();
            }
        }
    }
    const bool complete = fs::exists(path) && (!fs::is_directory(path) || ggufN >= 11);
    Deep2Engine engine;
    const bool loaded = complete && engine.loadModel(path);
    const char* reason = !complete ? "INCOMPLETE_SHARDS" : (!loaded ? "MLA_CERT_001" : "OK");
    size_t n = 0;
    double ms = 0.0, tps = 0.0;
    if (loaded) {
        const auto& mw = engine.getModelWeights();
        EngineConfig cfg{};
        cfg.hiddenDim = mw.hiddenDim; cfg.numLayers = mw.numLayers;
        cfg.numHeads = mw.numHeads; cfg.numKVHeads = mw.numKVHeads;
        cfg.headDim = mw.headDim; cfg.vocabSize = mw.vocabSize;
        cfg.maxSeqLen = 128; cfg.useKVCache = true; cfg.useThreadPool = true; cfg.numThreads = 8;
        if (engine.initialize(cfg)) {
            GenerationOptions o{}; o.maxTokens = 4; o.temperature = 0; o.topK = 1;
            auto t0 = std::chrono::steady_clock::now();
            engine.generateStream("hi", o, [&](int32_t, const std::string&) -> bool { ++n; return true; });
            ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
            if (n && ms > 0.0) tps = 1000.0 * (double)n / ms;
        } else reason = "INIT_FAIL";
    }
    const bool pass = loaded && n > 0 && tps > 0.0;
    char body[768];
    snprintf(body, sizeof(body),
             "HISTORICAL_14_38_TPS=SOVEREIGN_ASYNC_RING_E2E_001_NOT_THIS_MODEL\n"
             "HISTORICAL_14_2_TPS=SINGLE_R9700_SOVEREIGN_BASELINE_NOT_THIS_MODEL\n"
             "PATH=Deep2Engine::loadModel+generateStream\nMODEL=%s\n"
             "SHARDS=%u BYTES=%llu LOADED=%d REASON=%s\n"
             "TOKENS=%zu WALL_MS=%.3f DECODE_TPS=%.3f\n"
             "DEEP2_DEEPSEEK_LIVE_GEN_PERF_001=%s\n",
             path, ggufN, bytes, (int)loaded, reason, n, ms, tps,
             pass ? "PASS" : "FAIL_CLOSED");
    printf("%s", body);
    FILE* f = fopen("G:\\~dev\\rawrxd\\evidence\\DEEP2_DEEPSEEK_LIVE_GEN_PERF_001\\GATE_STATUS.txt", "w");
    if (f) { fputs(body, f); fclose(f); }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
