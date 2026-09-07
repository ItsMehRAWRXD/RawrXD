// deep2_k2_live_gen_perf_cert.cpp — DEEP2_K2_LIVE_GEN_PERF_001 + TRANSFER_COUNTER
#include "Deep2Engine.h"
#include "StreamTransferCounters.hpp"
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
    const char* dirEnv = std::getenv("DEEP2_K2_SHARD_DIR");
    const char* dir = (dirEnv && dirEnv[0])
        ? dirEnv : "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\DEEP2_K2_LIVE_GEN_PERF_001", nullptr);
    const char* ab = std::getenv("DEEP2_LIVE_PATH");
    const char* abLabel = (ab && ab[0] == '0') ? "A_BASELINE_LIVE_OFF"
        : (ab && ab[0] == '1') ? "B_LIVE_ON" : "DEFAULT_LIVE";
    printf("DEEP2_K2_LIVE_GEN_PERF_001\nTRANSFER_COUNTER_001\nAB_ARM=%s\n", abLabel);
    printf("HISTORICAL_85_4_TPS=K2.5_2.5B_Q8_0_NOT_THIS_MODEL\n");
    uint32_t ggufN = 0;
    unsigned long long bytes = 0;
    if (fs::is_directory(dir)) {
        for (auto& e : fs::directory_iterator(dir)) {
            if (e.is_regular_file() && e.path().extension() == ".gguf") {
                ++ggufN;
                bytes += (unsigned long long)e.file_size();
            }
        }
    }
    uint32_t nTok = 96;
    if (const char* t = std::getenv("DEEP2_LIVE_TOKENS")) nTok = (uint32_t)std::max(1, atoi(t));
    uint32_t depth = 4;
    if (const char* d = std::getenv("RAWRXD_K2_LAYERS")) depth = (uint32_t)std::max(1, atoi(d));
    static const char* kPrompt =
        "Write one short paragraph explaining why tokens-per-second (tok/s) "
        "improvement matters for local LLM inference, and name one concrete "
        "technique that raises decode tok/s without silently falling back to CPU.";
    auto* e = new Deep2Engine();
    EngineConfig cfg{};
    cfg.hiddenDim = 7168; cfg.numLayers = 61; cfg.numHeads = 64;
    cfg.numKVHeads = 1; cfg.vocabSize = 163840; cfg.useMLA = true;
    cfg.maxSeqLen = 512; cfg.useKVCache = true; cfg.useThreadPool = true; cfg.numThreads = 8;
    bool opened = e->initialize(cfg) && e->openK2ShardDirectory(dir);
    K2NativeStreamGate::Config kc;
    kc.prompt = kPrompt; kc.streamTokens = nTok; kc.layerDepth = depth;
    kc.enableMlaComplete = true; kc.budgetBytes = 512ull << 20;
    auto t0 = std::chrono::steady_clock::now();
    auto r = opened ? e->runK2NativeStreamPartial(kc) : K2NativeStreamGate::Result{};
    auto ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    const double tps = (r.ok && nTok && ms > 0.0) ? (1000.0 * (double)nTok / ms) : 0.0;
    const bool bounded = r.peakResidencyBytes > 0 && r.peakResidencyBytes <= kc.budgetBytes;
    const bool xferOk = r.streamBytesRead > 0 && r.streamReadOps > 0;
    const bool pass = opened && r.ok && ggufN >= 13 && r.shardsDiscovered >= 13 &&
        r.generatedTokenId >= 0 && r.outputNonempty && bounded && tps > 0.0 && xferOk;
    const auto& lp = LivePath_Counters();
    char body[2048];
    snprintf(body, sizeof(body),
             "HISTORICAL_85_4_TPS=K2.5_2.5B_Q8_0_NOT_THIS_MODEL\n"
             "PATH=K2NativeStreamPartial\nAB_ARM=%s\nMODEL=%s\nSHARDS=%u BYTES=%llu\n"
             "PROMPT=tok_s_improvement_paragraph\n"
             "NVME_REVERSE_SOURCE_AVAILABLE=FALSE\n"
             "NVME_HOPS=%u\n"
             "LAYER_DEPTH=%u TOKENS=%u GEN_ID=%d PEAK=%llu\n"
             "WALL_MS=%.3f DECODE_TPS=%.3f bounded=%d ok=%d\n"
             "TRANSFER_BYTES_READ_TOTAL=%llu\n"
             "TRANSFER_BYTES_TO_GPU_TOTAL=%llu\n"
             "TRANSFER_BYTES_RECONSTRUCTED_TOTAL=%llu\n"
             "TRANSFER_READ_OPS=%llu\n"
             "TRANSFER_GPU_UPLOAD_OPS=%llu\n"
             "STREAM_BYTES_READ_TOTAL=%llu\n"
             "STREAM_BYTES_TO_GPU_TOTAL=%llu\n"
             "STREAM_BYTES_RECONSTRUCTED_TOTAL=%llu\n"
             "STREAM_READ_OPS=%llu\nSTREAM_GPU_UPLOAD_OPS=%llu\n"
             "STREAM_CACHE_HITS=%llu\nSTREAM_CACHE_MISSES=%llu\n"
             "STREAM_BYTES_PER_TOKEN=%.1f\nSTREAM_BYTES_PER_LAYER=%.1f\n"
             "TRANSFER_COUNTER_001=%s\n"
             "DEEP2_K2_LIVE_GEN_PERF_001=%s\n",
             abLabel, dir, ggufN, bytes, lp.nvmeHops,
             r.layerDepth, nTok, r.generatedTokenId,
             (unsigned long long)r.peakResidencyBytes, ms, tps, (int)bounded,
             (int)r.ok,
             (unsigned long long)r.streamBytesRead,
             (unsigned long long)r.streamBytesToGpu,
             (unsigned long long)r.streamBytesReconstructed,
             (unsigned long long)r.streamReadOps,
             (unsigned long long)r.streamGpuUploadOps,
             (unsigned long long)r.streamBytesRead,
             (unsigned long long)r.streamBytesToGpu,
             (unsigned long long)r.streamBytesReconstructed,
             (unsigned long long)r.streamReadOps,
             (unsigned long long)r.streamGpuUploadOps,
             (unsigned long long)r.streamCacheHits,
             (unsigned long long)r.streamCacheMisses,
             r.streamBytesPerToken, r.streamBytesPerLayer,
             xferOk ? "PASS" : "FAIL",
             pass ? "PASS" : "FAIL");
    printf("%s", body);
    printf("GENERATED_TEXT=");
    for (char c : r.generatedText) {
        if (c == '\n' || c == '\r') putchar(' ');
        else putchar(c);
    }
    printf("\n");
    const char* statusPath = (ab && ab[0] == '0')
        ? "G:\\~dev\\rawrxd\\evidence\\DEEP2_K2_LIVE_GEN_PERF_001\\GATE_STATUS_A.txt"
        : (ab && ab[0] == '1')
            ? "G:\\~dev\\rawrxd\\evidence\\DEEP2_K2_LIVE_GEN_PERF_001\\GATE_STATUS_B.txt"
            : "G:\\~dev\\rawrxd\\evidence\\DEEP2_K2_LIVE_GEN_PERF_001\\GATE_STATUS.txt";
    FILE* f = fopen(statusPath, "w");
    if (f) {
        fputs(body, f);
        fputs("GENERATED_TEXT=", f);
        for (char c : r.generatedText) {
            if (c == '\n' || c == '\r') fputc(' ', f);
            else fputc(c, f);
        }
        fputc('\n', f);
        fclose(f);
    }
    fflush(stdout);
    if (!pass) delete e;
    _exit(pass ? 0 : 2);
}
