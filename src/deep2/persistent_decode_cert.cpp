// persistent_decode_cert.cpp — DEEP2_PERSISTENT_DECODE_001 live product path
// OWNER=PERSISTENT_DECODE — DualStick MULTI STRICT; do not switch to SOLO.
#include "Deep2Engine.h"
#include "Deep2PersistentContinuity.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#ifdef _WIN32
#include <windows.h>
#endif
using namespace Deep2;

static void WriteReceipt(const char* path, int runtime, int pass,
                         const PersistentContinuity& pc, uint64_t n,
                         uint64_t d0, uint64_t m0, uint64_t c0, uint64_t r0,
                         uint64_t d1, uint64_t m1, uint64_t c1, uint64_t r1,
                         int bind_auth, unsigned bind_pass,
                         int gpu_res, int dual_armed) {
    FILE* f = nullptr;
    fopen_s(&f, path, "wb");
    if (!f) return;
    const int same = (n >= 17) ? 1 : 0;
    const int no_dev = (d1 == d0) ? 1 : 0;
    const int no_model = (m1 == m0) ? 1 : 0;
    const int no_graph = (c1 == c0) ? 1 : 0;
    const int no_seal = (r1 == r0 && pc.sealed_logits_reuse_events == 0) ? 1 : 0;
    const int ssvk = (bind_auth && bind_pass >= 16) ? 1 : 0;
    const int resid = gpu_res ? 1 : 0;
    const int kv = (pc.kv_regressions == 0 && pc.n_gt0_tokens >= 16) ? 1 : 0;
    const int win = (pc.n_gt0_pass >= 16) ? 1 : 0;
    const int conj = pass && same && no_dev && no_model && no_graph && no_seal &&
                     ssvk && resid && kv && win && dual_armed &&
                     (pc.dualstick_reset_events == 0);
    fprintf(f, "GATE=DEEP2_PERSISTENT_DECODE_001\n");
    fprintf(f, "STATUS=%s\n", conj ? "LIVE_PRODUCT_PASS" :
            (runtime ? "RUNTIME_HOLD" : "SOURCE_WIRED"));
    fprintf(f, "SOURCE_WIRED=1\n");
    fprintf(f, "RUNTIME_REACHED=%d\n", runtime ? 1 : 0);
    fprintf(f, "LIVE_PRODUCT_RUN=%s\n",
            conj ? "PASS" : (runtime ? "HOLD" : "NOT_RUN"));
    fprintf(f, "SAME_PROCESS_MULTI_TOKEN=%d\n", same);
    fprintf(f, "NO_PER_TOKEN_DEVICE_RECREATE=%d\n", no_dev);
    fprintf(f, "NO_PER_TOKEN_MODEL_REOPEN=%d\n", no_model);
    fprintf(f, "NO_PER_TOKEN_GRAPH_REBUILD=%d\n", no_graph);
    fprintf(f, "NO_SEALED_LOGITS_REUSE=%d\n", no_seal);
    fprintf(f, "PRODUCT_SSVK_PATH_RETAINED=%d\n", ssvk);
    fprintf(f, "GPU_RESIDENCY_RETAINED=%d\n", resid);
    fprintf(f, "TOKEN_TO_TOKEN_STATE_CONTINUITY=%s\n",
            kv ? "PASS" : "FAIL");
    fprintf(f, "PERSISTENT_DECODE_WINDOW=%s\n", win ? "PASS" : "HOLD");
    fprintf(f, "PERSISTENT_DECODE=%s\n", conj ? "PASS" : "HOLD");
    fprintf(f, "N_GT0_PASS=%llu/16 TOKENS=%llu\n",
            (unsigned long long)pc.n_gt0_pass, (unsigned long long)n);
    fprintf(f, "DEVICE_CREATE_DELTA=%llu MODEL_LOAD_DELTA=%llu\n",
            (unsigned long long)(d1 - d0), (unsigned long long)(m1 - m0));
    fprintf(f, "CMD_REBUILD_DELTA=%llu SEALED_DELTA=%llu DS_RESET=%llu\n",
            (unsigned long long)(c1 - c0), (unsigned long long)(r1 - r0),
            (unsigned long long)pc.dualstick_reset_events);
    fprintf(f, "BIND16_WINDOW_AUTHORITY=%d pass=%u\n", bind_auth, bind_pass);
    fprintf(f, "DUALSTICK_ARMED=%d\n", dual_armed);
    fprintf(f, "VERIFY=%s\n", conj ? "PASS" : "HOLD");
    fprintf(f, "PROMOTE=0\nTIP_CLIMB=HOLD\n");
    fprintf(f, "NEXT=%s\n", conj ? "RESIDENCY" : "PERSISTENT_DECODE");
    fprintf(f, "NOT_RUN!=PASS\n");
    fclose(f);
}

int main(int argc, char** argv) {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "2048");
    _putenv_s("RAWRXD_GPU_POLICY", "MULTI");
    _putenv_s("RAWRXD_GPU_DEVICES", "ALL");
    _putenv_s("RAWRXD_GPU_FWD", "1");
    _putenv_s("RAWRXD_ALLOW_GPU", "1");
    _putenv_s("DEEP2_DUALSTICK_ARM", "1");
    _putenv_s("RAWRXD_DEEP2_SSVK_PRODUCT_STRICT", "1");
    _putenv_s("RAWRXD_DEEP2_GPU_RESIDENT_STRICT", "1");
    _putenv_s("RAWRXD_Q2K_PRODUCT_DECODE", "1");
    _putenv_s("DEEP2_WEIGHT_PREFETCH", "0");
#endif
    const char* model = argc > 1 ? argv[1]
        : "G:\\~dev\\rawrxd\\llama3.2-3b-Q2_K.gguf";
    const char* logPath = argc > 2 ? argv[2]
        : "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PERFORMANCE_001\\"
          "DEEP2_PERSISTENT_DECODE_001\\persistent_decode_live.log";
    const char* receipt = argc > 3 ? argv[3]
        : "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PERFORMANCE_001\\"
          "DEEP2_PERSISTENT_DECODE_001\\RECEIPT.txt";
    freopen(logPath, "w", stderr);
    printf("GATE=DEEP2_PERSISTENT_DECODE_001 LIVE model=%s\n", model);

    Deep2Engine engine;
    if (!engine.loadModel(model)) {
        printf("FAIL load\n");
        WriteReceipt(receipt, 0, 0, engine.persistentContinuity(), 0,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return 1;
    }
    const auto& mw = engine.getModelWeights();
    EngineConfig cfg{};
    cfg.hiddenDim = mw.hiddenDim; cfg.numLayers = mw.numLayers;
    cfg.numHeads = mw.numHeads; cfg.numKVHeads = mw.numKVHeads;
    cfg.headDim = mw.headDim; cfg.vocabSize = mw.vocabSize;
    cfg.maxSeqLen = 4096; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 16;
    std::snprintf(cfg.modelPath, sizeof(cfg.modelPath), "%s", model);
    if (!engine.initialize(cfg)) {
        printf("FAIL init\n");
        WriteReceipt(receipt, 0, 0, engine.persistentContinuity(), 0,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return 1;
    }
    engine.enableVulkan(true);
    engine.enableMedusa(false);

    const uint64_t d0 = engine.deviceCreateEvents();
    const uint64_t m0 = engine.modelLoadEvents();
    const uint64_t c0 = engine.commandRebuildEvents();
    const uint64_t r0 = engine.sealedLogitsReuseEvents();

    GenerationOptions o{};
    o.maxTokens = 17; o.temperature = 0; o.topK = 1; o.seed = 42;
    size_t n = 0;
    engine.generateStream("hi", o, [&](int32_t, const std::string&) -> bool {
        ++n; return true;
    });

    const uint64_t d1 = engine.deviceCreateEvents();
    const uint64_t m1 = engine.modelLoadEvents();
    const uint64_t c1 = engine.commandRebuildEvents();
    const uint64_t r1 = engine.sealedLogitsReuseEvents();
    const D2Bind16Window* w = engine.ssVkDecodeBindWindow();
    const int auth = (w && w->authority) ? 1 : 0;
    const unsigned pass = w ? w->tokens_pass : 0u;
    const auto& pc = engine.persistentContinuity();
    const auto& gf = engine.gpuForwardCounters();
    const int gpu_res = engine.gpuResidentDecodeEnabled() ? 1 : 0;
    /* BIND16 commit already requires slot0/slot1 deltas; do not require
       DualStickState().armed after teardown — use live slot counters. */
    const int dual =
        (engine.vulkanDeviceCount() >= 2 && gf.forwardSlot[0] > 0 &&
         gf.forwardSlot[1] > 0)
            ? 1
            : 0;
    const int conj =
        (n >= 17) && (d1 == d0) && (m1 == m0) && (c1 == c0) && (r1 == r0) &&
        auth && (pass >= 16) && gpu_res && dual &&
        (pc.n_gt0_pass >= 16) && (pc.kv_regressions == 0) &&
        (pc.dualstick_reset_events == 0) &&
        (pc.sealed_logits_reuse_events == 0);

    WriteReceipt(receipt, 1, conj ? 1 : 0, pc, n, d0, m0, c0, r0, d1, m1, c1, r1,
                 auth, pass, gpu_res, dual);
    printf("TOKENS=%zu BIND16=%d pass=%u N_GT0=%llu conj=%d PROMOTE=0\n",
           n, auth, pass, (unsigned long long)pc.n_gt0_pass, conj);
    fflush(stdout); fflush(stderr);
    return conj ? 0 : 2;
}
