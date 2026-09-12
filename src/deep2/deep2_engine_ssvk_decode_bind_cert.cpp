// deep2_engine_ssvk_decode_bind_cert.cpp — DEEP2_ENGINE_SSVK_DECODE_BIND_001
#include "Deep2Engine.h"
#include "Deep2Engine_SsVkDecodeBind.hpp"
#include "Deep2GpuForward.hpp"
#include "d2_engine_ssvk_decode_bind.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

using namespace Deep2;

static void WriteReceipt(const char* path, int runtime, uint64_t committed,
                         uint64_t rejected, int conj16) {
    FILE* f = nullptr;
    fopen_s(&f, path, "wb");
    if (!f) return;
    fprintf(f, "GATE=DEEP2_ENGINE_SSVK_DECODE_BIND_001\n");
    fprintf(f, "STATUS=%s\n", runtime ? (conj16 ? "PASS_16_16" : "RUNTIME_REACHED")
                                      : "SOURCE_WIRED");
    fprintf(f, "SOURCE_WIRED=1\n");
    fprintf(f, "RUNTIME_REACHED=%d\n", runtime ? 1 : 0);
    fprintf(f, "LIVE_PRODUCT_RUN=%s\n", runtime ? "RAN" : "NOT_RUN");
    fprintf(f, "TOKENS_COMMITTED=%llu\n", (unsigned long long)committed);
    fprintf(f, "TOKENS_REJECTED=%llu\n", (unsigned long long)rejected);
    fprintf(f, "WINDOW_TARGET=16\n");
    fprintf(f, "CONJUNCTION_16=%s\n", conj16 ? "PASS" : "OPEN");
    fprintf(f, "PROMOTE=0\nTIP_CLIMB=HOLD\nNOT_RUN!=PASS\n");
    fclose(f);
}

int main(int argc, char** argv) {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
    _putenv_s("RAWRXD_GPU_POLICY", "SOLO");
    _putenv_s("RAWRXD_GPU_DEVICES", "ALL");
    _putenv_s("RAWRXD_GPU_FWD", "1");
    _putenv_s("RAWRXD_Q2K_PRODUCT_DECODE", "1");
#endif
    const char* model = argc > 1 ? argv[1]
        : "G:\\~dev\\rawrxd\\llama3.2-3b-Q2_K.gguf";
    const char* receipt =
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PERFORMANCE_001\\"
        "DEEP2_ENGINE_SSVK_DECODE_BIND_001\\RECEIPT.txt";
    printf("GATE=DEEP2_ENGINE_SSVK_DECODE_BIND_001\nModel: %s\n", model);

    Deep2Engine engine;
    if (!engine.loadModel(model)) {
        printf("FAIL load\n");
        WriteReceipt(receipt, 0, 0, 0, 0);
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
        WriteReceipt(receipt, 0, 0, 0, 0);
        return 1;
    }
    engine.enableVulkan(true);
    engine.enableMedusa(false);
    GenerationOptions go{};
    go.temperature = 0; go.topK = 1; go.seed = 42;
    engine.configureGeneration(go);

    SsVkDecodeBindUser user{};
    user.engine = &engine;
    user.lastInputToken = 1; /* BOS-ish seed; model-specific */
    {
        auto toks = engine.tokenize("hi");
        if (!toks.empty()) user.lastInputToken = toks[0];
    }

    D2DecodeBindOps ops{};
    SsVkDecodeBindFillOps(&ops, &user);
    D2DecodeBind bind{};
    if (d2_decode_bind_open(&bind, &ops) != D2X_OK) {
        printf("FAIL bind_open\n");
        WriteReceipt(receipt, 0, 0, 0, 0);
        return 2;
    }

    int conj = 1;
    for (int i = 0; i < 16; ++i) {
        uint32_t tid = 0;
        const char* utf8 = nullptr;
        size_t n = 0;
        D2DecodeReceipt r{};
        int rc = d2_decode_bind_one(&bind, &tid, &utf8, &n, &r);
        printf("t=%d rc=%d tid=%u q2k_live=%u host_fwd=%u expand=%u auth=%d\n",
               i, rc, tid, r.packed_q2k_live, r.host_forward_layer_calls,
               r.cpu_f32_expands, d2_decode_receipt_authoritative(&r));
        if (rc != D2X_OK || !d2_decode_receipt_authoritative(&r)) conj = 0;
        Deep2GpuForward_Emit(nullptr, engine.gpuForwardCounters(), 0);
    }
    d2_decode_bind_close(&bind);
    WriteReceipt(receipt, 1, bind.tokens_committed, bind.rejected_tokens, conj);
    printf("TOKENS_COMMITTED=%llu CONJUNCTION_16=%s PROMOTE=0\n",
           (unsigned long long)bind.tokens_committed, conj ? "PASS" : "OPEN");
    return conj ? 0 : 3;
}
