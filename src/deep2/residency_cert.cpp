// residency_cert.cpp — DEEP2_RESIDENCY_001 live product path
// OWNER=RESIDENCY — DualStick MULTI STRICT; prove residency across decode.
#include "Deep2Engine.h"
#include "Deep2Residency.hpp"
#include "GpuTransferCounters.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#ifdef _WIN32
#include <windows.h>
#endif
using namespace Deep2;

static ResidencySnapshot Snap(const Deep2Engine& e) {
    ResidencySnapshot s{};
    s.device_creates = e.deviceCreateEvents();
    s.model_loads = e.modelLoadEvents();
    s.reload_bytes = GpuTransfer_Snapshot().reloadBytes;
    const unsigned n = e.vulkanDeviceCount();
    for (unsigned i = 0; i < n; ++i) {
        s.weight_uploads += e.vulkanSlotWeightUploads(i);
        s.weight_hits += e.vulkanSlotWeightHits(i);
        auto* vc = e.getVulkanComputeSlot(i);
        if (!vc) continue;
        s.content_hits += vc->WeightContentHits();
        s.pin_evicts += vc->WeightPinEvicts();
        s.pin_rejects += vc->WeightPinRejects();
        s.resident_bytes += vc->WeightPinResidentBytes();
    }
    return s;
}

int main(int argc, char** argv) {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "2048");
    _putenv_s("DEEP2_WEIGHT_PIN", "1");
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
          "DEEP2_RESIDENCY_001\\residency_live.log";
    const char* receipt = argc > 3 ? argv[3]
        : "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PERFORMANCE_001\\"
          "DEEP2_RESIDENCY_001\\RECEIPT.txt";
    freopen(logPath, "w", stderr);
    printf("GATE=DEEP2_RESIDENCY_001 LIVE model=%s\n", model);

    Deep2Engine engine;
    if (!engine.loadModel(model)) {
        printf("FAIL load\n");
        ResidencyWriteReceipt(receipt, 0, 0, 0, {}, {}, 0, 0, 0, 0);
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
        ResidencyWriteReceipt(receipt, 0, 0, 0, {}, {}, 0, 0, 0, 0);
        return 1;
    }
    engine.enableVulkan(true);
    engine.enableMedusa(false);

    ResidencySnapshot a{};
    int haveA = 0;
    size_t n = 0;
    GenerationOptions o{};
    o.maxTokens = 17; o.temperature = 0; o.topK = 1; o.seed = 42;
    engine.generateStream("hi", o, [&](int32_t, const std::string&) -> bool {
        ++n;
        if (!haveA) { a = Snap(engine); haveA = 1; }
        return true;
    });
    const ResidencySnapshot b = Snap(engine);
    const D2Bind16Window* w = engine.ssVkDecodeBindWindow();
    const int auth = (w && w->authority) ? 1 : 0;
    const unsigned passN = w ? w->tokens_pass : 0u;
    const auto& gf = engine.gpuForwardCounters();
    const int gpu_res = engine.gpuResidentDecodeEnabled() ? 1 : 0;
    const int dual =
        (engine.vulkanDeviceCount() >= 2 && gf.forwardSlot[0] > 0 &&
         gf.forwardSlot[1] > 0) ? 1 : 0;
    const int no_dev = (b.device_creates == a.device_creates) ? 1 : 0;
    const int no_model = (b.model_loads == a.model_loads) ? 1 : 0;
    const int no_wup = (b.weight_uploads == a.weight_uploads) ? 1 : 0;
    const int no_reload = (b.reload_bytes == a.reload_bytes) ? 1 : 0;
    const int no_evict = (b.pin_evicts == a.pin_evicts) ? 1 : 0;
    const int conj =
        haveA && (n >= 17) && no_dev && no_model && no_wup && no_reload &&
        no_evict && auth && (passN >= 16) && gpu_res && dual &&
        (b.resident_bytes > 0);

    ResidencyWriteReceipt(receipt, 1, conj ? 1 : 0, n, a, b, auth, passN,
                          gpu_res, dual);
    printf("TOKENS=%zu BIND16=%d pass=%u wup_d=%llu reload_d=%llu "
           "res_B=%llu conj=%d PROMOTE=0\n",
           n, auth, passN,
           (unsigned long long)(b.weight_uploads - a.weight_uploads),
           (unsigned long long)(b.reload_bytes - a.reload_bytes),
           (unsigned long long)b.resident_bytes, conj);
    printf("CONJ_OPS haveA=%d n17=%d no_dev=%d no_model=%d no_wup=%d "
           "no_reload=%d no_evict=%d auth=%d pass16=%d gpu_res=%d dual=%d "
           "res_B_gt0=%d\n",
           haveA, (n >= 17) ? 1 : 0, no_dev, no_model, no_wup, no_reload,
           no_evict, auth, (passN >= 16) ? 1 : 0, gpu_res, dual,
           (b.resident_bytes > 0) ? 1 : 0);
    fflush(stdout); fflush(stderr);
    return conj ? 0 : 2;
}
