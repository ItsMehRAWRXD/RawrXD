// roofline_locality_cert.cpp — DEEP2_ROOFLINE_LOCALITY_001 live product path
// OWNER=ROOFLINE — DualStick MULTI STRICT; measure locality; PROMOTE=0.
#include "Deep2Engine.h"
#include "Deep2RooflineLocality.hpp"
#include "GpuTransferCounters.hpp"
#include "StreamTransferCounters.hpp"
#include "lavapath/DualStickStreamWindow.hpp"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#endif
using namespace Deep2;

static uint64_t WeightUploads(const Deep2Engine& e) {
    uint64_t u = 0;
    const unsigned n = e.vulkanDeviceCount();
    for (unsigned i = 0; i < n; ++i) u += e.vulkanSlotWeightUploads(i);
    return u;
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
          "DEEP2_ROOFLINE_LOCALITY_001\\roofline_locality_live.log";
    const char* receipt = argc > 3 ? argv[3]
        : "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PERFORMANCE_001\\"
          "DEEP2_ROOFLINE_LOCALITY_001\\RECEIPT.txt";
    const uint64_t TARGET = 64;
    freopen(logPath, "w", stderr);
    printf("GATE=DEEP2_ROOFLINE_LOCALITY_001 LIVE model=%s TARGET=%llu\n",
           model, (unsigned long long)TARGET);

    RooflineLocalityMetrics m{};
    m.target = TARGET;
    m.residency_sealed = 1;
    Deep2Engine engine;
    if (!engine.loadModel(model)) {
        printf("FAIL load\n");
        RooflineLocalityWriteReceipt(receipt, m);
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
        RooflineLocalityWriteReceipt(receipt, m);
        return 1;
    }
    engine.enableVulkan(true);
    engine.enableMedusa(false);

    GenerationOptions o{};
    o.maxTokens = (uint32_t)TARGET; o.temperature = 0; o.topK = 1; o.seed = 42;
    std::vector<uint64_t> token_ns;
    token_ns.reserve((size_t)TARGET);
    uint64_t n = 0, wup_warm = 0, s0p = 0, s1p = 0, overlap = 0;
    int have_warm = 0;
    GpuTransferSnapshot g_warm{}, g_end{};
    StreamTransferSnapshot st_warm{}, st_end{};
    DualStickExec ds_warm{}, ds_end{};
    auto t_prev = std::chrono::steady_clock::now();
    const auto t0 = t_prev;
    engine.generateStream("hi", o, [&](int32_t, const std::string&) -> bool {
        const auto t_now = std::chrono::steady_clock::now();
        const uint64_t dt = (uint64_t)std::chrono::duration_cast<
            std::chrono::nanoseconds>(t_now - t_prev).count();
        t_prev = t_now;
        ++n;
        const auto& gf = engine.gpuForwardCounters();
        const uint64_t s0 = gf.forwardSlot[0];
        const uint64_t s1 = gf.forwardSlot[1];
        if (have_warm && (s0 > s0p) && (s1 > s1p)) ++overlap;
        s0p = s0; s1p = s1;
        if (!have_warm) {
            have_warm = 1;
            wup_warm = WeightUploads(engine);
            g_warm = GpuTransfer_Snapshot();
            st_warm = StreamTransfer_SnapshotRaw();
            ds_warm = DualStickState();
            return true;
        }
        token_ns.push_back(dt);
        fprintf(stderr,
            "ROOFLINE_TOKEN t=%llu dt_ns=%llu wup=%llu s0=%llu s1=%llu\n",
            (unsigned long long)n, (unsigned long long)dt,
            (unsigned long long)WeightUploads(engine),
            (unsigned long long)s0, (unsigned long long)s1);
        return true;
    });
    const auto t1 = std::chrono::steady_clock::now();
    g_end = GpuTransfer_Snapshot();
    st_end = StreamTransfer_SnapshotRaw();
    ds_end = DualStickState();
    const uint64_t wup_end = WeightUploads(engine);
    const auto& gf = engine.gpuForwardCounters();

    m.runtime = 1;
    m.generated = n;
    m.wup_d = (wup_end >= wup_warm) ? (wup_end - wup_warm) : 0;
    m.weight_local = (g_end.weightHitBytes >= g_warm.weightHitBytes)
        ? (g_end.weightHitBytes - g_warm.weightHitBytes) : 0;
    const uint64_t miss =
        ((g_end.firstLoadBytes >= g_warm.firstLoadBytes)
             ? (g_end.firstLoadBytes - g_warm.firstLoadBytes) : 0) +
        ((g_end.reloadBytes >= g_warm.reloadBytes)
             ? (g_end.reloadBytes - g_warm.reloadBytes) : 0);
    m.bytes_not_local = miss;
    m.weight_req = m.weight_local + m.bytes_not_local;
    const uint64_t win = (n > 1) ? (n - 1) : 0;
    m.bytes_not_local_pt = win ? (m.bytes_not_local / win) : 0;
    m.host_to_device = (g_end.copyBytes >= g_warm.copyBytes)
        ? (g_end.copyBytes - g_warm.copyBytes) : 0;
    m.inter_gpu = (ds_end.runtimeBytesWorked >= ds_warm.runtimeBytesWorked)
        ? (ds_end.runtimeBytesWorked - ds_warm.runtimeBytesWorked) : 0;
    m.critical_host = (st_end.bytesRead >= st_warm.bytesRead)
        ? (st_end.bytesRead - st_warm.bytesRead) : 0;
    m.gpu0_fwd = gf.forwardSlot[0];
    m.gpu1_fwd = gf.forwardSlot[1];
    m.same_token_overlap = overlap;
    m.wall_ns = (uint64_t)std::chrono::duration_cast<
        std::chrono::nanoseconds>(t1 - t0).count();
    m.token_ns_p50 = RooflinePercentileNs(token_ns, 0.50);
    m.token_ns_p95 = RooflinePercentileNs(token_ns, 0.95);
    m.tps = (m.wall_ns && n) ? (1e9 * (double)n / (double)m.wall_ns) : 0.0;
    m.dual = (engine.vulkanDeviceCount() >= 2 && m.gpu0_fwd > 0 &&
              m.gpu1_fwd > 0) ? 1 : 0;
    /* Fail-closed: 64 tokens, residency flat, dual+overlap, locality not
       model-size/token (use resident proxy: miss/token << ~1GB). */
    const uint64_t modelish = 200ull * 1024ull * 1024ull; /* 200MiB/tok bad */
    const int locality_ok = (m.bytes_not_local_pt < modelish) ? 1 : 0;
    m.pass = (n >= TARGET) && (m.wup_d == 0) && m.dual &&
             (m.same_token_overlap > 0) && locality_ok && have_warm ? 1 : 0;

    RooflineLocalityWriteReceipt(receipt, m);
    printf("TOKENS=%llu wup_d=%llu not_local_pt=%llu overlap=%llu dual=%d "
           "ROOFLINE_LOCALITY=%s PROMOTE=0\n",
           (unsigned long long)n, (unsigned long long)m.wup_d,
           (unsigned long long)m.bytes_not_local_pt,
           (unsigned long long)m.same_token_overlap, m.dual,
           m.pass ? "PASS" : "HOLD");
    fflush(stdout); fflush(stderr);
    return m.pass ? 0 : 2;
}
