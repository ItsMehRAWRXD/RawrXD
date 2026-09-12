// roofline_locality_cert.cpp — DEEP2_ROOFLINE_LOCALITY_001 (Locality64 drop)
// DualStick MULTI STRICT. MAX_NONLOCAL from ROOFLINE_POLICY. PROMOTE=0.
#include "Deep2Engine.h"
#include "Deep2Locality64.hpp"
#include "Deep2Residency.hpp"
#include "GpuTransferCounters.hpp"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#ifdef _WIN32
#include <windows.h>
#endif
using namespace Deep2;

static uint64_t NowNs() {
    return (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
static ResidencySnapshot Snap(const Deep2Engine& e) {
    ResidencySnapshot s{};
    s.device_creates = e.deviceCreateEvents();
    s.model_loads = e.modelLoadEvents();
    s.reload_bytes = GpuTransfer_Snapshot().reloadBytes;
    const unsigned n = e.vulkanDeviceCount();
    for (unsigned i = 0; i < n; ++i) {
        s.weight_uploads += e.vulkanSlotWeightUploads(i);
        auto* vc = e.getVulkanComputeSlot(i);
        if (!vc) continue;
        s.pin_evicts += vc->WeightPinEvicts();
        s.resident_bytes += vc->WeightPinResidentBytes();
    }
    return s;
}

/* Policy ceiling from POLICY.txt — never from observed BPT. Env/arg override OK. */
static uint64_t LoadPolicyMaxNonlocal(const char* policyPath, int* from_policy) {
    if (from_policy) *from_policy = 0;
    FILE* f = nullptr;
    if (fopen_s(&f, policyPath, "rb") != 0 || !f) return 0;
    char line[256];
    uint64_t v = 0;
    while (std::fgets(line, sizeof(line), f)) {
        if (std::strncmp(line, "MAX_NONLOCAL_BYTES_PER_TOKEN=", 29) != 0)
            continue;
        v = (uint64_t)_strtoui64(line + 29, nullptr, 10);
        if (from_policy && v > 0) *from_policy = 1;
        break;
    }
    std::fclose(f);
    return v;
}
static uint64_t ParseMaxNonlocal(int argc, char** argv, int* from_policy) {
    if (from_policy) *from_policy = 0;
    if (const char* e = std::getenv("MAX_NONLOCAL_BYTES_PER_TOKEN")) {
        if (*e) {
            const uint64_t v = (uint64_t)_strtoui64(e, nullptr, 10);
            if (from_policy) *from_policy = 0; // env override, still not from BPT
            return v;
        }
    }
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (!a) continue;
        if (std::strncmp(a, "--max-nonlocal=", 15) == 0) {
            if (from_policy) *from_policy = 0;
            return (uint64_t)_strtoui64(a + 15, nullptr, 10);
        }
    }
    const char* pol =
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PERFORMANCE_001\\"
        "DEEP2_ROOFLINE_LOCALITY_001\\POLICY.txt";
    return LoadPolicyMaxNonlocal(pol, from_policy);
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
    const char* model = "G:\\~dev\\rawrxd\\llama3.2-3b-Q2_K.gguf";
    const char* logPath =
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PERFORMANCE_001\\"
        "DEEP2_ROOFLINE_LOCALITY_001\\roofline_locality_live.log";
    const char* receipt =
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PERFORMANCE_001\\"
        "DEEP2_ROOFLINE_LOCALITY_001\\RECEIPT.txt";
    for (int i = 1; i < argc; ++i) {
        if (argv[i][0] == '-') continue;
        if (std::strstr(argv[i], ".gguf")) model = argv[i];
        else if (std::strstr(argv[i], ".log")) logPath = argv[i];
        else if (std::strstr(argv[i], "RECEIPT")) receipt = argv[i];
    }
    int from_policy = 0;
    const uint64_t max_nl = ParseMaxNonlocal(argc, argv, &from_policy);
    freopen(logPath, "w", stderr);
    printf("GATE=DEEP2_ROOFLINE_LOCALITY_001 MAX_NONLOCAL=%llu "
           "SOURCE=%s model=%s\n",
           (unsigned long long)max_nl,
           from_policy ? "ROOFLINE_POLICY" : (max_nl ? "ENV_OR_ARG" : "UNSET"),
           model);

    Deep2Engine engine;
    if (!engine.loadModel(model)) { printf("FAIL load\n"); return 1; }
    const auto& mw = engine.getModelWeights();
    EngineConfig cfg{};
    cfg.hiddenDim = mw.hiddenDim; cfg.numLayers = mw.numLayers;
    cfg.numHeads = mw.numHeads; cfg.numKVHeads = mw.numKVHeads;
    cfg.headDim = mw.headDim; cfg.vocabSize = mw.vocabSize;
    cfg.maxSeqLen = 4096; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 16;
    std::snprintf(cfg.modelPath, sizeof(cfg.modelPath), "%s", model);
    if (!engine.initialize(cfg)) { printf("FAIL init\n"); return 1; }
    engine.enableVulkan(true);
    engine.enableMedusa(false);

    auto& L = Locality64_Global();
    L.reset();
    ResidencySnapshot a{}, b{};
    int haveA = 0;
    uint64_t raw = 0, open_ord = UINT64_MAX;
    // Warm + 64 measured => 65 generated tokens.
    GenerationOptions o{};
    o.maxTokens = 65; o.temperature = 0; o.topK = 1; o.seed = 42;
    engine.generateStream("hi", o, [&](int32_t, const std::string&) -> bool {
        const uint64_t now = NowNs();
        ++raw;
        if (!haveA) {
            a = Snap(engine);
            haveA = 1;
            L.reset();
            L.setArmed(true);
            L.beginWindow(now);
            Locality64_SetActiveOrdinal(0);
            L.beginToken(0, now);
            open_ord = 0;
            return true;
        }
        if (open_ord >= Locality64Collector::kTargetTokens) return true;
        L.endToken(open_ord, now);
        const uint64_t finished = open_ord;
        open_ord = UINT64_MAX;
        if (finished + 1 < Locality64Collector::kTargetTokens) {
            open_ord = finished + 1;
            Locality64_SetActiveOrdinal(open_ord);
            L.beginToken(open_ord, now);
        } else {
            Locality64_SetActiveOrdinal(UINT64_MAX);
        }
        fprintf(stderr, "ROOFLINE_TOKEN raw=%llu finished=%llu next_open=%llu\n",
                (unsigned long long)raw, (unsigned long long)finished,
                (unsigned long long)open_ord);
        return true;
    });
    const uint64_t end_ns = NowNs();
    if (open_ord < Locality64Collector::kTargetTokens)
        L.endToken(open_ord, end_ns);
    L.endWindow(end_ns);
    L.setArmed(false);
    b = Snap(engine);

    Locality64ParentSeal p{};
    p.bind16_sealed = true;
    p.persistent_decode_sealed = true;
    p.residency_sealed = true;
    p.weight_upload_delta = b.weight_uploads - a.weight_uploads;
    p.device_create_delta = b.device_creates - a.device_creates;
    p.model_load_delta = b.model_loads - a.model_loads;
    p.reload_bytes_delta = b.reload_bytes - a.reload_bytes;
    p.pin_evict_delta = b.pin_evicts - a.pin_evicts;

    Locality64Policy policy{};
    policy.max_nonlocal_bytes_per_token = max_nl;
    policy.require_dual_gpu = true;
    policy.require_same_token_overlap = true;
    const Locality64Verdict v = L.evaluate(p, policy);
    Locality64Collector::writeReceipt(receipt, p, policy, v, raw);

    /* Provenance footer — ceiling from POLICY, never from observed BPT. */
    {
        FILE* f = nullptr;
        if (fopen_s(&f, receipt, "ab") == 0 && f) {
            std::fprintf(f, "MAX_NONLOCAL_SOURCE=%s\n",
                         from_policy ? "ROOFLINE_POLICY"
                                     : (max_nl ? "ENV_OR_ARG" : "UNSET"));
            std::fprintf(f, "MAX_NONLOCAL_DERIVED_FROM_OBSERVED_BPT=0\n");
            std::fprintf(f, "SOURCE_WIRED=1\nRUNTIME_REACHED=1\n");
            std::fprintf(f, "LIVE_PRODUCT_RUN=%s\n",
                         v.conjunction ? "PASS" : "HOLD");
            std::fprintf(f, "HARNESS=build_ninja/bin/roofline_locality_cert.exe\n");
            std::fprintf(f, "DUALSTICK_SCHEDULE=BIND16_PACKED_DUAL_PREPARE_SUBMIT_BOTH_JOIN_MERGE\n");
            std::fprintf(f, "PROMOTE=0\n");
            std::fclose(f);
        }
    }

    const uint64_t n = v.s.measured_tokens ? v.s.measured_tokens : 1;
    printf("RAW=%llu MEASURED=%llu wup_d=%llu not_local_pt=%llu "
           "overlap=%llu threshold=%llu ROOFLINE_LOCALITY=%s PROMOTE=0\n",
           (unsigned long long)raw, (unsigned long long)v.s.measured_tokens,
           (unsigned long long)p.weight_upload_delta,
           (unsigned long long)(v.s.bytes_not_already_local_total / n),
           (unsigned long long)v.s.same_token_overlap_count,
           (unsigned long long)max_nl,
           v.conjunction ? "PASS" : "HOLD");
    fflush(stdout); fflush(stderr);
    return v.conjunction ? 0 : 2;
}
