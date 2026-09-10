#pragma once
/* Streamer mechanics receipt — prove exec, not just env request. */
#include "FreeTokenMicroZone.hpp"
#include "ParseMibBudget.hpp"
#include "Deep2DeviceManager.hpp"
#include "FutureConsumerSpace.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace Deep2 {

inline void EmitGpuEnumReceipt(FILE* f, const DeviceManagerSnapshot& snap) {
    if (!f) f = stderr;
    unsigned eligible = 0, selected = 0, igpuSel = 0;
    for (unsigned i = 0; i < snap.deviceCount; ++i) {
        const DeviceIdentity& d = snap.devices[i];
        const int discrete = d.integrated ? 0 : 1;
        if (discrete && d.score >= 10) ++eligible;
        std::fprintf(f, "GPU%u_CLASS=%s GPU%u_SCORE=%u GPU%u_NAME=%s\n",
                     i, discrete ? "DISCRETE" : "INTEGRATED",
                     i, d.score, i, d.name);
    }
    for (unsigned i = 0; i < snap.plan.openCount; ++i) {
        int idx = snap.plan.openIndexes[i];
        if (idx < 0 || (unsigned)idx >= snap.deviceCount) continue;
        ++selected;
        if (snap.devices[idx].integrated) ++igpuSel;
    }
    const char* cls = std::getenv("DEEP2_GPU_DEVICE_CLASS");
    if (!cls || !*cls) cls = std::getenv("RAWRXD_GPU_DEVICE_CLASS");
    /* DISCRETE needs 8 chars + NUL — reject any truncated env/copy path. */
    int truncated = 0;
    if (cls && *cls) {
        const size_t n = std::strlen(cls);
        if (n < 8 && (std::strncmp(cls, "DISCRETE", n) == 0) && n > 0)
            truncated = 1; /* "DISCRET" etc. */
        if (std::strcmp(cls, "DISCRETE") != 0 &&
            std::strcmp(cls, "DGPU") != 0 &&
            std::strcmp(cls, "ANY") != 0 &&
            std::strcmp(cls, "ALL") != 0) {
            /* Short needles that look like cut DISCRETE. */
            if (n > 0 && n < 8 && cls[0] == 'D') truncated = 1;
        }
    }
    std::fprintf(f,
                 "GPU_POLICY=%s\n"
                 "GPU_DEVICE_CLASS=%s\n"
                 "GPU_ENUM_COUNT=%u\n"
                 "GPU_ELIGIBLE_COUNT=%u\n"
                 "GPU_SELECTED_COUNT=%u\n"
                 "IGPU_SELECTED=%u\n"
                 "DEVICE_CLASS_TRUNCATED=%d\n",
                 std::getenv("DEEP2_GPU_POLICY")
                     ? std::getenv("DEEP2_GPU_POLICY")
                     : "?",
                 cls && *cls ? cls : "ANY",
                 snap.deviceCount, eligible, selected, igpuSel, truncated);
}

inline void EmitFreeTokenMechanics(FILE* f) {
    if (!f) f = stderr;
    using namespace freetoken;
    ZonePool& p = Pool();
    const uint64_t reuse = p.hits;
    const uint64_t ow = p.overwrites;
    const uint64_t miss = p.misses;
    const uint64_t newAlloc = p.allocsAfterInit;
    const int armed = p.live ? 1 : 0;
    const int exec = (ow > 0 || reuse > 0) ? 1 : 0;
    const int stable = (armed && newAlloc == 0) ? 1 : 0;
    std::fprintf(f,
                 "FREETOKEN_ARMED=%d\n"
                 "FREETOKEN_EXEC=%d\n"
                 "MICROZONE_ACQUIRE=%llu\n"
                 "MICROZONE_REUSE=%llu\n"
                 "MICROZONE_OVERWRITE=%llu\n"
                 "MICROZONE_MISS=%llu\n"
                 "MICROZONE_NEW_ALLOC=%llu\n"
                 "MICROZONE_NEW_ALLOC_AFTER_WARMUP=%llu\n"
                 "MICROZONE_PEAK_BYTES=%llu\n"
                 "PHYSICAL_WINDOW_STABLE=%d\n",
                 armed, exec,
                 (unsigned long long)(reuse + miss),
                 (unsigned long long)reuse,
                 (unsigned long long)ow,
                 (unsigned long long)miss,
                 (unsigned long long)newAlloc,
                 (unsigned long long)newAlloc,
                 (unsigned long long)(p.zoneBytes * FREETOKEN_ZONE_COUNT),
                 stable);
    future::EmitLaw(f);
}

inline void EmitDisposition(FILE* f, int runtimePass, uint32_t maxTok,
                            uint32_t tokens, int rc) {
    if (!f) f = stderr;
    const int productGate = (maxTok == 64u) ? 1 : 0;
    const int productPass =
        productGate && runtimePass && tokens >= 15 && rc == 0;
    std::fprintf(f,
                 "RUNTIME_DISPOSITION=%s\n"
                 "PRODUCT_DISPOSITION=%s\n"
                 "PRODUCT_GATE_64=%s\n"
                 "PRODUCT_BLOCKED_AT=%s\n"
                 "PROMOTE=%d\n",
                 runtimePass ? "PASS" : "FAIL",
                 productPass ? "PASS" : "BLOCKED",
                 productGate ? (productPass ? "PASS" : "FAIL") : "N/A",
                 productGate ? (productPass ? "NONE" : "64_TOKEN_PRODUCT_RUN")
                             : "64_TOKEN_PRODUCT_RUN",
                 0);
}

/* Survived generation: open + tokens + FutureConsumer + clean return. */
inline void EmitGenerationSurvive(FILE* f, int modelOpen, uint32_t tokens,
                                  int returnedNormally, int rc,
                                  int futureConsumerExec) {
    if (!f) f = stderr;
    const int av = 0; /* receipt reached ⇒ process did not AV before emit */
    const int survived = (modelOpen && tokens > 0 && returnedNormally &&
                          rc == 0 && futureConsumerExec && av == 0)
                             ? 1
                             : 0;
    std::fprintf(f,
                 "MODEL_OPEN=%s\nTOKENS_COMMITTED=%u\n"
                 "FUTURE_CONSUMER_EXEC=%d\n"
                 "GENERATION_RETURNED_NORMALLY=%d\n"
                 "GENERATION_SURVIVED=%d\nACCESS_VIOLATION=%d\nPROMOTE=0\n",
                 modelOpen ? "PASS" : "FAIL", tokens, futureConsumerExec,
                 returnedNormally, survived, av);
}

} // namespace Deep2
