#pragma once
/* Generic kernel tune: descriptor → variants → legal → parity → wall → winner. */
#include "RawrTuneKernel.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace rawr::ktune {

struct Variant {
    const char* id = "";
    uint32_t rowsPerWG = 0;
    const char* spvName = nullptr; // nullptr ⇒ not executable yet
    bool executable = false;
};

struct Descriptor {
    const char* name = "unknown";
    const Variant* variants = nullptr;
    uint32_t variantCount = 0;
};

struct Receipt {
    const char* kernel = "";
    uint32_t rows = 0;
    uint32_t legal = 0;
    uint32_t parity = 0;
    uint32_t measureComplete = 0;
    uint64_t gpuUs = 0;
    uint64_t wallUs = 0;
    const char* status = "OPEN";
};

using ParityFn = bool (*)(uint32_t rows, const void* out, uint32_t n);
using MeasureFn = bool (*)(uint32_t rows, uint64_t* gpuUs, uint64_t* wallUs,
                           void* outScratch, uint32_t outN);
using Candidate = rawr::tune::Candidate;

inline void EmitReceipt(const Receipt& r) noexcept {
    std::printf("KERNEL=%s ROWS=%u LEGAL=%u PARITY=%u MEASURE_COMPLETE=%u "
                "GPU_TIME_US=%llu WALL_TIME_US=%llu STATUS=%s\n",
                r.kernel, r.rows, r.legal, r.parity, r.measureComplete,
                (unsigned long long)r.gpuUs, (unsigned long long)r.wallUs,
                r.status);
}

inline uint32_t CollectExecutable(const Descriptor& d, Candidate* out,
                                  uint32_t outMax, uint32_t* rowsOut) noexcept {
    uint32_t n = 0;
    for (uint32_t i = 0; i < d.variantCount && n < outMax; ++i) {
        const Variant& v = d.variants[i];
        if (!v.executable || !v.spvName || !v.rowsPerWG) continue;
        rawr::tune::MakeQkvSharedX(v.rowsPerWG, out[n].shape);
        if (rowsOut) rowsOut[n] = v.rowsPerWG;
        ++n;
    }
    return n;
}

inline uint32_t CollectAllShapes(const Descriptor& d, Candidate* out,
                                 uint32_t outMax) noexcept {
    uint32_t n = 0;
    for (uint32_t i = 0; i < d.variantCount && n < outMax; ++i) {
        rawr::tune::MakeQkvSharedX(d.variants[i].rowsPerWG, out[n].shape);
        ++n;
    }
    return n;
}

inline uint32_t MarkLegal(Candidate* c, uint32_t n,
                          const RawrGpuCaps& gpu) noexcept {
    uint32_t legalN = 0;
    for (uint32_t i = 0; i < n; ++i) {
        c[i].legal = RawrShapeLegal(&c[i].shape, &gpu) != 0;
        if (c[i].legal) ++legalN;
    }
    return legalN;
}

/*
  Generic loop. measure/parity may be null ⇒ leave OPEN (WINNER=-1).
  Never invent wall times. Never treat LEGAL as winner.
*/
inline int RunTune(const Descriptor& d, const RawrGpuCaps& gpu, MeasureFn measure,
                   ParityFn parity, void* outScratch, uint32_t outN,
                   Candidate* cands, uint32_t candMax) noexcept {
    using rawr::tune::MakeQkvSharedX;
    using rawr::tune::PickFastestValid;
    const uint32_t nAll = CollectAllShapes(d, cands, candMax);
    MarkLegal(cands, nAll, gpu);
    for (uint32_t i = 0; i < nAll; ++i) {
        Receipt r{};
        r.kernel = d.name;
        r.rows = cands[i].shape.RowsPerWG;
        r.legal = cands[i].legal ? 1u : 0u;
        r.status = "LEGAL_ONLY";
        const Variant* var = nullptr;
        for (uint32_t v = 0; v < d.variantCount; ++v) {
            if (d.variants[v].rowsPerWG == r.rows) {
                var = &d.variants[v];
                break;
            }
        }
        if (!cands[i].legal) {
            r.status = "REJECT_ILLEGAL";
            EmitReceipt(r);
            continue;
        }
        if (!var || !var->executable) {
            r.status = "NO_EXECUTABLE_VARIANT";
            EmitReceipt(r);
            continue;
        }
        if (!measure) {
            r.status = "AWAIT_MEASURE";
            EmitReceipt(r);
            continue;
        }
        uint64_t gpuUs = 0, wallUs = 0;
        if (!measure(r.rows, &gpuUs, &wallUs, outScratch, outN)) {
            r.status = "DISPATCH_FAIL";
            EmitReceipt(r);
            continue;
        }
        cands[i].gpuUs = gpuUs;
        cands[i].wallUs = wallUs;
        cands[i].measureComplete = true;
        r.gpuUs = gpuUs;
        r.wallUs = wallUs;
        r.measureComplete = 1;
        const bool ok = parity ? parity(r.rows, outScratch, outN) : false;
        cands[i].parityOk = ok;
        r.parity = ok ? 1u : 0u;
        r.status = ok ? "MEASURED_OK" : "PARITY_FAIL";
        EmitReceipt(r);
    }
    return PickFastestValid(cands, nAll);
}

} // namespace rawr::ktune
