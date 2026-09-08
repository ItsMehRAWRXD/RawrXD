#pragma once
/* GE = Geometry Engine: geometry → bounded occupancy. Complexity-blind. */
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <climits>

namespace rawr::ge {

struct DeviceCaps {
    uint32_t cuCount = 0;                // 0 = unknown
    uint32_t waveSize = 64;
    uint32_t maxResidentWavesPerCU = 32;
    uint32_t ldsBytesPerCU = 65536;
    uint32_t vgprBudgetPerCU = 0;        // 0 = unknown
};

struct KernelDesc {
    const char* name = "unknown";
    uint32_t rows = 0;
    uint32_t cols = 0;
    uint32_t rowsPerWG = 1;
    uint32_t localSize = 256;
    uint32_t sharedBytesPerWG = 0;
    uint32_t vgprPerThread = 0; // 0 = unknown
};

struct Receipt {
    uint32_t totalWorkgroups = 0;
    uint32_t wavesPerWG = 0;
    uint32_t wgLimitByWaves = 0;
    uint32_t wgLimitByLds = 0;
    uint32_t wgLimitByRegs = 0;
    uint32_t residentWGMin = 0;
    uint32_t residentWGMax = 0;
    double theoreticalOccMin = 0.0;
    double theoreticalOccMax = 0.0;
    double gridSatMin = 0.0;
    double gridSatMax = 0.0;
    const char* occClass = "GEOMETRIC_ONLY";
};

inline uint32_t CeilDiv(uint32_t a, uint32_t b) noexcept {
    return b ? ((a + b - 1u) / b) : 0u;
}

inline double Clamp01(double x) noexcept {
    return x < 0.0 ? 0.0 : (x > 1.0 ? 1.0 : x);
}

inline Receipt Compute(const DeviceCaps& d, const KernelDesc& k) noexcept {
    Receipt r{};
    const uint32_t rpw = (std::max)(1u, k.rowsPerWG);
    const uint32_t ls = (std::max)(1u, k.localSize);
    const uint32_t ws = (std::max)(1u, d.waveSize);
    r.totalWorkgroups = CeilDiv(k.rows, rpw);
    r.wavesPerWG = CeilDiv(ls, ws);
    if (d.maxResidentWavesPerCU && r.wavesPerWG)
        r.wgLimitByWaves =
            (std::max)(1u, d.maxResidentWavesPerCU / r.wavesPerWG);
    if (d.ldsBytesPerCU) {
        r.wgLimitByLds = k.sharedBytesPerWG
                             ? (std::max)(1u, d.ldsBytesPerCU / k.sharedBytesPerWG)
                             : (r.wgLimitByWaves ? r.wgLimitByWaves : 1u);
    }
    if (d.vgprBudgetPerCU && k.vgprPerThread) {
        const uint64_t regs =
            uint64_t(k.vgprPerThread) * uint64_t(ls);
        if (regs)
            r.wgLimitByRegs =
                (std::max)(1u, uint32_t(d.vgprBudgetPerCU / regs));
    }
    uint32_t known = UINT32_MAX;
    auto app = [&](uint32_t v) {
        if (v) known = (std::min)(known, v);
    };
    app(r.wgLimitByWaves);
    app(r.wgLimitByLds);
    app(r.wgLimitByRegs);
    if (known == UINT32_MAX) {
        r.residentWGMin = 1;
        r.residentWGMax = 1;
        r.occClass = "GEOMETRIC_ONLY";
    } else {
        r.residentWGMax = (std::max)(1u, known);
        if (!r.wgLimitByRegs) {
            r.residentWGMin = 1;
            r.occClass = "BOUNDED";
        } else {
            r.residentWGMin = r.residentWGMax;
            r.occClass = "EXACT";
        }
    }
    if (d.maxResidentWavesPerCU && r.wavesPerWG) {
        r.theoreticalOccMin = Clamp01(double(r.residentWGMin * r.wavesPerWG) /
                                      double(d.maxResidentWavesPerCU));
        r.theoreticalOccMax = Clamp01(double(r.residentWGMax * r.wavesPerWG) /
                                      double(d.maxResidentWavesPerCU));
    }
    if (d.cuCount) {
        const double cMin =
            double(d.cuCount) * double((std::max)(1u, r.residentWGMin));
        const double cMax =
            double(d.cuCount) * double((std::max)(1u, r.residentWGMax));
        r.gridSatMin = Clamp01(double(r.totalWorkgroups) / cMin);
        r.gridSatMax = Clamp01(double(r.totalWorkgroups) / cMax);
    }
    return r;
}

inline void Emit(const DeviceCaps& d, const KernelDesc& k,
                 const Receipt& r) noexcept {
    std::printf("GE_BEGIN\nGE=1 GEOMETRY_ONLY=1 COMPLEXITY_USED=0\n");
    std::printf("FULL_MODEL_LOAD=0 GENERATE_REQUIRED=0 "
                "TENSOR_BYTES_REQUIRED=0\n");
    std::printf("KERNEL_NAME=%s\nROWS=%u COLS=%u ROWS_PER_WG=%u "
                "LOCAL_SIZE=%u WAVE_SIZE=%u\n",
                k.name, k.rows, k.cols, k.rowsPerWG, k.localSize, d.waveSize);
    std::printf("TOTAL_WORKGROUPS=%u WAVES_PER_WG=%u "
                "SHARED_BYTES_PER_WG=%u\n",
                r.totalWorkgroups, r.wavesPerWG, k.sharedBytesPerWG);
    std::printf("CU_COUNT_KNOWN=%u LDS_CAP_KNOWN=%u REG_CAP_KNOWN=%u\n",
                d.cuCount ? 1u : 0u, d.ldsBytesPerCU ? 1u : 0u,
                (d.vgprBudgetPerCU && k.vgprPerThread) ? 1u : 0u);
    std::printf("WG_LIMIT_BY_WAVES=%u WG_LIMIT_BY_LDS=%u\n", r.wgLimitByWaves,
                r.wgLimitByLds);
    if (r.wgLimitByRegs)
        std::printf("WG_LIMIT_BY_REG=%u\n", r.wgLimitByRegs);
    else
        std::printf("WG_LIMIT_BY_REG=UNKNOWN\n");
    std::printf("RESIDENT_WG_PER_CU_MIN=%u RESIDENT_WG_PER_CU_MAX=%u\n",
                r.residentWGMin, r.residentWGMax);
    std::printf("THEORETICAL_OCCUPANCY_MIN=%.3f "
                "THEORETICAL_OCCUPANCY_MAX=%.3f\n",
                r.theoreticalOccMin, r.theoreticalOccMax);
    std::printf("GRID_SATURATION_MIN=%.3f GRID_SATURATION_MAX=%.3f\n",
                r.gridSatMin, r.gridSatMax);
    std::printf("OCCUPANCY_CLASS=%s OCCUPANCY_RECEIPT=PASS\n", r.occClass);
    std::printf("WALL_LANGUAGE=GEOMETRY GE_END\n");
}

} // namespace rawr::ge
