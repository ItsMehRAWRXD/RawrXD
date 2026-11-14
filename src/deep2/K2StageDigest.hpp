#pragma once
/* K2 stage-digest API used by K2NativeStreamGate (mirrors B3_StageDigest). */
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>

namespace Deep2 {
namespace k2_digest {

inline bool Enabled() {
    static const bool on = (std::getenv("RAWRXD_STAGE_DIGEST") != nullptr);
    return on;
}

inline void NoteWiredOnce() {
    static bool noted = false;
    if (noted || !Enabled()) return;
    noted = true;
    std::printf("[STAGE_DIGEST] side=deep2 key=K2_DIGEST_WIRED once=1 PROMOTE=0\n");
    std::fflush(stdout);
}

inline bool DumpLayer(uint32_t layer) {
    if (!Enabled()) return false;
    if (layer <= 2u) return true;
    if (const char* p = std::getenv("RAWRXD_STAGE_DUMP_MAX_LAYER")) {
        if ((int)layer <= std::atoi(p)) return true;
    }
    return false;
}

inline void Emit(const char* key, size_t pos, const float* data, size_t n) {
    if (!Enabled() || !key || !data || n == 0) return;
    double minV = 0, maxV = 0, ss = 0, sum = 0, maxAbs = 0;
    bool any = false;
    uint64_t h = 14695981039346656037ull;
    int nf = 0;
    for (size_t i = 0; i < n; ++i) {
        const float v = data[i];
        uint32_t bits = 0;
        if (!std::isfinite(v)) {
            ++nf;
            bits = 0xFFFFFFFFu;
        } else {
            std::memcpy(&bits, &v, 4);
            const double d = (double)v;
            if (!any) { minV = maxV = d; any = true; }
            else { if (d < minV) minV = d; if (d > maxV) maxV = d; }
            sum += d; ss += d * d;
            const double a = (d < 0) ? -d : d;
            if (a > maxAbs) maxAbs = a;
        }
        for (int b = 0; b < 4; ++b) {
            h ^= (bits >> (8 * b)) & 0xFFu;
            h *= 1099511628211ull;
        }
    }
    std::printf("[STAGE_DIGEST] side=deep2 key=%s pos=%zu n=%zu l2=%.9e "
                "max_abs=%.9e min=%.9e max=%.9e sum=%.9e fnv=%016llx nf=%d\n",
                key, pos, n, std::sqrt(ss), maxAbs, minV, maxV, sum,
                (unsigned long long)h, nf);
    std::fflush(stdout);
}

} // namespace k2_digest
} // namespace Deep2
