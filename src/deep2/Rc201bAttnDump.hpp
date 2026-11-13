// RC2-01B measurement-only tensor dumps (no arithmetic changes).
// Env: DEEP2_01B_DUMP=1  DEEP2_01B_DIR=<abs path>  DEEP2_01B_SIDE=cpu|gpu
// Optional: DEEP2_01B_POS_LIST=0,9  (default dumps pos 0 and first decode pos)
#pragma once
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>

namespace Deep2 {
namespace Rc201b {

inline bool Enabled() noexcept {
    const char* e = std::getenv("DEEP2_01B_DUMP");
    return e && e[0] == '1';
}

inline const char* Side() noexcept {
    const char* s = std::getenv("DEEP2_01B_SIDE");
    return (s && s[0]) ? s : "unk";
}

inline const char* Dir() noexcept {
    const char* d = std::getenv("DEEP2_01B_DIR");
    return (d && d[0]) ? d : nullptr;
}

inline bool WantPos(uint32_t pos) noexcept {
    const char* list = std::getenv("DEEP2_01B_POS_LIST");
    if (!list || !list[0]) return pos == 0 || pos == 9;
    const char* p = list;
    while (*p) {
        char* end = nullptr;
        unsigned long v = std::strtoul(p, &end, 10);
        if (end == p) break;
        if (static_cast<uint32_t>(v) == pos) return true;
        p = (*end == ',') ? end + 1 : end;
    }
    return false;
}

inline void DumpF32(const char* stage, uint32_t layer, uint32_t pos,
                    const float* data, size_t n) {
    if (!Enabled() || !data || n == 0 || layer != 0 || !WantPos(pos)) return;
    const char* dir = Dir();
    if (!dir) return;
    char path[512];
    std::snprintf(path, sizeof(path), "%s\\%s_L%u_P%u_%s.f32",
                  dir, Side(), layer, pos, stage);
    FILE* f = nullptr;
#if defined(_MSC_VER)
    fopen_s(&f, path, "wb");
#else
    f = std::fopen(path, "wb");
#endif
    if (!f) return;
    std::fwrite(data, sizeof(float), n, f);
    std::fclose(f);

    double sum = 0.0, sumSq = 0.0, mx = 0.0;
    size_t nonfin = 0;
    for (size_t i = 0; i < n; ++i) {
        const float x = data[i];
        if (!std::isfinite(x)) { ++nonfin; continue; }
        const double d = static_cast<double>(x);
        sum += d;
        sumSq += d * d;
        const double a = std::fabs(d);
        if (a > mx) mx = a;
    }
    const double rms = (n > 0) ? std::sqrt(sumSq / static_cast<double>(n)) : 0.0;
    std::fprintf(stderr,
        "[01B_DUMP] side=%s stage=%s layer=%u pos=%u n=%zu maxAbs=%.6e rms=%.6e "
        "mean=%.6e nonfinite=%zu path=%s\n",
        Side(), stage, layer, pos, n, mx, rms, sum / static_cast<double>(n > 0 ? n : 1),
        nonfin, path);
    std::fflush(stderr);
}

inline void CompareFiles(const char* cpuPath, const char* gpuPath,
                         const char* label) {
    auto load = [](const char* p, std::vector<float>& o) -> bool {
        FILE* f = nullptr;
#if defined(_MSC_VER)
        fopen_s(&f, p, "rb");
#else
        f = std::fopen(p, "rb");
#endif
        if (!f) return false;
        std::fseek(f, 0, SEEK_END);
        long sz = std::ftell(f);
        std::fseek(f, 0, SEEK_SET);
        if (sz <= 0 || (sz % 4) != 0) { std::fclose(f); return false; }
        o.resize(static_cast<size_t>(sz / 4));
        const size_t n = std::fread(o.data(), 4, o.size(), f);
        std::fclose(f);
        return n == o.size();
    };
    std::vector<float> a, b;
    if (!load(cpuPath, a) || !load(gpuPath, b) || a.size() != b.size()) {
        std::fprintf(stderr, "[01B_CMP] FAIL label=%s load/size cpu=%s gpu=%s\n",
                     label, cpuPath, gpuPath);
        return;
    }
    double maxAbs = 0.0, maxRel = 0.0, sumSq = 0.0;
    size_t first = SIZE_MAX, nonfin = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        if (!std::isfinite(a[i]) || !std::isfinite(b[i])) { ++nonfin; continue; }
        const double d = std::fabs(static_cast<double>(a[i]) - b[i]);
        const double den = std::max(1e-20, std::max(std::fabs((double)a[i]),
                                                    std::fabs((double)b[i])));
        const double rel = d / den;
        if (d > maxAbs) maxAbs = d;
        if (rel > maxRel) maxRel = rel;
        sumSq += d * d;
        if (first == SIZE_MAX && d > 1e-5) first = i;
    }
    const double rms = std::sqrt(sumSq / static_cast<double>(a.size()));
    std::fprintf(stderr,
        "[01B_CMP] label=%s n=%zu maxAbs=%.6e maxRel=%.6e rms=%.6e "
        "firstDiv=%zu nonfinite=%zu\n",
        label, a.size(), maxAbs, maxRel, rms, first, nonfin);
    std::fflush(stderr);
}

} // namespace Rc201b
} // namespace Deep2
