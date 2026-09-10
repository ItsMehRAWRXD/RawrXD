// GgufDynamicGeometry_arrays.cpp — max-positive from GGUF array KV (≤99)
#include "GgufDynamicGeometry_internal.hpp"
#include <string>

namespace Deep2 {
namespace gguf_geom {

static uint32_t rdArrElem(FILE* f, uint32_t et, bool& ok) {
    switch (et) {
    case 0: { uint8_t v = 0; ok = ok && fread(&v, 1, 1, f) == 1; return v; }
    case 1: { int8_t v = 0; ok = ok && fread(&v, 1, 1, f) == 1;
              return v > 0 ? (uint32_t)v : 0; }
    case 2: { uint16_t v = 0; ok = ok && fread(&v, 2, 1, f) == 1; return v; }
    case 3: { int16_t v = 0; ok = ok && fread(&v, 2, 1, f) == 1;
              return v > 0 ? (uint32_t)v : 0; }
    case 4: return rdU32(f, ok);
    case 5: { int32_t v = 0; ok = ok && fread(&v, 4, 1, f) == 1;
              return v > 0 ? (uint32_t)v : 0; }
    case 10: {
        uint64_t v = rdU64(f, ok);
        return (ok && v > 0 && v <= 0xffffffffu) ? (uint32_t)v : 0;
    }
    case 11: {
        int64_t v = 0; ok = ok && fread(&v, 8, 1, f) == 1;
        return (ok && v > 0 && v <= 0xffffffffu) ? (uint32_t)v : 0;
    }
    default: ok = false; return 0;
    }
}

bool isPerLayerGeomArrayKey(const std::string& key) {
    return endsWith(key, "feed_forward_length") ||
           endsWith(key, "intermediate_size") ||
           endsWith(key, "attention.head_count_kv") ||
           endsWith(key, "n_head_kv");
}

/* Hybrid GGUF (nemotron_h): FFN/KV are per-layer arrays with zeros on
 * non-FFN/non-attn layers. Authority = max positive element (attested). */
bool takeArrayMaxPositive(FILE* f, Scratch& s, const std::string& key,
                          bool& ok) {
    uint32_t et = rdU32(f, ok);
    uint64_t n = rdU64(f, ok);
    if (!ok || n == 0 || n > kMaxArr) { ok = false; return false; }
    uint32_t mx = 0;
    for (uint64_t i = 0; i < n && ok; ++i) {
        uint32_t v = rdArrElem(f, et, ok);
        if (ok && v > mx) mx = v;
    }
    if (!ok) return false;
    if (mx == 0) return true; /* present but all-zero → leave unset */
    applyKey(s, key, std::to_string(mx));
    return true;
}

bool applyRopeBaseArchCompat(Scratch& s) {
    if (s.hasRopeBase && s.ropeBase > 0.f) return true;
    if (s.arch == "nemotron_h" && s.hasRopeDim && s.ropeDim > 0) {
        s.hasRopeBase = true;
        s.ropeBase = 10000.f;
        std::fprintf(stderr,
                     "ROPE_BASE_ARCH_COMPAT=1 arch=nemotron_h value=10000\n");
        return true;
    }
    return false;
}

} // namespace gguf_geom
} // namespace Deep2
