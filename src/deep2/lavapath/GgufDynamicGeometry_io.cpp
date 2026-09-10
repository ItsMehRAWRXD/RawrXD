// GgufDynamicGeometry_io.cpp — bounds-checked GGUF header + KV I/O
#include "GgufDynamicGeometry_internal.hpp"
#include <cstdio>
#include <cstring>

namespace Deep2 {
namespace gguf_geom {

uint32_t rdU32(FILE* f, bool& ok) {
    uint32_t v = 0;
    if (fread(&v, 1, 4, f) != 4) ok = false;
    return v;
}
uint64_t rdU64(FILE* f, bool& ok) {
    uint64_t v = 0;
    if (fread(&v, 1, 8, f) != 8) ok = false;
    return v;
}
float rdF32(FILE* f, bool& ok) {
    float v = 0;
    if (fread(&v, 1, 4, f) != 4) ok = false;
    return v;
}
double rdF64(FILE* f, bool& ok) {
    double v = 0;
    if (fread(&v, 1, 8, f) != 8) ok = false;
    return v;
}

std::string rdStr(FILE* f, bool& ok) {
    uint64_t n = rdU64(f, ok);
    if (!ok || n > kMaxStr) { ok = false; return {}; }
    std::string s;
    s.resize(static_cast<size_t>(n));
    if (n && fread(&s[0], 1, (size_t)n, f) != n) { ok = false; return {}; }
    return s;
}

bool skipVal(FILE* f, uint32_t t, bool& ok) {
    switch (t) {
    case 0: case 1: case 7: return fseek(f, 1, SEEK_CUR) == 0;
    case 2: case 3: return fseek(f, 2, SEEK_CUR) == 0;
    case 4: case 5: case 6: return fseek(f, 4, SEEK_CUR) == 0;
    case 8: (void)rdStr(f, ok); return ok;
    case 9: {
        uint32_t et = rdU32(f, ok);
        uint64_t n = rdU64(f, ok);
        if (!ok || n > kMaxArr) { ok = false; return false; }
        for (uint64_t i = 0; i < n && ok; ++i)
            if (!skipVal(f, et, ok)) return false;
        return ok;
    }
    case 10: case 11: case 12: return fseek(f, 8, SEEK_CUR) == 0;
    default: ok = false; return false;
    }
}

bool endsWith(const std::string& s, const char* suf) {
    size_t n = std::strlen(suf);
    return s.size() >= n && s.compare(s.size() - n, n, suf) == 0;
}

bool isBlockCountKey(const std::string& key) {
    if (key.find("leading_dense_block_count") != std::string::npos)
        return false;
    if (key.find("dense_block_count") != std::string::npos)
        return false;
    return key == "block_count" || endsWith(key, ".block_count") ||
           key == "n_layer" || endsWith(key, ".n_layer");
}

bool isHeadCountKey(const std::string& k) {
    if (endsWith(k, "attention.head_count_kv")) return false;
    return endsWith(k, "attention.head_count") ||
           endsWith(k, ".n_head") || k == "n_head";
}

} // namespace gguf_geom
} // namespace Deep2
