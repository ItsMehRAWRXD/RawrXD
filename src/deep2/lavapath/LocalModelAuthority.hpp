#pragma once
/* ONE_LOCAL_MODEL_AUTHORITY — GGUF → dynamic geometry (fail-closed). ≤99. */
#include "../GGUFLoader.hpp"
#include <cstdlib>
#include <string>

namespace rawr::olma {

struct GeomSeal {
    int GGUF_MAGIC_OK = 0;
    uint32_t GGUF_VERSION = 0;
    uint64_t GGUF_TENSOR_COUNT = 0;
    uint64_t GGUF_METADATA_COUNT = 0;
    std::string ARCH, MODEL_NAME, BLOCKED_AT, REASON;
    std::string FIRST_DELTA = "TENSOR_NAME_TYPE_BINDING";
    uint32_t LAYERS = 0, HIDDEN = 0, FFN = 0, HEADS = 0, KV_HEADS = 0;
    uint32_t HEAD_DIM = 0, CONTEXT = 0, ROPE_DIM = 0;
    float RMS_EPS = 0.f, ROPE_BASE = 0.f, ROPE_SCALING = 0.f;
    int ROPE_SCALING_PRESENT = 0;
    int NO_STATIC_MODEL_GEOMETRY = 1;
    int METADATA_BOUNDS_CHECKED = 0;
    int GEOMETRY_SELF_CONSISTENT = 0;
    int ONE_LOCAL_MODEL_AUTHORITY = 1;
    int PASS = 0;
    size_t TENSOR_BINDABLE_COUNT = 0;
};

inline void Block(GeomSeal& g, const char* at, const std::string& why, const char* d) {
    g.PASS = 0;
    g.BLOCKED_AT = at;
    g.REASON = why;
    g.FIRST_DELTA = d;
}

inline bool ArchKey(const Deep2::GGUFLoadResult& r, const char* suf, std::string* k) {
    if (r.metadata.architecture.empty() || !suf) return false;
    std::string key = r.metadata.architecture + "." + suf;
    if (!r.rawKv.count(key)) return false;
    if (k) *k = key;
    return true;
}

inline bool ParseU32(const std::string& s, uint32_t& o) {
    char* e = nullptr;
    unsigned long v = std::strtoul(s.c_str(), &e, 10);
    if (!e || e == s.c_str() || *e || v == 0 || v > 0xFFFFFFFFul) return false;
    o = (uint32_t)v;
    return true;
}

inline bool ParseF32(const std::string& s, float& o) {
    char* e = nullptr;
    o = std::strtof(s.c_str(), &e);
    return e && e != s.c_str() && !*e && o > 0.f;
}

inline bool ReqU32(const Deep2::GGUFLoadResult& r, const char* suf, uint32_t& dst, GeomSeal& g,
                   const char* tag) {
    std::string k;
    if (!ArchKey(r, suf, &k)) {
        Block(g, tag, std::string("missing ") + r.metadata.architecture + "." + suf,
              "GGUF_METADATA_KV");
        return false;
    }
    if (!ParseU32(r.rawKv.at(k), dst)) {
        Block(g, tag, "invalid u32 " + k, "GGUF_METADATA_BOUNDS");
        return false;
    }
    return true;
}

inline bool ReqF32(const Deep2::GGUFLoadResult& r, const char* suf, float& dst, GeomSeal& g,
                   const char* tag) {
    std::string k;
    if (!ArchKey(r, suf, &k)) {
        Block(g, tag, std::string("missing ") + r.metadata.architecture + "." + suf,
              "GGUF_METADATA_KV");
        return false;
    }
    if (!ParseF32(r.rawKv.at(k), dst)) {
        Block(g, tag, "invalid f32 " + k, "GGUF_METADATA_BOUNDS");
        return false;
    }
    return true;
}

/* Gemma3 dual-rope: global/local.freq_base when rope.freq_base absent. */
inline bool ReqRopeBase(const Deep2::GGUFLoadResult& r, float& dst, GeomSeal& g) {
    std::string k;
    for (const char* suf :
         {"rope.freq_base", "rope.global.freq_base", "rope.local.freq_base"}) {
        if (ArchKey(r, suf, &k) && ParseF32(r.rawKv.at(k), dst)) return true;
    }
    Block(g, "ROPE_BASE", "missing rope.freq_base|global|local", "GGUF_METADATA_KV");
    return false;
}

bool SealFromLoad(const Deep2::GGUFLoadResult& r, GeomSeal& g);
bool SealFromPath(const char* path, GeomSeal& g);
void Emit(FILE* f, const GeomSeal& g);

} // namespace rawr::olma
