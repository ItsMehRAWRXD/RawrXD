#pragma once
/* Emit GeomSeal receipt. ≤99. */
#include "LocalModelAuthority.hpp"
#include <cstdio>

namespace rawr::olma {

inline void Emit(FILE* f, const GeomSeal& g) {
    if (!f) f = stdout;
    if (!g.PASS) {
        std::fprintf(f, "GGUF_DYNAMIC_GEOMETRY_001=BLOCKED\n");
        std::fprintf(f, "BLOCKED_AT=%s\nBLOCKED_OWNER=GGUF_METADATA\n", g.BLOCKED_AT.c_str());
        std::fprintf(f, "REASON=%s\nFIRST_DELTA=%s\n", g.REASON.c_str(), g.FIRST_DELTA.c_str());
        std::fprintf(f, "ONE_LOCAL_MODEL_AUTHORITY=%d\n", g.ONE_LOCAL_MODEL_AUTHORITY);
        return;
    }
    std::fprintf(f, "GGUF_MAGIC_OK=%d\nGGUF_VERSION=%u\n", g.GGUF_MAGIC_OK, g.GGUF_VERSION);
    std::fprintf(f, "GGUF_TENSOR_COUNT=%llu\nGGUF_METADATA_COUNT=%llu\n",
                 (unsigned long long)g.GGUF_TENSOR_COUNT,
                 (unsigned long long)g.GGUF_METADATA_COUNT);
    std::fprintf(f, "ARCH=%s\nMODEL_NAME=%s\n", g.ARCH.c_str(), g.MODEL_NAME.c_str());
    std::fprintf(f, "LAYERS=%u\nHIDDEN=%u\nFFN=%u\n", g.LAYERS, g.HIDDEN, g.FFN);
    std::fprintf(f, "HEADS=%u\nKV_HEADS=%u\nHEAD_DIM=%u\n", g.HEADS, g.KV_HEADS, g.HEAD_DIM);
    std::fprintf(f, "CONTEXT=%u\nRMS_EPS=%.8g\n", g.CONTEXT, (double)g.RMS_EPS);
    std::fprintf(f, "ROPE_DIM=%u\nROPE_BASE=%.8g\n", g.ROPE_DIM, (double)g.ROPE_BASE);
    if (g.ROPE_SCALING_PRESENT)
        std::fprintf(f, "ROPE_SCALING=%.8g\n", (double)g.ROPE_SCALING);
    else
        std::fprintf(f, "ROPE_SCALING=ABSENT\n");
    std::fprintf(f, "NO_STATIC_MODEL_GEOMETRY=%d\nMETADATA_BOUNDS_CHECKED=%d\n",
                 g.NO_STATIC_MODEL_GEOMETRY, g.METADATA_BOUNDS_CHECKED);
    std::fprintf(f, "GEOMETRY_SELF_CONSISTENT=%d\nONE_LOCAL_MODEL_AUTHORITY=%d\n",
                 g.GEOMETRY_SELF_CONSISTENT, g.ONE_LOCAL_MODEL_AUTHORITY);
    std::fprintf(f, "TENSOR_BINDABLE_COUNT=%zu\n", g.TENSOR_BINDABLE_COUNT);
    std::fprintf(f, "GGUF_DYNAMIC_GEOMETRY_001=PASS\nFIRST_DELTA=TENSOR_NAME_TYPE_BINDING\n");
}

} // namespace rawr::olma
