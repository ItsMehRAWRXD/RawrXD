#pragma once
/* OPEN = meta indexed && storage reachable && working set acquirable. ≤99. */
#include "../Deep2Engine.h"
#include "../NVMeStream.h"
#include <cstdio>
#include <cstdint>

namespace Deep2 {
namespace product_open {

struct Facts {
    int meta_indexed = 0;
    int storage_reachable = 0;
    int working_set_acquirable = 0;
    int acquire_live = 0;
    int mmap_bound = 0;
    int file_backing = 0;
    int tensor_count = 0;
    int open_pass = 0;
};

inline int TouchPtr(const void* p) {
    if (!p) return 0;
    volatile char c = static_cast<const volatile char*>(p)[0];
    (void)c;
    return 1;
}

inline int AcquireWorkingSet(Deep2Engine& e, const ModelWeights& mw) {
    const WeightTensor& w = mw.tokenEmbed.data || mw.tokenEmbed.hasFileBacking
                                ? mw.tokenEmbed
                                : mw.lmHead;
    uint64_t n = w.sizeBytes ? w.sizeBytes : 4096ull;
    if (n > (1ull << 20)) n = 1ull << 20;
    if (NVMeStream* nv = e.HostNvme()) {
        if (w.hasFileBacking && nv->prefetchRange(w.fileOffset, (size_t)n))
            return 1;
    }
    return TouchPtr(w.data);
}

inline Facts Evaluate(Deep2Engine& e, const char* path) {
    Facts f{};
    const ModelWeights& mw = e.getModelWeights();
    f.tensor_count = (int)mw.layers.size() + (mw.tokenEmbed.sizeBytes ? 1 : 0) +
                     (mw.lmHead.sizeBytes ? 1 : 0);
    f.meta_indexed = (mw.loaded && f.tensor_count > 0) ? 1 : 0;
    f.file_backing = (mw.tokenEmbed.hasFileBacking || mw.lmHead.hasFileBacking) ? 1 : 0;
    f.mmap_bound = e.GgufMmapBound();
    const int ptr = (mw.tokenEmbed.data || mw.lmHead.data) ? 1 : 0;
    f.storage_reachable =
        (path && path[0] && (ptr || f.file_backing || f.mmap_bound)) ? 1 : 0;
    f.acquire_live = AcquireWorkingSet(e, mw);
    f.working_set_acquirable = f.acquire_live;
    f.open_pass = (f.meta_indexed && f.storage_reachable &&
                   f.working_set_acquirable && e.isModelLoaded())
                      ? 1
                      : 0;
    return f;
}

inline void Emit(FILE* fp, const Facts& f) {
    if (!fp) fp = stderr;
    std::fprintf(fp,
                 "OPEN_SEMANTIC=STREAMABLE\n"
                 "OPEN_META_INDEXED=%d\nOPEN_STORAGE_REACHABLE=%d\n"
                 "OPEN_WORKING_SET_ACQUIRABLE=%d\nOPEN_WORKING_SET_ACQUIRE_LIVE=%d\n"
                 "OPEN_MMAP_BOUND=%d\nOPEN_FILE_BACKING=%d\n"
                 "OPEN_TENSOR_COUNT=%d\nPRODUCT_OPEN_STREAMABLE=%d\n"
                 "NOTE=OPEN_NE_WEIGHTS_RESIDENT; LAA_NOT_OPEN_GATE\n",
                 f.meta_indexed, f.storage_reachable, f.working_set_acquirable,
                 f.acquire_live, f.mmap_bound, f.file_backing, f.tensor_count,
                 f.open_pass);
    std::fflush(fp);
}

inline bool StreamableOk(Deep2Engine& e, const char* path, FILE* fp) {
    Facts f = Evaluate(e, path);
    Emit(fp, f);
    if (!f.open_pass) {
        std::fprintf(fp ? fp : stderr,
                     "PRODUCT_OPEN=FAIL reason=NOT_STREAMABLE "
                     "meta=%d storage=%d ws=%d loaded=%d\n",
                     f.meta_indexed, f.storage_reachable, f.working_set_acquirable,
                     e.isModelLoaded() ? 1 : 0);
        std::fflush(fp ? fp : stderr);
    }
    return f.open_pass != 0;
}

} /* namespace product_open */
} /* namespace Deep2 */
