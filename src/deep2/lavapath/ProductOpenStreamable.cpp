/* ProductOpenStreamable — Acquire+Evaluate (single TU, no inline COMDAT). ≤99. */
#include "ProductOpenStreamable.hpp"
#include "../NVMeStream.h"
#include <cstdint>
#include <cstdlib>
#ifdef _WIN32
#include <windows.h>
#endif

namespace Deep2 {
namespace product_open {

int AcquireWorkingSet(Deep2Engine& e, const ModelWeights& mw) {
    /* Never probe WeightTensor::data on GPU/mmap (device VA → SEH). */
    if (e.isModelLoaded() || e.GgufMmapBound() || e.isK2ShardIndexOpen()) {
        std::fprintf(stderr, "OPEN_ACQUIRE_SHORTCIRCUIT=LOADED_OR_MMAP\n");
        std::fflush(stderr);
        return 1;
    }
    if (mw.tokenEmbed.hasFileBacking || mw.lmHead.hasFileBacking) {
        std::fprintf(stderr, "OPEN_ACQUIRE_SHORTCIRCUIT=FILE_BACKING\n");
        std::fflush(stderr);
        return 1;
    }
    {
        const char* hd = std::getenv("RAWRXD_HOST_DECODE");
        const char* fg = std::getenv("RAWR_FORCE_GPU");
        const char* ag = std::getenv("RAWRXD_ALLOW_GPU");
        if ((hd && hd[0] == '0') || (fg && fg[0] == '1') ||
            (ag && ag[0] == '1')) {
            std::fprintf(stderr, "OPEN_ACQUIRE_SHORTCIRCUIT=GPU_ENV\n");
            std::fflush(stderr);
            return 1;
        }
    }
    const WeightTensor& w =
        mw.tokenEmbed.data ? mw.tokenEmbed : mw.lmHead;
    if (!w.data) return 0;
#ifdef _WIN32
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(w.data, &mbi, sizeof(mbi)) == 0) return 0;
    if (!(mbi.State & MEM_COMMIT)) return 0;
    if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                         PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                         PAGE_EXECUTE_WRITECOPY)))
        return 0;
    return 1; /* VirtualQuery only — never deref */
#else
    return 1;
#endif
}

Facts Evaluate(Deep2Engine& e, const char* path) {
    Facts f{};
    std::fprintf(stderr, "OPEN_EVALUATE_ENTER=1\n");
    std::fflush(stderr);
    if (e.isK2ShardIndexOpen()) {
        f.meta_indexed = f.storage_reachable = f.working_set_acquirable =
            f.acquire_live = f.file_backing = 1;
        f.tensor_count = 1;
        f.open_pass = e.isModelLoaded() ? 1 : 0;
        return f;
    }
    const ModelWeights& mw = e.getModelWeights();
    f.tensor_count = (int)mw.layers.size() + (mw.tokenEmbed.sizeBytes ? 1 : 0) +
                     (mw.lmHead.sizeBytes ? 1 : 0);
    f.meta_indexed = (mw.loaded && f.tensor_count > 0) ? 1 : 0;
    f.file_backing =
        (mw.tokenEmbed.hasFileBacking || mw.lmHead.hasFileBacking) ? 1 : 0;
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

} /* namespace product_open */
} /* namespace Deep2 */
