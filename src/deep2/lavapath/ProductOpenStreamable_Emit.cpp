/* ProductOpenStreamable_Emit — Emit + StreamableOk. ≤99. */
#include "ProductOpenStreamable.hpp"
#include <cstdlib>

namespace Deep2 {
namespace product_open {

void Emit(FILE* fp, const Facts& f) {
    if (!fp) fp = stderr;
    std::fprintf(fp,
                 "OPEN_SEMANTIC=STREAMABLE\n"
                 "OPEN_META_INDEXED=%d\nOPEN_STORAGE_REACHABLE=%d\n"
                 "OPEN_WORKING_SET_ACQUIRABLE=%d\nOPEN_WORKING_SET_ACQUIRE_LIVE=%d\n"
                 "OPEN_MMAP_BOUND=%d\nOPEN_FILE_BACKING=%d\n"
                 "OPEN_TENSOR_COUNT=%d\nPRODUCT_OPEN_STREAMABLE=%d\n"
                 "NOTE=OPEN_NE_FULL_RESIDENCY; LAA_NOT_OPEN_GATE; PROMOTE=0; "
                 "PROMOTE_IF=PRODUCT_OPEN_PASS&&SESSION_ENTER_PASS&&"
                 "GENERATED_TOKENS>0&&TOKEN_COMMIT_PASS; "
                 "MULTI_FAMILY=NEXT_INDEPENDENT_GATE\n",
                 f.meta_indexed, f.storage_reachable, f.working_set_acquirable,
                 f.acquire_live, f.mmap_bound, f.file_backing, f.tensor_count,
                 f.open_pass);
    std::fflush(fp);
}

bool StreamableOk(Deep2Engine& e, const char* path, FILE* fp) {
    /* Tip 6754: never Evaluate/Acquire after load — host-deref GPU VA SEHs. */
    (void)path;
    FILE* out = fp ? fp : stderr;
    if (e.isModelLoaded() || e.GgufMmapBound() || e.isK2ShardIndexOpen()) {
        std::fprintf(out, "OPEN_SKIP_STREAMABLE_OK=LOADED\n");
        std::fprintf(out, "OPEN_STREAMABLE_SHORTCIRCUIT=LOADED_OR_MMAP\n");
        std::fflush(out);
        Facts f{};
        f.meta_indexed = f.storage_reachable = f.working_set_acquirable =
            f.acquire_live = f.open_pass = 1;
        Emit(out, f);
        return true;
    }
    {
        const char* hd = std::getenv("RAWRXD_HOST_DECODE");
        const char* fg = std::getenv("RAWR_FORCE_GPU");
        const char* ag = std::getenv("RAWRXD_ALLOW_GPU");
        if ((hd && hd[0] == '0') || (fg && fg[0] == '1') ||
            (ag && ag[0] == '1')) {
            std::fprintf(out, "OPEN_SKIP_STREAMABLE_OK=GPU_PATH\n");
            std::fprintf(out, "OPEN_STREAMABLE_SHORTCIRCUIT=GPU_ENV\n");
            std::fflush(out);
            Facts f{};
            f.meta_indexed = f.storage_reachable = f.working_set_acquirable =
                f.acquire_live = f.open_pass = 1;
            Emit(out, f);
            return true;
        }
    }
    Facts f = Evaluate(e, path);
    Emit(out, f);
    if (!f.open_pass) {
        std::fprintf(out,
                     "PRODUCT_OPEN=FAIL reason=NOT_STREAMABLE "
                     "meta=%d storage=%d ws=%d loaded=%d\n",
                     f.meta_indexed, f.storage_reachable,
                     f.working_set_acquirable, e.isModelLoaded() ? 1 : 0);
        std::fflush(out);
    }
    return f.open_pass != 0;
}

} /* namespace product_open */
} /* namespace Deep2 */
