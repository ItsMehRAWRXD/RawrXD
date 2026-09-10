#pragma once
/* Infer/Stream SEH wrappers — companion to product_deep2_infer_internal. ≤99. */
#include <cstdio>
#include <cstring>
#include <string>
#ifdef _WIN32
#include <windows.h>
#endif

namespace rawr {
namespace product_infer_detail {

inline bool StreamSeh(const StreamPack& p) {
#ifdef _WIN32
    __try {
        return StreamBody(p);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        std::fprintf(stderr, "PRODUCT_DEEP2_INFER_STREAM_SEH=1 CODE=0x%08lX\n",
                     (unsigned long)GetExceptionCode());
        return false;
    }
#else
    return StreamBody(p);
#endif
}

inline bool InferBody(const char* prompt, char* out, size_t cap) {
    std::string text;
    const char* failedStage = nullptr;
    const char* failedOwner = nullptr;
    const char* exitReason = nullptr;
    /* HOST_DECODE matrix floor: short budget (was 48). */
    StreamPack p{prompt, 8, nullptr, &text, &failedStage, &failedOwner,
                 &exitReason, nullptr};
    if (!StreamSeh(p) || text.empty()) {
        std::fprintf(stderr,
                     "PRODUCT_DEEP2_INFER_FAIL stage=%s owner=%s exit=%s text_len=%zu\n",
                     failedStage ? failedStage : "?",
                     failedOwner ? failedOwner : "?",
                     exitReason ? exitReason : "?", text.size());
        std::fflush(stderr);
        return false;
    }
    size_t n = text.size() < cap ? text.size() : cap - 1;
    std::memcpy(out, text.data(), n);
    out[n] = 0;
    return true;
}

} // namespace product_infer_detail
} // namespace rawr
