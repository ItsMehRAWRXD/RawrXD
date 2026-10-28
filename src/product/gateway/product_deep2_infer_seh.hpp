#pragma once
/* InferBody (no __try) — SEH in product_deep2_infer.cpp. ≤99. */
#include <cstdio>
#include <cstring>
#include <string>

namespace rawr {
namespace product_infer_detail {

inline bool InferBody(const char* prompt, char* out, size_t cap,
                      uint32_t maxTokens = 0) {
    std::string text;
    const char* failedStage = nullptr;
    const char* failedOwner = nullptr;
    const char* exitReason = nullptr;
    /* 0 → StreamBody product default (64). Honor caller / CLI --max-tokens. */
    StreamPack p{prompt, maxTokens, nullptr, &text, &failedStage, &failedOwner,
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
