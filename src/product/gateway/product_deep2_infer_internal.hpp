#pragma once
/* Stream body + SEH — kept out of product_deep2_infer.cpp for ≤99-line blocks. */
#include "product_deep2_infer_open.hpp"
#include "../../deep2/lavapath/ProductRun.hpp"
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#ifdef _WIN32
#include <windows.h>
#endif

namespace rawr {
namespace product_infer_detail {

inline const char* Alias() {
    if (const char* e = std::getenv("RAWRXD_PRODUCT_MODEL"))
        if (e && e[0]) return e;
    return "llama32";
}
inline product_run::ProductRuntime& Rt() {
    return product_run::SharedProductRuntime();
}

struct StreamPack {
    const char* prompt;
    uint32_t maxTokens;
    const std::function<bool(const std::string&)>* onPiece;
    std::string* outText;
    const char** failedStage;
    const char** failedOwner;
    const char** exitReason;
    int* firstToken;
};

inline bool StreamBody(const StreamPack& p) {
    if (!Deep2::ProductStreamerPrep()) return false;
#ifdef _WIN32
    _putenv_s("RAWRXD_GREEDY", "1");
    _putenv_s("RAWRXD_DECODE_FEEDBACK", "0");
#endif
    if (!Rt().IsOpen() && !OpenSeh(Alias())) return false;
    const std::string user = p.prompt && p.prompt[0] ? p.prompt : "complete";
    product_run::Request req{};
    req.modelAlias = Alias();
    req.prompt = user.c_str();
    req.maxTokens = p.maxTokens ? p.maxTokens : 64u;
    req.runtime = &Rt();
    req.keepOpen = 1;
    if (p.onPiece) req.onPiece = *p.onPiece;
    auto rc = product_run::ProductRun(req);
    if (p.outText) *p.outText = rc.text;
    if (p.failedStage) *p.failedStage = rc.failedStage;
    if (p.failedOwner) *p.failedOwner = rc.failedOwner;
    if (p.exitReason) *p.exitReason = rc.exitReason;
    if (p.firstToken) *p.firstToken = rc.firstToken;
    return rc.productPass != 0;
}

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
