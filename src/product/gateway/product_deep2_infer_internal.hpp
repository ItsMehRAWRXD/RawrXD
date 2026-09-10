#pragma once
/* Stream body — ≤99. SEH wrappers in product_deep2_infer_seh.hpp. */
#include "product_deep2_infer_open.hpp"
#include "../../deep2/lavapath/ProductRun.hpp"
#include <atomic>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#ifdef _WIN32
#include <windows.h>
#endif

namespace rawr {
namespace product_infer_detail {

inline std::atomic<uint32_t>& LastEvalCount() {
    static std::atomic<uint32_t> g{0};
    return g;
}

inline const char* Alias() {
    if (const char* e = std::getenv("RAWRXD_PRODUCT_MODEL"))
        if (e && e[0]) return e;
    return "llama32";
}
inline product_run::ProductRuntime& Rt() {
    return product_run::SharedProductRuntime();
}

inline bool OpenSeh(const char* modelAliasOrPath) {
#ifdef _WIN32
    __try {
        return OpenBody(modelAliasOrPath);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        std::fprintf(stderr, "PRODUCT_DEEP2_OPEN_SEH=1 CODE=0x%08lX\n",
                     (unsigned long)GetExceptionCode());
        return false;
    }
#else
    return OpenBody(modelAliasOrPath);
#endif
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
    LastEvalCount().store(rc.generatedTokens);
    if (p.outText) *p.outText = rc.text;
    if (p.failedStage) *p.failedStage = rc.failedStage;
    if (p.failedOwner) *p.failedOwner = rc.failedOwner;
    if (p.exitReason) *p.exitReason = rc.exitReason;
    if (p.firstToken) *p.firstToken = rc.firstToken;
    return rc.productPass != 0;
}

} // namespace product_infer_detail
} // namespace rawr

#include "product_deep2_infer_seh.hpp"
