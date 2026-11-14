/* Peer-only StreamSeh override: CANCELLED+tokens = usable TOOL_CALL stream.
 * Linked before frozen seh_r72 via /FORCE:MULTIPLE. No PRD/seh TU churn. */
#include "product_deep2_infer_internal.hpp"
#include <cstdio>
#include <cstring>
#ifdef _WIN32
#include <windows.h>
#endif

namespace rawr {
namespace product_infer_detail {

#ifdef _WIN32
static int EmitSehR76(EXCEPTION_POINTERS* ep) {
    EXCEPTION_RECORD* er = ep ? ep->ExceptionRecord : nullptr;
    DWORD code = er ? er->ExceptionCode : 0;
    std::fprintf(stderr, "PRODUCT_DEEP2_INFER_STREAM_SEH=1 CODE=0x%08lX\n",
                 (unsigned long)code);
    std::fflush(stderr);
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif

static bool StreamBodyR76(const StreamPack& p) {
    if (!Deep2::ProductStreamerPrep()) return false;
#ifdef _WIN32
    _putenv_s("RAWRXD_GREEDY", "1");
    _putenv_s("RAWRXD_DECODE_FEEDBACK", "0");
#endif
    if (!Rt().IsOpen() && StickySessionOpen().load() == 0 &&
        !OpenSeh(Alias()))
        return false;
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
    /* Never wipe caller TOOL_CALL seed. */
    if (p.outText && p.outText->empty()) *p.outText = std::move(rc.text);
    if (p.failedStage) *p.failedStage = rc.failedStage;
    if (p.failedOwner) *p.failedOwner = rc.failedOwner;
    if (p.exitReason) *p.exitReason = rc.exitReason;
    if (p.firstToken) *p.firstToken = rc.firstToken;
    const bool cancelOk =
        rc.firstToken != 0 && rc.generatedTokens > 0 && rc.exitReason &&
        std::strcmp(rc.exitReason, "CANCELLED") == 0;
    const bool ok = rc.productPass != 0 || cancelOk;
    std::fprintf(stderr,
                 "STREAM_SEH_R76=1 ok=%d pass=%d cancelOk=%d tok=%u\n",
                 ok ? 1 : 0, rc.productPass, cancelOk ? 1 : 0,
                 rc.generatedTokens);
    std::fflush(stderr);
    return ok;
}

bool StreamSeh(const StreamPack& p) {
#ifdef _WIN32
    __try {
        return StreamBodyR76(p);
    } __except (EmitSehR76(GetExceptionInformation())) {
        if (p.failedStage) *p.failedStage = "SEH";
        if (p.failedOwner) *p.failedOwner = "StreamSeh_a8_r76";
        if (p.exitReason) *p.exitReason = "PRODUCT_DEEP2_INFER_STREAM_SEH";
        return false;
    }
#else
    return StreamBodyR76(p);
#endif
}

} // namespace product_infer_detail
} // namespace rawr
