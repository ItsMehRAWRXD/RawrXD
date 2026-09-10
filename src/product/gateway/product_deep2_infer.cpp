// product_deep2_infer.cpp — SharedProductRuntime on sticky Vulkan lane
#include "product_deep2_infer.hpp"
#include "product_deep2_infer_internal.hpp"
#include "product_deep2_infer_lane.hpp"
#include <cstdio>
#ifdef _WIN32
#include <windows.h>
#endif

namespace rawr {
namespace {
using product_infer_detail::Rt;
using product_infer_detail::StreamPack;
using product_infer_detail::StreamSeh;
using product_infer_detail::InferBody;
using product_infer_lane::Run;

#ifdef _WIN32
bool InferSeh(const char* prompt, char* out, size_t cap) {
    __try {
        return InferBody(prompt, out, cap);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        std::fprintf(stderr, "PRODUCT_DEEP2_INFER_SEH=1 CODE=0x%08lX\n",
                     (unsigned long)GetExceptionCode());
        out[0] = 0;
        return false;
    }
}
#else
bool InferSeh(const char* prompt, char* out, size_t cap) {
    return InferBody(prompt, out, cap);
}
#endif
} // namespace

bool ProductOpenSession(const char* modelAliasOrPath) {
    return Run([&]() -> bool {
        return product_infer_detail::OpenSeh(modelAliasOrPath);
    });
}

void ProductCloseSession() {
    Run([&]() -> int {
        Rt().CloseSession();
        return 0;
    });
}

bool ProductSessionOpen() {
    return Run([&]() -> bool { return Rt().IsOpen(); });
}

void ProductRequestCancel() {
    /* Cancel must not block on infer lane — publish from caller thread. */
    (void)Rt().CancelGeneration();
}

bool ProductDeep2InferStream(const char* prompt, uint32_t maxTokens,
                             const std::function<bool(const std::string&)>& onPiece,
                             std::string* outText, const char** outFailedStage,
                             const char** outFailedOwner, const char** outExitReason,
                             int* outFirstToken) {
    return Run([&]() -> bool {
        StreamPack p{prompt, maxTokens, &onPiece, outText, outFailedStage,
                     outFailedOwner, outExitReason, outFirstToken};
        return StreamSeh(p);
    });
}

bool ProductDeep2Infer(const char* prompt, char* out, size_t cap) {
    if (!out || cap < 2) return false;
    out[0] = 0;
    return Run([&]() -> bool { return InferSeh(prompt, out, cap); });
}

uint32_t ProductDeep2LastEvalCount() {
    return product_infer_detail::LastEvalCount().load();
}

} // namespace rawr
