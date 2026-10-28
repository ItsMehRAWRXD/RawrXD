// SEH frames for open/stream/close — companion to product_deep2_infer.cpp. ≤99.
#include "product_deep2_infer_internal.hpp"
#include <cstdio>
#ifdef _WIN32
#include <windows.h>
#endif

namespace rawr {
namespace product_infer_detail {

bool OpenSeh(const char* modelAliasOrPath) {
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

bool StreamSeh(const StreamPack& p) {
#ifdef _WIN32
    __try {
        return StreamBody(p);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        std::fprintf(stderr, "PRODUCT_DEEP2_INFER_STREAM_SEH=1 CODE=0x%08lX\n",
                     (unsigned long)GetExceptionCode());
        /* Literals only in __except — no C++ dtors/methods (/EHsc). */
        if (p.failedStage) *p.failedStage = "SEH";
        if (p.failedOwner) *p.failedOwner = "product_deep2_infer";
        if (p.exitReason) *p.exitReason = "PRODUCT_DEEP2_INFER_STREAM_SEH";
        return false;
    }
#else
    return StreamBody(p);
#endif
}

bool CloseSeh() {
#ifdef _WIN32
    __try {
        Rt().CloseSession();
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        std::fprintf(stderr, "PRODUCT_DEEP2_CLOSE_SEH=1 CODE=0x%08lX\n",
                     (unsigned long)GetExceptionCode());
        return false;
    }
#else
    Rt().CloseSession();
    return true;
#endif
}

} // namespace product_infer_detail
} // namespace rawr
