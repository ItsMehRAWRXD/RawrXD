// SEH frames for open/stream/close — companion to product_deep2_infer.cpp. ≤99.
#include "product_deep2_infer_internal.hpp"
#include <cstdio>
#ifdef _WIN32
#include <windows.h>
#endif

namespace rawr {
namespace product_infer_detail {

#ifdef _WIN32
/* Filter may use ExceptionInformation; __except body stays literal-only (/EHsc). */
static int EmitSeh(const char* tag, EXCEPTION_POINTERS* ep) {
    EXCEPTION_RECORD* er = ep ? ep->ExceptionRecord : nullptr;
    CONTEXT* cx = ep ? ep->ContextRecord : nullptr;
    DWORD code = er ? er->ExceptionCode : 0;
    void* addr = er ? er->ExceptionAddress : nullptr;
    std::fprintf(stderr, "%s=1 CODE=0x%08lX ADDR=%p RIP=%p\n", tag,
                 (unsigned long)code, addr, cx ? (void*)cx->Rip : nullptr);
    if (er && code == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2) {
        const char* rw = er->ExceptionInformation[0] ? "WRITE" : "READ";
        std::fprintf(stderr, "%s_ACCESS=%s VA=%p\n", tag, rw,
                     (void*)er->ExceptionInformation[1]);
    }
    HMODULE hm = nullptr;
    if (addr && GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCWSTR)addr, &hm) &&
        hm) {
        wchar_t path[MAX_PATH] = {};
        GetModuleFileNameW(hm, path, MAX_PATH);
        std::fprintf(stderr, "%s_MODULE=%ls BASE=%p\n", tag, path, (void*)hm);
    }
    void* frames[16] = {};
    USHORT n = CaptureStackBackTrace(0, 16, frames, nullptr);
    std::fprintf(stderr, "%s_STACK n=%u", tag, (unsigned)n);
    for (USHORT i = 0; i < n; ++i)
        std::fprintf(stderr, " %p", frames[i]);
    std::fprintf(stderr, "\n");
    std::fflush(stderr);
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif

bool OpenSeh(const char* modelAliasOrPath) {
#ifdef _WIN32
    __try {
        return OpenBody(modelAliasOrPath);
    } __except (EmitSeh("PRODUCT_DEEP2_OPEN_SEH", GetExceptionInformation())) {
        StickySessionOpen().store(0);
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
    } __except (EmitSeh("PRODUCT_DEEP2_INFER_STREAM_SEH",
                        GetExceptionInformation())) {
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
        StickySessionOpen().store(0);
        Rt().CloseSession();
        return true;
    } __except (EmitSeh("PRODUCT_DEEP2_CLOSE_SEH", GetExceptionInformation())) {
        StickySessionOpen().store(0);
        return false;
    }
#else
    StickySessionOpen().store(0);
    Rt().CloseSession();
    return true;
#endif
}

} // namespace product_infer_detail
} // namespace rawr
