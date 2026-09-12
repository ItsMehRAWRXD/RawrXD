/* d2_adapter_internal.hpp — shared adapter hooks */
#pragma once
#include "d2_deep2_binding.h"
#include "Deep2Engine.h"
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace d2_adapt {

inline int adapter_trace() {
    const char* e = std::getenv("RAWRXD_D2_SESSION_TRACE");
    return e && e[0] == '1';
}
inline void atr(const char* fmt, ...) {
    va_list ap;
    if (!adapter_trace()) return;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fflush(stderr);
}

struct BridgeCtx {
    D2TokenCallback cb;
    void* user;
    D2Cancel* cancel;
    D2StreamMetrics* metrics;
    Deep2::Deep2Engine* eng;
    std::chrono::steady_clock::time_point t0;
    bool first;
};

int load_model(void* engine, const char* gguf_path);
int generate(void* engine, const D2GenerateRequest* req, D2TokenCallback cb,
             void* user, D2Cancel* cancel, D2StreamMetrics* metrics);
inline void request_cancel(void* engine) {
    if (engine) static_cast<Deep2::Deep2Engine*>(engine)->requestCancel();
}
inline void reset_context(void* engine) {
    if (engine) static_cast<Deep2::Deep2Engine*>(engine)->reset();
}
inline void unload_model(void* engine) {
    if (engine) static_cast<Deep2::Deep2Engine*>(engine)->unloadModel();
}

} // namespace d2_adapt
