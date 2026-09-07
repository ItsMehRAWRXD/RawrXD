// RawrSemanticSafe.hpp — boring correctness lane for normal GGUF
#pragma once
#ifdef _WIN32
#include <stdlib.h>
#endif
#include <cstdio>
#include <cstdlib>

namespace Deep2 {
namespace rawr_run {

inline bool SemanticSafeWanted() {
    const char* e = std::getenv("RAWRXD_SEMANTIC_SAFE");
    return e && e[0] == '1';
}

// Must run before Deep2Engine construct / initialize.
inline void ApplySemanticSafeEnv() {
#ifdef _WIN32
    _putenv_s("RAWRXD_SEMANTIC_SAFE", "1");
    _putenv_s("RAWRXD_GPU_FWD", "0");
    _putenv_s("DEEP2_FUSED", "0");
    _putenv_s("DEEP2_LIVE_POLICY", "MIN");
    _putenv_s("DEEP2_K2_SHARD_DIR", "");
    _putenv_s("RAWRXD_ENHANCE_SKIP",
              "elastic,cyclone,ckv,medusa,nvme,prefetch,torus,mars,sov,plasma,"
              "chamber,nu,warmup,slide,telemetry");
    _putenv_s("RAWRXD_TOP_LOGITS_STDERR", "1");
#endif
}

inline void Diag(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

} // namespace rawr_run
} // namespace Deep2
