// SemanticSafe.hpp — RAWRXD_SEMANTIC_SAFE=1 correctness lane
#pragma once
#include <cstdlib>
#include <cstring>
#ifdef _WIN32
#include <stdlib.h>
#endif

namespace Deep2 {

inline bool SemanticSafeWanted() {
    const char* e = std::getenv("RAWRXD_SEMANTIC_SAFE");
    return e && e[0] == '1' && e[1] == '\0';
}

// Apply boring correctness env before Deep2Engine construct/init.
// Recipe from GIBBERISH_EMBED_ZERO_001 + TinyLlama CPU known-good lane:
// force CPU, kill elastic/medusa/cyclone, greedy decode, no live mechs.
inline void SemanticSafeApply() {
#ifdef _WIN32
    _putenv_s("RAWRXD_SEMANTIC_SAFE", "1");
    _putenv_s("RAWRXD_GPU_DEVICES", "CPU");
    _putenv_s("RAWRXD_GPU_FWD", "0");
    _putenv_s("DEEP2_FUSED", "0");
    _putenv_s("DEEP2_LIVE_FUSED", "0");
    _putenv_s("DEEP2_LIVE_POLICY", "MIN");
    _putenv_s("DEEP2_LIVE_MECH", "none");
    _putenv_s("DEEP2_LIVE_PATH", "0");
    _putenv_s("DEEP2_GEN_ALG", "standard");
    _putenv_s("RAWRXD_GREEDY", "1");
    _putenv_s("DEEP2_K2_SHARD_DIR", "");
    _putenv_s("RAWRXD_ENHANCE_SKIP",
              "vulkan,elastic,cyclone,prefetch,telemetry,medusa,nu,warmup,"
              "ckv,nvme,slide,chamber,plasma,sov,mars,torus");
    _putenv_s("RAWRXD_TOP_LOGITS", "0");
    _putenv_s("RAWRXD_AGENT_TOKEN_TRACE", "0");
    _putenv_s("RAWRXD_EMBED_DIAG", "0");
#else
    setenv("RAWRXD_SEMANTIC_SAFE", "1", 1);
    setenv("RAWRXD_GPU_DEVICES", "CPU", 1);
    setenv("RAWRXD_GPU_FWD", "0", 1);
    setenv("DEEP2_LIVE_MECH", "none", 1);
    setenv("DEEP2_GEN_ALG", "standard", 1);
    setenv("RAWRXD_GREEDY", "1", 1);
    setenv("RAWRXD_EMBED_DIAG", "0", 1);
#endif
}

} // namespace Deep2
