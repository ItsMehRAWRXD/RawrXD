#pragma once
/* Product CLI GPU law: ALLOW/FORCE/NO_CPU_FALLBACK; HOST_DECODE opt-in only. */
#include "../deep2/lavapath/SetEnvDual.hpp"
#include <cstdlib>
#include <cstdio>

namespace rawr {

inline void ApplyCliProductGpuLaw(bool wantVulkan) {
    const char* forceCpu = std::getenv("RAWR_FORCE_CPU");
    const char* hostDec = std::getenv("RAWRXD_HOST_DECODE");
    const bool explicitHost =
        (forceCpu && forceCpu[0] == '1') ||
        (hostDec && hostDec[0] == '1');
    if (explicitHost) {
        std::fprintf(stderr,
                     "CLI_GPU_LAW=HOST_OPT_IN FORCE_CPU=%d HOST_DECODE=%d\n",
                     (forceCpu && forceCpu[0] == '1') ? 1 : 0,
                     (hostDec && hostDec[0] == '1') ? 1 : 0);
        return;
    }
    Deep2::SetEnvIfUnset("RAWRXD_ALLOW_GPU", "1");
    Deep2::SetEnvIfUnset("RAWR_FORCE_GPU", "1");
    Deep2::SetEnvIfUnset("RAWR_NO_CPU_FALLBACK", "1");
    Deep2::SetEnv("RAWRXD_HOST_DECODE", "0");
    if (wantVulkan) {
        Deep2::SetEnvIfUnset("DEEP2_GPU_FWD", "1");
        Deep2::SetEnvIfUnset("RAWRXD_GPU_FWD", "1");
    }
    std::fprintf(stderr,
                 "CLI_GPU_LAW=1 ALLOW_GPU=1 FORCE_GPU=1 NO_CPU_FALLBACK=1 "
                 "HOST_DECODE=0 VULKAN_WANT=%d\n",
                 wantVulkan ? 1 : 0);
}

} // namespace rawr
