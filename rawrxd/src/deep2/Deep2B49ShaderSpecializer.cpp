#include "Deep2B49ShaderSpecializer.hpp"
#include <sstream>

namespace Deep2 {

static uint64_t mix(uint64_t h, uint64_t v) noexcept {
    h ^= v + 0x9e3779b97f4a7c15ull + (h<<6) + (h>>2);
    return h;
}

B49ShaderKey B49ShaderSpecializer::derive(const B49Geometry& g,
                                          const B49Device& d) noexcept {
    B49ShaderKey k{};
    k.workgroup = g.hidden >= 4096 ? 256u : 128u;
    if (k.workgroup > d.maxWorkgroup) k.workgroup = d.maxWorkgroup;

    k.vectorWidth = (g.quantBits <= 4 && g.hidden % 8u == 0u) ? 8u : 4u;
    k.rowsPerGroup = g.hidden >= 8192 ? 8u : (g.hidden >= 4096 ? 4u : 2u);
    k.prefetch = g.hidden >= 8192 ? 8u : 4u;
    k.expertConcurrency = g.expertsPerToken >= 8 ? 8u :
                          (g.expertsPerToken >= 4 ? 4u :
                          (g.expertsPerToken > 0 ? 2u : 1u));
    k.layerChain = g.layers >= 64 ? 8u :
                   (g.layers >= 48 ? 6u :
                   (g.layers >= 24 ? 4u : 2u));
    k.flashMLA = g.useMLA && g.kvLoraRank > 0;
    k.moeRegisterFusion = g.experts > 0 && g.expertsPerToken > 0;
    k.ssmFastPath = g.hasSSM;

    uint64_t h=1469598103934665603ull;
    h=mix(h,g.hidden); h=mix(h,g.intermediate); h=mix(h,g.heads);
    h=mix(h,g.kvHeads); h=mix(h,g.headDim); h=mix(h,g.experts);
    h=mix(h,g.expertsPerToken); h=mix(h,g.qLoraRank); h=mix(h,g.kvLoraRank);
    h=mix(h,g.ropeDim); h=mix(h,g.layers); h=mix(h,g.quantBits);
    h=mix(h,d.waveWidth); h=mix(h,d.ldsBytes);
    h=mix(h,k.workgroup); h=mix(h,k.vectorWidth); h=mix(h,k.rowsPerGroup);
    h=mix(h,k.prefetch); h=mix(h,k.expertConcurrency); h=mix(h,k.layerChain);
    k.hash=h;
    return k;
}

std::string B49ShaderSpecializer::macroPreamble(const B49ShaderKey& k) {
    std::ostringstream o;
    o << "#define D2_WG " << k.workgroup << "\n"
      << "#define D2_VEC " << k.vectorWidth << "\n"
      << "#define D2_ROWS_PER_GROUP " << k.rowsPerGroup << "\n"
      << "#define D2_PREFETCH " << k.prefetch << "\n"
      << "#define D2_EXPERT_CONCURRENCY " << k.expertConcurrency << "\n"
      << "#define D2_LAYER_CHAIN " << k.layerChain << "\n"
      << "#define D2_FLASH_MLA " << (k.flashMLA?1:0) << "\n"
      << "#define D2_MOE_REGISTER_FUSION " << (k.moeRegisterFusion?1:0) << "\n"
      << "#define D2_SSM_FAST " << (k.ssmFastPath?1:0) << "\n";
    return o.str();
}

}
