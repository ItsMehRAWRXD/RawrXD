/* K2NativeMoEFfn.cpp — orchestration: dense L0 | MoE L1+ after MLA. */
#include "K2NativeMoEFfn.hpp"
#include "K2GlobalTensorIndex.hpp"
#include "K2WeightResolve.hpp"
#include "MoEPlaceLiveCounters.hpp"
#include <cstdlib>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <vector>

namespace Deep2 {

bool K2NativeMoE_AfterMla(const GlobalTensorIndex& index, const KimiK2Config& cfg,
                          uint32_t layer, bool decodePhase, float* hiddenIO,
                          float* scratch, std::string& error) {
    if (const char* off = std::getenv("DEEP2_K2_MOE");
        off && off[0] == '0' && !off[1])
        return true;
    if (!hiddenIO || !scratch || !cfg.hiddenDim) {
        error = "K2MoE: bad args";
        return false;
    }
    MoEPlaceLive().moe_ffn_enter++;
    if (const char* t = std::getenv("DEEP2_MOE_PLACE_TRACE");
        t && t[0] && t[0] != '0')
        std::fprintf(stderr, "LIVE_K2_MOE_ENTER layer=%u decode=%d ctr=%llu\n",
                     layer, decodePhase ? 1 : 0,
                     (unsigned long long)MoEPlaceLive().moe_ffn_enter);

    const size_t H = cfg.hiddenDim;
    char denseGate[64];
    std::snprintf(denseGate, sizeof(denseGate), "blk.%u.ffn_gate.weight", layer);
    if (layer == 0 && index.Find(denseGate)) {
        MoEPlaceLive().ffn_dispatch_dense++;
        return true;
    }
    if (cfg.numExperts == 0) {
        MoEPlaceLive().ffn_dispatch_dense++;
        return true;
    }
    MoEPlaceLive().ffn_dispatch_moe++;
    if (decodePhase) MoEPlaceLive().decode_moe_layer_calls++;

    char normN[64];
    std::snprintf(normN, sizeof(normN), "blk.%u.ffn_norm.weight", layer);
    WeightSpan nSpan{};
    std::vector<uint8_t> nBuf;
    if (!ResolveWeight(index, normN, nSpan, nBuf, error)) return false;
    const float* nw =
        reinterpret_cast<const float*>(nSpan.data ? nSpan.data : nBuf.data());
    float ss = 0.f;
    for (size_t i = 0; i < H; ++i) ss += hiddenIO[i] * hiddenIO[i];
    float inv = 1.f / std::sqrt(ss / (float)H + cfg.normRmsEps);
    for (size_t i = 0; i < H; ++i) scratch[i] = hiddenIO[i] * inv * nw[i];

    std::vector<float> accum(H, 0.f);
    if (!K2MoEPlaceAndExec(index, cfg, layer, decodePhase, scratch, accum.data(),
                           error))
        return false;
    for (size_t i = 0; i < H; ++i) hiddenIO[i] += accum[i];
    return true;
}

} // namespace Deep2
