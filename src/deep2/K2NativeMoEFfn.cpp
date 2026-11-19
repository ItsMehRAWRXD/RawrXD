/* K2NativeMoEFfn.cpp — orchestration: dense L0 | MoE L1+ after MLA. */
#include "K2NativeMoEFfn.hpp"
#include "K2GlobalTensorIndex.hpp"
#include "K2WeightResolve.hpp"
#include "K2NativeMoE_LayerTrace.hpp"
#include "MoEPlaceLiveCounters.hpp"
#include <cstdlib>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <vector>

namespace Deep2 {

namespace {
bool ValidateMoEFinite(const float* data, size_t count, uint32_t layer,
                       const char* stage) {
    if (!data || !count) return false;
    for (size_t i = 0; i < count; ++i) {
        if (!std::isfinite(data[i])) {
            std::fprintf(stderr,
                         "[MOE_NONFINITE] layer=%u stage=%s index=%zu value=%g\n",
                         layer, stage, i, data[i]);
            std::fflush(stderr);
            return false;
        }
    }
    return true;
}
}

bool K2MoEExecDense(const GlobalTensorIndex& index, const KimiK2Config& cfg,
                    uint32_t layer, const float* hidden, float* output,
                    std::string& error);

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
    moe_ltrace::DumpLayerPair(index, moe_ltrace::TraceLayer());
    moe_ltrace::BC(layer, "ENTER");
    MoEPlaceLive().moe_ffn_enter++;
    if (const char* t = std::getenv("DEEP2_MOE_PLACE_TRACE");
        t && t[0] && t[0] != '0')
        std::fprintf(stderr, "LIVE_K2_MOE_ENTER layer=%u decode=%d ctr=%llu\n",
                     layer, decodePhase ? 1 : 0,
                     (unsigned long long)MoEPlaceLive().moe_ffn_enter);

    const size_t H = cfg.hiddenDim;
    if (!ValidateMoEFinite(hiddenIO, H, layer, "input")) {
        error = "K2MoE: non-finite layer input";
        return false;
    }
    char denseGate[64];
    std::snprintf(denseGate, sizeof(denseGate), "blk.%u.ffn_gate.weight", layer);
    if (cfg.numExperts == 0 || index.Find(denseGate)) {
        MoEPlaceLive().ffn_dispatch_dense++;
        if (!K2MoEExecDense(index, cfg, layer, scratch, hiddenIO, error)) {
            moe_ltrace::BC(layer, "DENSE_FAIL");
            return false;
        }
        moe_ltrace::BC(layer, "DENSE_DONE");
        return true;
    }
    MoEPlaceLive().ffn_dispatch_moe++;
    if (decodePhase) MoEPlaceLive().decode_moe_layer_calls++;

    char normN[64];
    std::snprintf(normN, sizeof(normN), "blk.%u.ffn_norm.weight", layer);
    WeightSpan nSpan{};
    std::vector<uint8_t> nBuf;
    if (!ResolveWeight(index, normN, nSpan, nBuf, error)) {
        moe_ltrace::BC(layer, "NORM_FAIL");
        return false;
    }
    const uint8_t* normData = nSpan.data ? nSpan.data : nBuf.data();
    const size_t normBytes = nSpan.data ? nSpan.bytes : nBuf.size();
    if (!normData || normBytes < H * sizeof(float)) {
        error = "K2MoE: ffn_norm weight view is incomplete";
        moe_ltrace::BC(layer, "NORM_INCOMPLETE");
        if (const char* t = std::getenv("DEEP2_MOE_PLACE_TRACE");
            t && t[0] && t[0] != '0')
            std::fprintf(stderr, "LIVE_K2_MOE_NORM_INCOMPLETE layer=%u bytes=%zu required=%zu\n",
                         layer, normBytes, H * sizeof(float));
        return false;
    }
    const float* nw = reinterpret_cast<const float*>(normData);
    float ss = 0.f;
    for (size_t i = 0; i < H; ++i) ss += hiddenIO[i] * hiddenIO[i];
    float inv = 1.f / std::sqrt(ss / (float)H + cfg.normRmsEps);
    for (size_t i = 0; i < H; ++i) scratch[i] = hiddenIO[i] * inv * nw[i];
    if (!std::isfinite(ss) || !std::isfinite(inv) ||
        !ValidateMoEFinite(scratch, H, layer, "normed")) {
        error = "K2MoE: non-finite normalized input";
        return false;
    }
    moe_ltrace::BC(layer, "NORM_DONE");

    std::vector<float> accum(H, 0.f);
    if (!K2MoEPlaceAndExec(index, cfg, layer, decodePhase, scratch, accum.data(),
                           error)) {
        moe_ltrace::BC(layer, "PLACE_EXEC_FAIL");
        return false;
    }
    if (!ValidateMoEFinite(accum.data(), H, layer, "routed_shared_accum")) {
        error = "K2MoE: non-finite routed/shared accumulation";
        return false;
    }
    for (size_t i = 0; i < H; ++i) hiddenIO[i] += accum[i];
    if (!ValidateMoEFinite(hiddenIO, H, layer, "final_residual")) {
        error = "K2MoE: non-finite final residual";
        return false;
    }
    moe_ltrace::BC(layer, "RESIDUAL_DONE");
    moe_ltrace::BC(layer, "EXIT");
    return true;
}

} // namespace Deep2
