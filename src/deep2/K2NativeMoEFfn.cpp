/* K2NativeMoEFfn.cpp — orchestration: dense L0 | MoE L1+ after MLA. */
#include "K2NativeMoEFfn.hpp"
#include "K2GlobalTensorIndex.hpp"
#include "K2WeightResolve.hpp"
#include "K2NativeMoE_LayerTrace.hpp"
#include "KimiLayer1FfnResidualCert.hpp"
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
    moe_ltrace::DumpLayerPair(index, moe_ltrace::TraceLayer());
    moe_ltrace::BC(layer, "ENTER");
    MoEPlaceLive().moe_ffn_enter++;
    if (const char* t = std::getenv("DEEP2_MOE_PLACE_TRACE");
        t && t[0] && t[0] != '0')
        std::fprintf(stderr, "LIVE_K2_MOE_ENTER layer=%u decode=%d ctr=%llu\n",
                     layer, decodePhase ? 1 : 0,
                     (unsigned long long)MoEPlaceLive().moe_ffn_enter);

    const size_t H = cfg.hiddenDim;
    const uint32_t tok = moe_ltrace::Tok();
    const bool dumpL1 = kimi_l1_ffn::CertOn() && layer == 1u;
    std::vector<float> ffnInpCopy;
    if (dumpL1) {
        ffnInpCopy.assign(hiddenIO, hiddenIO + H);
        kimi_l1_ffn::DumpVec("FFN_INP_1", layer, tok, hiddenIO, H);
    }

    char denseGate[64];
    std::snprintf(denseGate, sizeof(denseGate), "blk.%u.ffn_gate.weight", layer);
    if (layer == 0 && index.Find(denseGate)) {
        MoEPlaceLive().ffn_dispatch_dense++;
        moe_ltrace::BC(layer, "EXIT_DENSE");
        if (kimi_l1_ffn::CertOn()) {
            std::fprintf(stderr,
                         "L1FFN_NOTE L0_DENSE_STUB=1 "
                         "(EXIT_DENSE; no dense GEMV yet)\n");
            std::fflush(stderr);
        }
        return true;
    }
    if (cfg.numExperts == 0) {
        MoEPlaceLive().ffn_dispatch_dense++;
        moe_ltrace::BC(layer, "EXIT_NO_EXPERTS");
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
    const float* nw =
        reinterpret_cast<const float*>(nSpan.data ? nSpan.data : nBuf.data());
    float ss = 0.f;
    for (size_t i = 0; i < H; ++i) ss += hiddenIO[i] * hiddenIO[i];
    float inv = 1.f / std::sqrt(ss / (float)H + cfg.normRmsEps);
    for (size_t i = 0; i < H; ++i) scratch[i] = hiddenIO[i] * inv * nw[i];
    moe_ltrace::BC(layer, "NORM_DONE");
    if (dumpL1) kimi_l1_ffn::DumpVec("FFN_NORM_1", layer, tok, scratch, H);

    std::vector<float> accum(H, 0.f);
    if (!K2MoEPlaceAndExec(index, cfg, layer, decodePhase, scratch, accum.data(),
                           error)) {
        moe_ltrace::BC(layer, "PLACE_EXEC_FAIL");
        return false;
    }
    if (dumpL1) kimi_l1_ffn::DumpVec("FFN_DOWN_1", layer, tok, accum.data(), H);
    for (size_t i = 0; i < H; ++i) hiddenIO[i] += accum[i];
    if (dumpL1) {
        kimi_l1_ffn::DumpVec("FFN_RESIDUAL_1", layer, tok, hiddenIO, H);
        kimi_l1_ffn::DumpVec("LAYER_OUT_1", layer, tok, hiddenIO, H);
        const double maxAbs = kimi_l1_ffn::CheckResidualInvariant(
            ffnInpCopy.data(), accum.data(), hiddenIO, H);
        kimi_l1_ffn::EmitInvariant(layer, tok, maxAbs, H);
    }
    moe_ltrace::BC(layer, "RESIDUAL_DONE");
    moe_ltrace::BC(layer, "EXIT");
    return true;
}

} // namespace Deep2
