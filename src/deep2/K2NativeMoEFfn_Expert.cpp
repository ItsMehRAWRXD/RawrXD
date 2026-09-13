/* K2NativeMoEFfn_Expert.cpp — FindExpertSlice + DualStick GPU or host GEMV. */
#include "K2NativeMoEFfn.hpp"
#include "K2GlobalTensorIndex.hpp"
#include "K2ShardIo.hpp"
#include "K2WeightResolve.hpp"
#include "K2NativeMoE_LayerTrace.hpp"
#include "MoEPlaceLiveCounters.hpp"
#include "QuantKernelRegistry.hpp"
#include "StreamPathTiming.hpp"
#include "lavapath/DualStickStreamWindow.hpp"
#include "lavapath/DualStickExpertBundle.hpp"
#include "MoELiveAdd.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <vector>

namespace Deep2 {

bool K2MoEExecExpertGpu(unsigned stick, int ggmlGate, const uint8_t* g,
                        size_t gb, int ggmlUp, const uint8_t* u, size_t ub,
                        int ggmlDown, const uint8_t* d, size_t db,
                        const float* hidden, float* expertOut, size_t H,
                        size_t I, uint32_t layer, int expertId);

namespace {

bool ReadExpertSlice(const GlobalTensorIndex& index, const char* base,
                     uint32_t expertId, std::vector<uint8_t>& out, int& ggmlType,
                     size_t& outBytes, std::string& error) {
    auto slice = index.FindExpertSlice(base, expertId);
    if (!slice) {
        error = std::string("expert slice missing: ") + base;
        return false;
    }
    if (!slice->expertStrideBytes || !slice->byteSize) {
        error = "expert slice physical stride invalid";
        return false;
    }
    auto full = index.Find(base);
    if (!full || slice->byteOffset + slice->byteSize > full->byteSize) {
        error = "expert slice offset+size > source.byteSize";
        return false;
    }
    ggmlType = (int)slice->ggmlType;
    outBytes = (size_t)slice->byteSize;
    out.resize(outBytes);
    const auto& path = index.ShardPath(slice->shardId);
    const uint64_t off = slice->fileOffset + slice->byteOffset;
    const uint64_t t0 = StreamPathTiming_NowUs();
    if (!K2ShardIo_Read(path.string(), off, out.data(), out.size())) {
        error = "K2ShardIo_Read expert failed";
        return false;
    }
    StreamPathTiming_Add(SPT_shardMoe(), t0);
    return true;
}

void SiluMul(float* gate, const float* up, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        const float x = gate[i];
        gate[i] = (x / (1.0f + std::exp(-x))) * up[i];
    }
}

bool HostGemv(int ggmlType, const uint8_t* w, const float* x, float* y,
              size_t rows, size_t cols, const char* tag, std::string& error) {
    auto kn = QuantKernelRegistry::Instance().GetGEMV(ggmlType);
    if (!kn || !w || !x || !y || !rows || !cols) {
        char buf[192];
        std::snprintf(buf, sizeof(buf),
                      "%s GEMV failed type=%d kn=%p rows=%zu cols=%zu",
                      tag ? tag : "gemv", ggmlType, (void*)kn, rows, cols);
        error = buf;
        return false;
    }
    std::memset(y, 0, rows * sizeof(float));
    kn(w, x, y, rows, cols);
    return true;
}

bool MoEDimsFromGate(const GlobalTensorIndex& index, uint32_t layer, size_t& H,
                     size_t& I, std::string& error) {
    char gateN[64];
    std::snprintf(gateN, sizeof(gateN), "blk.%u.ffn_gate_exps.weight", layer);
    auto g = index.Find(gateN);
    if (g && g->shape.size() >= 2) {
        H = (size_t)g->shape[0];
        I = (size_t)g->shape[1];
        if (H && I) return true;
    }
    error = "MoEDimsFromGate: gate shape missing";
    return false;
}

bool SwiGLUHost(const uint8_t* g, int gt, const uint8_t* u, int ut,
                const uint8_t* d, int dt, const float* hidden, float* out,
                size_t H, size_t I, uint32_t layer, int expertId, bool shared,
                std::string& error) {
    std::vector<float> gate(I), up(I);
    if (shared) moe_ltrace::BC(layer, "SHARED_GATE_ACQUIRE");
    else moe_ltrace::BCExpert(layer, "GATE_ACQUIRE", expertId);
    if (!HostGemv(gt, g, hidden, gate.data(), I, H, "gate", error))
        return false;
    if (!HostGemv(ut, u, hidden, up.data(), I, H, "up", error)) return false;
    SiluMul(gate.data(), up.data(), I);
    if (!HostGemv(dt, d, gate.data(), out, H, I, "down", error)) return false;
    if (shared) moe_ltrace::BC(layer, "SHARED_DOWN_DONE");
    else moe_ltrace::BCExpert(layer, "DOWN_DONE", expertId);
    return true;
}

} // namespace

bool K2MoEExecExpert(const GlobalTensorIndex& index, const KimiK2Config& cfg,
                     uint32_t layer, int expertId, unsigned stick,
                     const float* hidden, float* expertOut, std::string& error) {
    size_t H = cfg.hiddenDim, I = cfg.moeIntermediateSize
                                       ? cfg.moeIntermediateSize
                                       : 2048u;
    size_t Hs = 0, Is = 0;
    if (MoEDimsFromGate(index, layer, Hs, Is, error)) {
        H = Hs;
        I = Is;
    } else
        error.clear();

    const bool wantGpu =
        (DualStickState().armed || DualStickState().planned ||
         DualStickState().requested) &&
        DualStickVc(stick) != nullptr;
    if (wantGpu) {
        if (DualStickBundlePinsReady(stick, (int)layer, expertId, H, I)) {
            MoELiveAdd(MoEPlaceLive().host_bytes_for_hit, 0);
            if (K2MoEExecExpertGpu(stick, 0, nullptr, 0, 0, nullptr, 0, 0,
                                   nullptr, 0, hidden, expertOut, H, I, layer,
                                   expertId))
                return true;
        }
        char gateN[64], upN[64], downN[64];
        std::snprintf(gateN, sizeof(gateN), "blk.%u.ffn_gate_exps.weight",
                      layer);
        std::snprintf(upN, sizeof(upN), "blk.%u.ffn_up_exps.weight", layer);
        std::snprintf(downN, sizeof(downN), "blk.%u.ffn_down_exps.weight",
                      layer);
        std::vector<uint8_t> gateB, upB, downB;
        int gt = 12, ut = 12, dt = 12;
        size_t gb = 0, ub = 0, db = 0;
        if (!ReadExpertSlice(index, gateN, (uint32_t)expertId, gateB, gt, gb,
                             error))
            return false;
        if (!ReadExpertSlice(index, upN, (uint32_t)expertId, upB, ut, ub, error))
            return false;
        if (!ReadExpertSlice(index, downN, (uint32_t)expertId, downB, dt, db,
                             error))
            return false;
        MoELiveAdd(MoEPlaceLive().host_bytes_for_miss, (uint64_t)gb + ub + db);
        if (K2MoEExecExpertGpu(stick, gt, gateB.data(), gb, ut, upB.data(), ub,
                               dt, downB.data(), db, hidden, expertOut, H, I,
                               layer, expertId))
            return true;
        /* Enterprise bind: never host-buffer DispatchGEMVQuant / host GEMV. */
        error = "DualStick device SubmitExpert failed (no host fallback)";
        return false;
    }

    char gateN[64], upN[64], downN[64];
    std::snprintf(gateN, sizeof(gateN), "blk.%u.ffn_gate_exps.weight", layer);
    std::snprintf(upN, sizeof(upN), "blk.%u.ffn_up_exps.weight", layer);
    std::snprintf(downN, sizeof(downN), "blk.%u.ffn_down_exps.weight", layer);
    std::vector<uint8_t> gateB, upB, downB;
    int gt = 12, ut = 12, dt = 12;
    size_t gb = 0, ub = 0, db = 0;
    if (!ReadExpertSlice(index, gateN, (uint32_t)expertId, gateB, gt, gb, error))
        return false;
    if (!ReadExpertSlice(index, upN, (uint32_t)expertId, upB, ut, ub, error))
        return false;
    if (!ReadExpertSlice(index, downN, (uint32_t)expertId, downB, dt, db, error))
        return false;
    MoELiveAdd(MoEPlaceLive().host_bytes_for_miss, (uint64_t)gb + ub + db);
    MoELiveAdd(MoEPlaceLive().host_gemv_expert, 1);
    return SwiGLUHost(gateB.data(), gt, upB.data(), ut, downB.data(), dt, hidden,
                      expertOut, H, I, layer, expertId, false, error);
}

bool K2MoEExecShared(const GlobalTensorIndex& index, const KimiK2Config& cfg,
                     uint32_t layer, const float* hidden, float* sharedOut,
                     std::string& error) {
    char gateN[64], upN[64], downN[64];
    std::snprintf(gateN, sizeof(gateN), "blk.%u.ffn_gate_shexp.weight", layer);
    std::snprintf(upN, sizeof(upN), "blk.%u.ffn_up_shexp.weight", layer);
    std::snprintf(downN, sizeof(downN), "blk.%u.ffn_down_shexp.weight", layer);
    WeightSpan gs{}, us{}, ds{};
    std::vector<uint8_t> gBuf, uBuf, dBuf;
    if (!ResolveWeight(index, gateN, gs, gBuf, error)) return false;
    if (!ResolveWeight(index, upN, us, uBuf, error)) return false;
    if (!ResolveWeight(index, downN, ds, dBuf, error)) return false;
    auto gRef = index.Find(gateN);
    auto uRef = index.Find(upN);
    auto dRef = index.Find(downN);
    if (!gRef || !uRef || !dRef) {
        error = "shared expert refs missing";
        return false;
    }
    size_t H = cfg.hiddenDim;
    size_t I = cfg.moeIntermediateSize ? cfg.moeIntermediateSize : 2048u;
    if (gRef->shape.size() >= 2 && gRef->shape[0] && gRef->shape[1]) {
        H = (size_t)gRef->shape[0];
        I = (size_t)gRef->shape[1];
    }
    const uint8_t* gp = gs.data ? gs.data : gBuf.data();
    const uint8_t* up = us.data ? us.data : uBuf.data();
    const uint8_t* dp = ds.data ? ds.data : dBuf.data();
    /* Shared stays host; HOST_GEMV_EXPERT counts routed experts only. */
    return SwiGLUHost(gp, (int)gRef->ggmlType, up, (int)uRef->ggmlType, dp,
                      (int)dRef->ggmlType, hidden, sharedOut, H, I, layer, -1,
                      true, error);
}

} // namespace Deep2
