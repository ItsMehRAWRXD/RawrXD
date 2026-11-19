#include "QwenGdnHost.hpp"
#include "op_gdn.hpp"
#include "vulkan_compute.h"

#include <cmath>
#include <cstring>

namespace Deep2 {
namespace {

bool CopyF32Prefix(const WeightTensor& wt, std::vector<float>& out, size_t n,
                   std::string& err, const char* tag) {
    if (!wt.data || n == 0) {
        err = std::string("GDN: missing ") + tag;
        return false;
    }
    if (wt.type != 0 /* GGML_TYPE_F32 */) {
        err = std::string("GDN: non-F32 ") + tag + " unsupported on host path";
        return false;
    }
    if (wt.sizeBytes < n * sizeof(float)) {
        err = std::string("GDN: short ") + tag;
        return false;
    }
    out.resize(n);
    std::memcpy(out.data(), wt.data, n * sizeof(float));
    return true;
}

} // namespace

bool RunQwenGdnRecurrence(const LayerWeights& lw, const QwenGdnMeta& meta,
                          const std::vector<float>& qkv,
                          const std::vector<float>& gate,
                          const std::vector<float>& alpha,
                          const std::vector<float>& beta,
                          std::vector<float>& state,
                          std::vector<float>& convState,
                          uint8_t& gpuActive, uint64_t stateKey,
                          std::vector<float>& recurrentOut,
                          std::string& err) {
    if (!IsQwenGdnLayer(lw)) {
        err = "GDN: unsupported or incomplete layer binding";
        return false;
    }
    if (!meta.bound || meta.stateSize == 0 || meta.groupCount == 0) {
        err = "GDN: model metadata ssm.state_size/group_count missing";
        return false;
    }

    const size_t qkvWidth = qkv.size();
    const size_t gateWidth = gate.size();
    const size_t valueHeads = alpha.size();
    constexpr size_t kHeadDim = 128;
    if (qkvWidth == 0 || gateWidth == 0 || valueHeads == 0 ||
        beta.size() != valueHeads ||
        (qkvWidth % kHeadDim) != 0 || (gateWidth % kHeadDim) != 0 ||
        gateWidth != valueHeads * kHeadDim) {
        err = "GDN: qkv/gate/alpha geometry inconsistent";
        return false;
    }
    const size_t keyHeads = (qkvWidth / kHeadDim - valueHeads) / 2;
    if (keyHeads == 0 ||
        (2 * keyHeads + valueHeads) != qkvWidth / kHeadDim) {
        err = "GDN: key/value head geometry inconsistent";
        return false;
    }

    const size_t convKernel = meta.convKernel > 0 ? meta.convKernel : 4;
    std::vector<float> convWeights;
    if (!CopyF32Prefix(lw.ssmConv1d, convWeights, convKernel * qkvWidth, err, "conv"))
        return false;

    const size_t historyWidth = (convKernel - 1) * qkvWidth;
    if (convState.size() != historyWidth)
        convState.assign(historyWidth, 0.0f);

    std::vector<float> mixed(qkvWidth, 0.0f);
    for (size_t ch = 0; ch < qkvWidth; ++ch) {
        float value = 0.0f;
        for (size_t tap = 0; tap < convKernel; ++tap) {
            const float sample = (tap + 1 == convKernel)
                ? qkv[ch]
                : convState[ch * (convKernel - 1) + tap];
            value += convWeights[ch * convKernel + tap] * sample;
        }
        mixed[ch] = value / (1.0f + std::exp(-value));
    }
    for (size_t ch = 0; ch < qkvWidth; ++ch) {
        for (size_t tap = 0; tap + 1 < convKernel - 1; ++tap)
            convState[ch * (convKernel - 1) + tap] =
                convState[ch * (convKernel - 1) + tap + 1];
        if (convKernel >= 2)
            convState[ch * (convKernel - 1) + (convKernel - 2)] = qkv[ch];
    }

    Qwen4Exp::GDNDescriptor desc{};
    desc.channels = static_cast<uint32_t>(gateWidth);
    desc.state_size = meta.stateSize;
    desc.groups = meta.groupCount;
    desc.key_heads = static_cast<uint32_t>(keyHeads);
    desc.value_heads = static_cast<uint32_t>(valueHeads);
    desc.head_dim = static_cast<uint32_t>(kHeadDim);
    desc.tokens = 1;
    desc.scale = 1.0f / std::sqrt(static_cast<float>(kHeadDim));
    desc.stride = desc.channels;
    desc.qkv_stride = static_cast<uint32_t>(qkvWidth);
    desc.gate_stride = static_cast<uint32_t>(gateWidth);
    desc.epsilon = 1e-6f;
    std::string failure;
    if (!Qwen4Exp::ValidateGDNDescriptor(desc, failure)) {
        err = "GDN: " + failure;
        return false;
    }

    std::vector<float> aLog, dtBias, norm;
    if (!CopyF32Prefix(lw.ssmA, aLog, valueHeads, err, "A") ||
        !CopyF32Prefix(lw.ssmDtBias, dtBias, valueHeads, err, "dt") ||
        !CopyF32Prefix(lw.ssmNorm, norm, kHeadDim, err, "norm"))
        return false;

    const size_t qwenState = Qwen4Exp::GDNQwenStateElements(desc);
    if (qwenState == 0) {
        err = "GDN: state geometry overflow";
        return false;
    }
    if (state.size() != qwenState)
        state.assign(qwenState, 0.0f);

    bool gpuOk = false;
    {
        std::vector<float> gpuOut;
        auto& gpu = GetDeep2VulkanCompute();
        if (gpu.DispatchGdn(mixed.data(), mixed.size(), beta.data(), beta.size(),
                            alpha.data(), alpha.size(), aLog.data(), aLog.size(),
                            dtBias.data(), dtBias.size(), norm.data(), norm.size(),
                            gate.data(), gate.size(),
                            static_cast<uint32_t>(keyHeads),
                            static_cast<uint32_t>(valueHeads),
                            static_cast<uint32_t>(kHeadDim),
                            desc.epsilon, desc.scale, false, stateKey, gpuOut)) {
            recurrentOut.swap(gpuOut);
            gpuActive = 1;
            gpuOk = true;
        } else if (gpuActive) {
            err = "GDN: Vulkan stateful dispatch failed after GPU state authoritative";
            return false;
        }
    }
    if (!gpuOk) {
        if (!Qwen4Exp::GDNQwenReferenceStep(desc, mixed, beta, alpha, aLog, dtBias,
                                            norm, gate, state, recurrentOut,
                                            failure)) {
            err = "GDN: " + failure;
            return false;
        }
    }
    return true;
}

} // namespace Deep2
