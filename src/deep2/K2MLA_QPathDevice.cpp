// K2MLA_QPathDevice.cpp — fused Q_A→RMS→Q_B (one submit)
#include "K2MLA_QPathDevice.hpp"
#include "K2GpuStreamCopy.hpp"
#include "K2MLA_GpuGemv.hpp"
#include "vulkan_compute.h"
#include <cstdlib>

namespace Deep2 {

bool MLA_QPathDeviceFused(const float* hidden, float* q_a, float* q_b,
                          const RawrXD::TensorView& wQa,
                          const RawrXD::TensorView& wQb,
                          const RawrXD::TensorView& wNorm, bool haveNorm,
                          uint32_t hiddenDim, uint32_t qLora, uint32_t qBCols,
                          float eps, uint32_t layerIdx) {
    const char* on = std::getenv("DEEP2_MLA_Q_DEVICE");
    if (!(on && on[0] == '1')) return false;
    if (!MLA_GpuGemvWanted() || !hidden || !q_a || !q_b) return false;
    if (wQa.quantType() != RawrXD::QuantType::Q4_K ||
        wQb.quantType() != RawrXD::QuantType::Q4_K || !wQa.data() || !wQb.data())
        return false;
    if (haveNorm &&
        (wNorm.quantType() != RawrXD::QuantType::F32 || !wNorm.asF32()))
        return false;
    auto* vc = K2GpuStreamCopy_Vc();
    if (!vc) return false;
    const size_t inB = (size_t)hiddenDim * 4u;
    const size_t midB = (size_t)qLora * 4u;
    const size_t outB = (size_t)qBCols * 4u;
    const size_t actIn = (std::max)(inB, midB);
    const size_t actOut = (std::max)(midB, outB);
    // RMSNorm pipeline + Arena live in EnsureForwardArena.
    if (!vc->EnsureForwardArena(hiddenDim, hiddenDim, qBCols, 1, 1, 1, 1) ||
        !vc->EnsureHostIo(actIn, actOut) || !vc->EnsureGemvActDevice(actIn, actOut) ||
        !vc->GemvHostWriteIn(hidden, inB)) {
        MLA_QPathDevice_NoteFail(); return false;
    }
    const uint64_t pkA = ((uint64_t)layerIdx << 8) | 1ull;
    const uint64_t pkB = ((uint64_t)layerIdx << 8) | 2ull;
    const uint64_t pkN = ((uint64_t)layerIdx << 8) | 0xF1ull;
    VkBuffer wA = nullptr, wB = nullptr, wN = nullptr;
    if (!vc->EnsurePinnedPackedWeight(wQa.data(), wQa.byteSize(), qLora,
                                      hiddenDim, wA, pkA) ||
        !vc->EnsurePinnedPackedWeight(wQb.data(), wQb.byteSize(), qBCols, qLora,
                                      wB, pkB)) {
        MLA_QPathDevice_NoteFail(); return false;
    }
    CPUInference::VulkanCompute::DeviceBuf normBuf{};
    if (haveNorm) {
        if (!vc->EnsurePinnedF32(wNorm.asF32(), qLora, wN, pkN)) {
            MLA_QPathDevice_NoteFail(); return false;
        }
        normBuf.buffer = wN;
        normBuf.bytes = midB;
    }
    (void)wA; (void)wB;
    if (!vc->BeginFusedLayer()) { MLA_QPathDevice_NoteFail(); return false; }
    auto fail = [&]() -> bool {
        (void)vc->EndFusedLayer();
        MLA_QPathDevice_NoteFail();
        return false;
    };
    auto& aIn = vc->GemvActIn();
    auto& aOut = vc->GemvActOut();
    if (!vc->RecordCopy(vc->GemvHostInBuffer(), aIn.buffer, 0, 0, inB))
        return fail();
    if (!vc->DispatchGemvPacked(wQa.data(), wQa.byteSize(), aIn, aOut, qLora,
                                hiddenDim, pkA))
        return fail();
    if (haveNorm) {
        if (!vc->DispatchRmsNorm(aOut, normBuf, aIn, qLora, eps)) return fail();
        if (!vc->DispatchGemvPacked(wQb.data(), wQb.byteSize(), aIn, aOut, qBCols,
                                    qLora, pkB))
            return fail();
    } else if (!vc->DispatchGemvPacked(wQb.data(), wQb.byteSize(), aOut, aIn,
                                       qBCols, qLora, pkB)) {
        return fail();
    }
    const VkBuffer qOut = haveNorm ? aOut.buffer : aIn.buffer;
    if (!vc->RecordCopy(qOut, vc->GemvHostOutBuffer(), 0, 0, outB)) return fail();
    if (!vc->EndFusedLayer() || !vc->GemvHostReadOut(q_b, outB)) {
        MLA_QPathDevice_NoteFail(); return false;
    }
    (void)q_a;
    MLA_QPathDevice_NoteOk();
    return true;
}

} // namespace Deep2
