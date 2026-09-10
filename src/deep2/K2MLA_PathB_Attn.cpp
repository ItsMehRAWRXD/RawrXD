// K2MLA_PathB_Attn.cpp — Everything: device Q→pack→attn; host KV = oracle
#include "K2MLA_PathB.hpp"
#include <cmath>
#include <cstring>
#include <vector>

namespace Deep2 {
namespace {
void ropeNeoX(float* x, size_t dim, uint32_t pos, float theta, float scale) {
    if (dim < 2 || (dim & 1u)) return;
    const size_t half = dim / 2;
    const float inv = (scale > 0.0f) ? (1.0f / scale) : 1.0f;
    const float epos = static_cast<float>(pos) * inv;
    for (size_t i = 0; i < half; ++i) {
        const float freq =
            1.0f / powf(theta, (2.0f * (float)i) / (float)dim);
        const float ang = epos * freq;
        const float c = cosf(ang), s = sinf(ang);
        const float x0 = x[i], x1 = x[i + half];
        x[i] = x0 * c - x1 * s;
        x[i + half] = x0 * s + x1 * c;
    }
}
} // namespace

bool PathBAttend(CPUInference::VulkanCompute* vc,
                 CPUInference::VulkanCompute::DeviceBuf& qDev,
                 const float* k_b, const float* v_b, const float* k_pe,
                 float* attnOut, rawrxd::deep2::K2KVCache* kvCache,
                 uint32_t nHeads, uint32_t nope, uint32_t rope, uint32_t vDim,
                 uint32_t pos, uint32_t layer, uint32_t maxSeq, uint32_t nLayers,
                 float theta, float ropeScale, std::string& error) {
    if (!vc || !k_b || !v_b || !k_pe || !attnOut || !kvCache) {
        error = "PathBAttend: null";
        return false;
    }
    auto* qPtr = PathB_QDev();
    auto& qUse = (qPtr && qPtr->buffer) ? *qPtr : qDev;
    if (!qUse.buffer) {
        error = "PathBAttend: no device Q";
        return false;
    }
    const uint32_t qk = nope + rope;
    const uint32_t cachePos = (uint32_t)kvCache->currentLength();
    if (pos != cachePos) {
        error = "PathBAttend: position!=cacheLen";
        return false;
    }
    uint32_t seqCap = maxSeq;
    if (seqCap > 512u) seqCap = 512u;
    if (seqCap < 8u) seqCap = 8u;
    if (cachePos >= seqCap) {
        error = "PathBAttend: seqCap";
        return false;
    }
    if (!qUse.buffer || qUse.bytes < (size_t)nHeads * qk * 4ull) {
        error = "PathBAttend: Q buf 0x0/undersized";
        return false;
    }
    if (!vc->EnsureMlaAttn(nHeads, qk, vDim, nope, rope, seqCap, nLayers)) {
        error = "PathBAttend: EnsureMlaAttn";
        return false;
    }
    if (!vc->UploadBuf(vc->MlaKb(), k_b, nHeads * nope) ||
        !vc->UploadBuf(vc->MlaVb(), v_b, nHeads * vDim) ||
        !vc->UploadBuf(vc->MlaKpe(), k_pe, rope)) {
        error = "PathBAttend: KV H2D";
        return false;
    }
    const float scale = 1.0f / sqrtf((float)qk);
    if (!vc->DispatchAttnDecodeMLA(qUse, vc->MlaKb(), vc->MlaVb(), vc->MlaKpe(),
                                   vc->MlaAttnOut(), qk, vDim, nope, rope, nHeads,
                                   cachePos, theta, scale, ropeScale, layer)) {
        error = "PathBAttend: dispatch";
        return false;
    }
    if (!vc->DownloadBuf(vc->MlaAttnOut(), attnOut, nHeads * vDim)) {
        error = "PathBAttend: attnOut D2H";
        return false;
    }
    std::vector<float> kpeR(rope), kCur(kvCache->kvDim(), 0.f),
        vCur(kvCache->kvDim(), 0.f);
    std::memcpy(kpeR.data(), k_pe, rope * sizeof(float));
    ropeNeoX(kpeR.data(), rope, pos, theta, ropeScale);
    for (uint32_t h = 0; h < nHeads; ++h) {
        float* kh = kCur.data() + h * qk;
        std::memcpy(kh, k_b + h * nope, nope * sizeof(float));
        std::memcpy(kh + nope, kpeR.data(), rope * sizeof(float));
        std::memcpy(vCur.data() + h * vDim, v_b + h * vDim, vDim * sizeof(float));
    }
    try {
        kvCache->Write(layer, kCur.data(), vCur.data());
    } catch (const std::exception& ex) {
        error = std::string("PathBAttend: host KV oracle: ") + ex.what();
        return false;
    }
    PathB_ClearQDev();
    (void)maxSeq; (void)nLayers;
    return true;
}

} // namespace Deep2
