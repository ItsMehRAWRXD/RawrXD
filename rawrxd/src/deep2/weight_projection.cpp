// ============================================================================
// weight_projection.cpp — AVX-512 host-staged weight upload
// ============================================================================
#include "weight_projection.h"

#include <algorithm>
#include <stdexcept>
#include <cstring>

namespace Deep2 {

// ----------------------------------------------------------------------------
// AVX-512 non-temporal FMA transform (F32 only)
// ----------------------------------------------------------------------------
void WeightProjectionTransformF32(
    const float* __restrict src,
    float*       __restrict dst,
    size_t                  count,
    float                   scale,
    float                   bias) noexcept
{
    size_t i = 0;
#if defined(__AVX512F__) || defined(RAWRXD_HAS_AVX512)
    const __m512 vscale = _mm512_set1_ps(scale);
    const __m512 vbias  = _mm512_set1_ps(bias);

    for (; i + 63 < count; i += 64) {
        __m512 a = _mm512_loadu_ps(src + i);
        __m512 b = _mm512_loadu_ps(src + i + 16);
        __m512 c = _mm512_loadu_ps(src + i + 32);
        __m512 d = _mm512_loadu_ps(src + i + 48);

        _mm512_stream_ps(dst + i,      _mm512_fmadd_ps(a, vscale, vbias));
        _mm512_stream_ps(dst + i + 16, _mm512_fmadd_ps(b, vscale, vbias));
        _mm512_stream_ps(dst + i + 32, _mm512_fmadd_ps(c, vscale, vbias));
        _mm512_stream_ps(dst + i + 48, _mm512_fmadd_ps(d, vscale, vbias));
    }
    _mm_sfence();
#endif
    for (; i < count; ++i)
        dst[i] = src[i] * scale + bias;
}

// ----------------------------------------------------------------------------
// WeightProjectionUpload
// ----------------------------------------------------------------------------
bool WeightProjectionUpload(
    VulkanCompute&          gpu,
    const GGUFTensor&       tensor,
    const ProjectionConfig& cfg,
    uint64_t                cacheKey,
    uint64_t                epoch)
{
    if (!gpu.initialized())
        return false;

    const uint8_t* src      = tensor.data;
    const size_t   total    = tensor.sizeBytes;
    const size_t   chunk    = std::max(cfg.chunkBytes, size_t{4096});
    const bool     isF32    = (tensor.type == GGMLType::GGML_TYPE_F32);
    const bool     needXfrm = isF32 && (cfg.scale != 1.0f || cfg.bias != 0.0f);

    // Allocate a host-side aligned transform buffer only when needed.
    // For quantized tensors the raw bytes go straight to the staging upload.
    std::vector<float> xfrmBuf;
    if (needXfrm)
        xfrmBuf.resize(chunk / sizeof(float));

    // Double-buffered MaterialTickets: while GPU copies slot N, CPU fills N^1.
    VulkanCompute::MaterialTicket tickets[2]{};
    int   active   = 0;
    bool  inflight = false;

    size_t offset = 0;
    while (offset < total) {
        const size_t thisChunk = std::min(chunk, total - offset);
        const uint8_t* chunkSrc = src + offset;

        // If a transform is needed, apply it into the aligned buffer first.
        if (needXfrm) {
            const size_t floats = thisChunk / sizeof(float);
            xfrmBuf.resize(floats);
            WeightProjectionTransformF32(
                reinterpret_cast<const float*>(chunkSrc),
                xfrmBuf.data(),
                floats,
                cfg.scale,
                cfg.bias);
            chunkSrc = reinterpret_cast<const uint8_t*>(xfrmBuf.data());
        }

        // Wait for the previous use of this slot before resubmitting.
        if (inflight) {
            if (!gpu.WaitMaterialUpload(tickets[active]))
                return false;
        }

        if (!gpu.SubmitMaterialUploadAsync(chunkSrc, thisChunk, epoch,
                                           tickets[active]))
            return false;

        inflight = true;
        active   = 1 - active;
        offset  += thisChunk;
    }

    // Drain the last in-flight ticket.
    if (inflight) {
        const int last = 1 - active;
        if (!gpu.WaitMaterialUpload(tickets[last]))
            return false;
    }

    // Commit the final ticket into the weight cache so DispatchGemvQuant
    // can find it by cacheKey.
    return gpu.CommitWeightPrime(
        tickets[1 - active],
        static_cast<int>(tensor.type),
        cacheKey);
}

} // namespace Deep2
