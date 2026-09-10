// XR_RealMath.hpp — C ABI for xr_realmath climb kernels (Win64).
#pragma once
#include <cstdint>

extern "C" {

/* rcx=x in-place, rdx=count — SiLU: x/(1+exp(-x)); eax=0 */
int XR_SiLU_F32(float* x, uint64_t n);

/* rcx=scores in-place, rdx=count — stable SoftMax; eax=0 ok, 1 bad */
int XR_Softmax_F32(float* x, uint64_t n);

/* rcx=a, rdx=b, r8=n → xmm0 dot (MSVC: return float) */
float XR_Dot_F32(const float* a, const float* b, uint64_t n);

/* rcx=x, rdx=w, r8=n — RMSNorm*weight in-place; eax=0 ok */
int XR_RMSNorm_F32(float* x, const float* w, uint64_t n);

#pragma pack(push, 8)
struct XR_AttnCtx {
    const float* q;       /* [head_dim] */
    const float* k;       /* [seq*head_dim] */
    const float* v;       /* [seq*head_dim] */
    float* scores;        /* [seq] scratch */
    float* out;           /* [head_dim] */
    uint64_t seq_len;
    uint64_t head_dim;
};
#pragma pack(pop)

/* rcx=ctx — Q·K/√d SoftMax Σw·V; eax=0 ok */
int XR_AttentionHead_F32(XR_AttnCtx* ctx);

/* rcx=gate, rdx=up, r8=dst, r9=n — dst[i]=SiLU(gate[i])*up[i]; eax=0 */
int XR_SwiGLU_F32(const float* gate, const float* up, float* dst, uint64_t n);

}
