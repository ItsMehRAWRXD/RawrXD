// XR_K2_RealAttention.hpp — C ABI for K2 real reference lane
#pragma once
#include <cstdint>

extern "C" {

int XR_SiLU_F32(float* x, uint64_t n);
int XR_Softmax_F32(float* x, uint64_t n);
float XR_Dot_F32(const float* a, const float* b, uint64_t n);
/* rcx=gate rdx=up r8=dst r9=n — dst[i]=SiLU(gate[i])*up[i] */
int XR_SwiGLU_F32(float* gate, const float* up, float* dst, uint64_t n);

#pragma pack(push, 8)
struct XR_AttnCtx {
    const float* q;
    const float* k;
    const float* v;
    float* scores;
    float* out;
    uint64_t seq_len;
    uint64_t head_dim;
};
#pragma pack(pop)

int XR_AttentionHead_F32(XR_AttnCtx* ctx);

}
