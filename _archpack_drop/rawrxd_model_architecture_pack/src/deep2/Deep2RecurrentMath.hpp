#pragma once
// RAWRXD_MODEL_ARCH_PACK_001
// Pure C++20 reference recurrent math.  No Win32, Vulkan, GGML or external deps.
//
// This is deliberately scalar/reference code.  Its job is correctness authority
// and CPU bring-up for architectures whose GPU kernel is not wired yet.
// Production Vulkan kernels can implement the same contracts later.

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace Deep2::Arch::Ref {

inline float sigmoid(float x) noexcept {
    if (x >= 0.0f) {
        const float z = std::exp(-x);
        return 1.0f / (1.0f + z);
    }
    const float z = std::exp(x);
    return z / (1.0f + z);
}

inline float softplus(float x) noexcept {
    if (x > 20.0f) return x;
    if (x < -20.0f) return std::exp(x);
    return std::log1p(std::exp(x));
}

inline float silu(float x) noexcept {
    return x * sigmoid(x);
}

inline void l2Normalize(float* x, std::size_t n, float eps) {
    double ss = 0.0;
    for (std::size_t i=0;i<n;++i) ss += double(x[i])*double(x[i]);
    const float inv = 1.0f / std::sqrt(float(ss) + eps);
    for (std::size_t i=0;i<n;++i) x[i] *= inv;
}

inline void rmsNormGated(float* y, const float* weight, const float* gate,
                         std::size_t headDim, std::size_t heads, float eps) {
    for (std::size_t h=0; h<heads; ++h) {
        float* p = y + h*headDim;
        const float* g = gate + h*headDim;
        double ss=0.0;
        for(std::size_t d=0; d<headDim; ++d) ss += double(p[d])*double(p[d]);
        const float inv=1.0f/std::sqrt(float(ss/double(headDim))+eps);
        for(std::size_t d=0; d<headDim; ++d) {
            const float w = weight ? weight[d] : 1.0f;
            p[d] = p[d]*inv*w*silu(g[d]);
        }
    }
}

// Per-channel causal depthwise convolution.
// history layout: [channels][kernel-1], oldest -> newest.
// kernel layout:  [channels][kernel], oldest -> newest.
inline void depthwiseConvStep(const float* input, std::size_t channels,
                              const float* kernel, std::size_t kernelSize,
                              float* history, const float* bias,
                              float* output) {
    if (!input || !kernel || !output || !kernelSize) throw std::runtime_error("depthwiseConvStep: invalid args");
    const std::size_t hist = kernelSize - 1;
    for(std::size_t c=0;c<channels;++c) {
        float acc = bias ? bias[c] : 0.0f;
        const float* k = kernel + c*kernelSize;
        float* h = history + c*hist;
        for(std::size_t j=0;j<hist;++j) acc += h[j]*k[j];
        acc += input[c]*k[hist];
        output[c] = acc;
        if(hist) {
            for(std::size_t j=0;j+1<hist;++j) h[j]=h[j+1];
            h[hist-1]=input[c];
        }
    }
}

// Exact autoregressive Gated Delta Net recurrence used by Qwen3-Next/Qwen3.5:
//
//   S' = exp(g) * S + k outer [ beta * (v - exp(g) * S^T k) ]
//   y  = S'^T q
//
// State layout: [vHead][kDim][vDim].
inline void gatedDeltaNetStep(
    const float* q, const float* k, const float* v,
    const float* gateLog, const float* beta,
    std::size_t kHeads, std::size_t vHeads,
    std::size_t kDim, std::size_t vDim,
    float* state, float* output)
{
    if(!q||!k||!v||!gateLog||!beta||!state||!output)
        throw std::runtime_error("gatedDeltaNetStep: null");
    if(!kHeads||!vHeads||!kDim||!vDim||vHeads%kHeads)
        throw std::runtime_error("gatedDeltaNetStep: geometry");

    const std::size_t ratio=vHeads/kHeads;
    for(std::size_t vh=0; vh<vHeads; ++vh) {
        const std::size_t kh=vh/ratio;
        const float* qh=q+kh*kDim;
        const float* khv=k+kh*kDim;
        const float* vv=v+vh*vDim;
        float* S=state+vh*kDim*vDim;
        float* yy=output+vh*vDim;

        const float decay=std::exp(gateLog[vh]);
        const float b=beta[vh];

        std::vector<float> pred(vDim,0.0f);
        for(std::size_t kd=0; kd<kDim; ++kd) {
            const float kval=khv[kd];
            const float* row=S+kd*vDim;
            for(std::size_t vd=0; vd<vDim; ++vd)
                pred[vd]+=row[vd]*kval;
        }

        // CPU reference in upstream keeps state accumulation in fp32.
        for(std::size_t kd=0; kd<kDim; ++kd) {
            const float kval=khv[kd];
            float* row=S+kd*vDim;
            for(std::size_t vd=0; vd<vDim; ++vd) {
                const float delta=(vv[vd]-decay*pred[vd])*b;
                row[vd]=decay*row[vd]+kval*delta;
            }
        }

        std::fill(yy,yy+vDim,0.0f);
        for(std::size_t kd=0; kd<kDim; ++kd) {
            const float qval=qh[kd];
            const float* row=S+kd*vDim;
            for(std::size_t vd=0; vd<vDim; ++vd)
                yy[vd]+=row[vd]*qval;
        }
    }
}

// Reference selective SSM/Mamba2 autoregressive step.
// State layout: [head][headDim][stateDim].
// B/C are group-shared state vectors; x is [head][headDim].
// A is per-head negative transition coefficient (normally -exp(A_log)).
// D is per-head skip coefficient.
inline void mamba2Step(
    const float* x, const float* B, const float* C,
    const float* dt, const float* A, const float* D,
    std::size_t heads, std::size_t groups,
    std::size_t headDim, std::size_t stateDim,
    float* state, float* y)
{
    if(!x||!B||!C||!dt||!A||!D||!state||!y)
        throw std::runtime_error("mamba2Step: null");
    if(!heads||!groups||!headDim||!stateDim||heads%groups)
        throw std::runtime_error("mamba2Step: geometry");
    const std::size_t ratio=heads/groups;

    for(std::size_t h=0;h<heads;++h) {
        const std::size_t g=h/ratio;
        const float delta=softplus(dt[h]);
        const float decay=std::exp(delta*A[h]); // A must be <= 0
        const float* b=B+g*stateDim;
        const float* c=C+g*stateDim;
        for(std::size_t d=0;d<headDim;++d) {
            const float xv=x[h*headDim+d];
            float* s=state+(h*headDim+d)*stateDim;
            float acc=0.0f;
            for(std::size_t n=0;n<stateDim;++n) {
                s[n]=decay*s[n]+delta*b[n]*xv;
                acc+=s[n]*c[n];
            }
            y[h*headDim+d]=acc+D[h]*xv;
        }
    }
}

inline bool finite(const float* p,std::size_t n) noexcept {
    if(!p) return false;
    for(std::size_t i=0;i<n;++i) if(!std::isfinite(p[i])) return false;
    return true;
}

} // namespace Deep2::Arch::Ref
