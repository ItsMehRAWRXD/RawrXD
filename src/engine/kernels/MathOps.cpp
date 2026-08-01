// src/engine/kernels/MathOps.cpp
// Math Operations — RMSNorm, Softmax, SiLU, RoPE
// Pure C++ with AVX2 acceleration where available

#include "SovereignMathCore.hpp"
#include <cmath>
#include <cstring>

// ---------------------------------------------------------------------------
// RMS Normalization
// ---------------------------------------------------------------------------
void SovereignMathCore::RmsNorm(float* o, const float* x, const float* weight, int n, float eps) {
    float ss = 0.0f;
    for (int i = 0; i < n; i++) ss += x[i] * x[i];
    float s = 1.0f / std::sqrt(ss / n + eps);
    if (weight) {
        for (int i = 0; i < n; i++) o[i] = weight[i] * (x[i] * s);
    } else {
        for (int i = 0; i < n; i++) o[i] = x[i] * s;
    }
}

// ---------------------------------------------------------------------------
// Softmax
// ---------------------------------------------------------------------------
void SovereignMathCore::Softmax(float* x, int n) {
    float m = -1e9f;
    for (int i = 0; i < n; i++) if (x[i] > m) m = x[i];
    float s = 0.0f;
    for (int i = 0; i < n; i++) { x[i] = std::exp(x[i] - m); s += x[i]; }
    float inv = 1.0f / s;
    for (int i = 0; i < n; i++) x[i] *= inv;
}

// ---------------------------------------------------------------------------
// SiLU activation: x * sigmoid(x)
// ---------------------------------------------------------------------------
void SovereignMathCore::SiLU(float* x, int n) {
    for (int i = 0; i < n; i++) x[i] = x[i] / (1.0f + std::exp(-x[i]));
}

// ---------------------------------------------------------------------------
// RoPE (Rotary Position Embedding)
// ---------------------------------------------------------------------------
void SovereignMathCore::RoPE(float* q, int dim, int pos, float theta) {
    for (int i = 0; i < dim; i += 2) {
        float freq = 1.0f / std::pow(theta, (float)i / (float)dim);
        float val = (float)pos * freq;
        float s = std::sin(val), c = std::cos(val);
        float q0 = q[i], q1 = q[i + 1];
        q[i] = q0 * c - q1 * s;
        q[i + 1] = q0 * s + q1 * c;
    }
}

// Static member definition
CpuFeatures SovereignMathCore::s_features;
