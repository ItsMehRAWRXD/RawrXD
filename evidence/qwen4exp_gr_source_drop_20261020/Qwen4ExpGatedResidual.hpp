#pragma once
// Qwen4-Exp gated residual arithmetic reference. C++20, STL only.
// This module is a numerical contract, NOT a certified Vulkan implementation.
// Matrices are row-major [out_features, in_features].

#include <cmath>
#include <cstddef>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace deep2::qwen4exp {

struct GRShape {
    std::size_t streams;      // hc_count
    std::size_t hidden;       // hidden_size per stream
    std::size_t lowrank;      // hc_lowrank
    float rms_eps = 1.0e-6f;
};

struct GRWeights {
    std::span<const float> norm_delta; // [streams*hidden], effective gamma=1+delta
    std::span<const float> mix_down;   // [lowrank, streams*hidden]
    std::span<const float> mix_up;     // [streams*hidden, lowrank]
    std::span<const float> inject;     // [streams, streams*hidden], absent for final combine-less GR
};

struct GRRead {
    std::vector<float> mixed;     // [hidden] next attention / MoE input
    std::vector<float> residual;  // [streams*hidden] unchanged input
    std::vector<float> injection; // [streams] weights or empty if use_combine=false
};

inline void require(bool ok, const char* reason) {
    if (!ok) throw std::invalid_argument(reason);
}

inline std::size_t checked_product(std::size_t a, std::size_t b) {
    require(a && b && a <= std::numeric_limits<std::size_t>::max() / b,
            "Qwen4Exp GR: invalid or overflowing dimensions");
    return a * b;
}

inline void finite(std::span<const float> data) {
    for (float f : data)
        require(std::isfinite(f), "Qwen4Exp GR: non-finite input or weight");
}

inline float sigmoid(float x) noexcept {
    if (x >= 0.0f) {
        const float z = std::exp(-x);
        return 1.0f / (1.0f + z);
    }
    const float z = std::exp(x);
    return z / (1.0f + z);
}

inline float silu(float x) noexcept { return x * sigmoid(x); }

// Reference GEMV. A GPU integration must replace this with its GPU-only
// dispatcher; do not silently use this routine from a GPU certification path.
inline std::vector<float> cpu_gemv(std::span<const float> matrix,
                                    std::span<const float> vector,
                                    std::size_t rows) {
    const std::size_t cols = vector.size();
    require(matrix.size() == checked_product(rows, cols), "Qwen4Exp GR: GEMV matrix shape mismatch");
    std::vector<float> result(rows, 0.0f);
    for (std::size_t r = 0; r < rows; ++r) {
        float sum = 0.0f;
        for (std::size_t c = 0; c < cols; ++c)
            sum += matrix[r * cols + c] * vector[c];
        result[r] = sum;
    }
    return result;
}

inline GRRead cpu_gr_read(std::span<const float> input,
                         const GRShape& sh,
                         const GRWeights& w,
                         bool use_combine = true) {
    const auto width = checked_product(sh.streams, sh.hidden);
    checked_product(sh.lowrank, width);
    require(std::isfinite(sh.rms_eps) && sh.rms_eps > 0.0f,
            "Qwen4Exp GR: invalid RMS epsilon");
    require(input.size() == width, "Qwen4Exp GR: residual shape mismatch");
    require(w.norm_delta.size() == width, "Qwen4Exp GR: norm shape mismatch");
    require(w.mix_down.size() == sh.lowrank * width, "Qwen4Exp GR: mixer down shape mismatch");
    require(w.mix_up.size() == width * sh.lowrank, "Qwen4Exp GR: mixer up shape mismatch");
    require(use_combine || w.inject.empty(), "Qwen4Exp GR: unexpected injection weights");
    // Injection tensor is [streams, width].
    if (use_combine)
        require(w.inject.size() == checked_product(sh.streams, width),
                "Qwen4Exp GR: injection shape mismatch");
    finite(input);
    finite(w.norm_delta);
    finite(w.mix_down);
    finite(w.mix_up);
    finite(w.inject);

    std::vector<float> normed(width);
    for (std::size_t s = 0; s < sh.streams; ++s) {
        float sq = 0.0f;
        for (std::size_t d = 0; d < sh.hidden; ++d) {
            const float v = input[s * sh.hidden + d];
            sq += v * v;
        }
        const float inv = 1.0f / std::sqrt(sq / static_cast<float>(sh.hidden) + sh.rms_eps);
        for (std::size_t d = 0; d < sh.hidden; ++d) {
            const std::size_t i = s * sh.hidden + d;
            normed[i] = input[i] * inv * (1.0f + w.norm_delta[i]);
        }
    }
    finite(normed);

    auto low = cpu_gemv(w.mix_down, normed, sh.lowrank);
    for (auto& v : low) v = silu(v / static_cast<float>(sh.streams));
    auto gates = cpu_gemv(w.mix_up, low, width);
    for (auto& v : gates) v = sigmoid(v);

    GRRead result;
    result.mixed.assign(sh.hidden, 0.0f);
    result.residual.assign(input.begin(), input.end());
    for (std::size_t d = 0; d < sh.hidden; ++d) {
        float sum = 0.0f;
        for (std::size_t s = 0; s < sh.streams; ++s) {
            const std::size_t i = s * sh.hidden + d;
            sum += gates[i] * normed[i];
        }
        result.mixed[d] = sum / static_cast<float>(sh.streams);
    }
    if (use_combine) {
        result.injection = cpu_gemv(w.inject, normed, sh.streams);
        for (auto& v : result.injection)
            v = 2.0f * sigmoid(v / static_cast<float>(sh.streams));
    }
    finite(result.mixed);
    finite(result.injection);
    return result;
}

inline std::vector<float> cpu_gr_write(const GRRead& read,
                                       std::span<const float> block_output,
                                       const GRShape& sh) {
    const auto width = checked_product(sh.streams, sh.hidden);
    require(read.residual.size() == width && read.injection.size() == sh.streams &&
            block_output.size() == sh.hidden, "Qwen4Exp GR: write shape mismatch");
    finite(read.residual);
    finite(read.injection);
    finite(block_output);
    std::vector<float> updated = read.residual;
    for (std::size_t s = 0; s < sh.streams; ++s)
        for (std::size_t d = 0; d < sh.hidden; ++d)
            updated[s * sh.hidden + d] += read.injection[s] * block_output[d];
    finite(updated);
    return updated;
}

} // namespace deep2::qwen4exp
