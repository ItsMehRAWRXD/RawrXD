#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <numeric>
#include <random>
#include <string>
#include <vector>

#include "ggml.h"
#include "ggml-vulkan.h"
#include "generic_vulkan_matmul.hpp"

namespace {

bool RunType(ggml_type type, const char* label) {
    constexpr size_t rows = 16;
    constexpr size_t cols = 256;
    const size_t row_bytes = ggml_row_size(type, cols);
    std::vector<uint8_t> weights(row_bytes * rows);
    std::vector<float> source(cols * rows);
    std::vector<float> input(cols), gpu(rows), reference(rows);

    std::mt19937 rng(type == GGML_TYPE_IQ2_S ? 0x12a5u : 0x4f31u);
    std::uniform_real_distribution<float> input_dist(-1.0f, 1.0f);
    for (auto& value : source) value = input_dist(rng);
    for (auto& value : input) value = input_dist(rng);

    // Use GGML's own quantizer instead of arbitrary bytes.  This makes the
    // test exercise the same valid block encodings present in GGUF, including
    // IQ2_S's lookup-table metadata and MXFP4's E8M0 scales.
    std::vector<float> imatrix(cols, 1.0f);
    const float* importance = ggml_quantize_requires_imatrix(type)
        ? imatrix.data() : nullptr;
    ggml_quantize_chunk(type, source.data(), weights.data(), 0,
                        static_cast<int64_t>(rows), static_cast<int64_t>(cols),
                        importance);

    const ggml_type_traits* traits = ggml_get_type_traits(type);
    if (!traits || !traits->to_float) {
        std::fprintf(stderr, "%s missing GGML decoder\n", label);
        return false;
    }
    std::vector<float> decoded(cols);
    for (size_t row = 0; row < rows; ++row) {
        traits->to_float(weights.data() + row * row_bytes, decoded.data(), cols);
        reference[row] = std::inner_product(decoded.begin(), decoded.end(),
                                            input.begin(), 0.0f);
    }

    const bool gpu_ok = RawrXD::Deep2::GenericVulkan::MatVec(
        0, type, weights.data(), weights.size(), rows, cols,
        input.data(), gpu.data());
    if (!gpu_ok) {
        std::fprintf(stderr, "%s GPU dispatch unavailable\n", label);
        return false;
    }

    double max_abs = 0.0;
    double ref_norm = 0.0;
    double diff_norm = 0.0;
    for (size_t i = 0; i < rows; ++i) {
        max_abs = std::max(max_abs, std::abs(static_cast<double>(gpu[i]) - reference[i]));
        ref_norm += static_cast<double>(reference[i]) * reference[i];
        const double d = static_cast<double>(gpu[i]) - reference[i];
        diff_norm += d * d;
    }
    const double cosine_den = std::sqrt(ref_norm) *
        std::sqrt(std::inner_product(gpu.begin(), gpu.end(), gpu.begin(), 0.0));
    double cosine = cosine_den > 0.0
        ? std::inner_product(gpu.begin(), gpu.end(), reference.begin(), 0.0) / cosine_den
        : 1.0;
    const bool pass = max_abs <= 2e-3 && cosine >= 0.9999 && diff_norm >= 0.0;
    std::printf("%s_GPU= %s max_abs=%.9g cosine=%.9g\n",
                label, pass ? "PASS" : "FAIL", max_abs, cosine);
    return pass;
}

}  // namespace

int main() {
    const int devices = ggml_backend_vk_get_device_count();
    if (devices <= 0) {
        std::fprintf(stderr, "QWEN4EXP_GENERIC_GPU=BLOCKED_NO_VULKAN_DEVICE\n");
        return 2;
    }
    bool iq2 = RunType(GGML_TYPE_IQ2_S, "IQ2_S");
    bool mxfp4 = RunType(GGML_TYPE_MXFP4, "MXFP4");
    std::printf("QWEN4EXP_GENERIC_GPU=%s\n", iq2 && mxfp4 ? "PASS" : "FAIL");
    return iq2 && mxfp4 ? 0 : 1;
}
