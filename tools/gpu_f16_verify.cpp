// RAWRXD_DEEP2_F16_ROW4_VERIFY_001
// Independent synthetic parity probe for the scalar and four-row FP16 GEMV
// paths. The process is run once per shader selection because the runtime
// intentionally latches DEEP2_F16_ROW_TILE at first pipeline creation.

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "vulkan_compute.h"

namespace {

float HalfToFloat(uint16_t h) {
    const uint32_t sign = uint32_t(h & 0x8000u) << 16;
    const uint32_t exp = (h >> 10) & 31u;
    const uint32_t frac = h & 1023u;
    uint32_t bits = 0;
    if (exp == 0) {
        if (frac == 0) {
            bits = sign;
        } else {
            uint32_t m = frac;
            int e = -14;
            while ((m & 1024u) == 0u) {
                m <<= 1;
                --e;
            }
            bits = sign | uint32_t(e + 127) << 23 | ((m & 1023u) << 13);
        }
    } else if (exp == 31) {
        bits = sign | 0x7f800000u | (frac << 13);
    } else {
        bits = sign | ((exp + 112u) << 23) | (frac << 13);
    }
    float value = 0.0f;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}

uint16_t FloatToHalf(float value) {
    uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    const uint32_t sign = (bits >> 16) & 0x8000u;
    const int exponent = int((bits >> 23) & 0xffu) - 127 + 15;
    const uint32_t mantissa = bits & 0x7fffffu;
    if (exponent <= 0) return static_cast<uint16_t>(sign);
    if (exponent >= 31) return static_cast<uint16_t>(sign | 0x7c00u);
    return static_cast<uint16_t>(sign | (uint32_t(exponent) << 10) |
                                 (mantissa >> 13));
}

}  // namespace

int main() {
    constexpr size_t n_out = 13;
    constexpr size_t n_in = 512;
    std::vector<uint16_t> weights(n_out * n_in);
    std::vector<float> input(n_in);
    for (size_t i = 0; i < n_in; ++i)
        input[i] = 0.75f * std::sin(float(i) * 0.071f) -
                   0.25f * std::cos(float(i) * 0.013f);
    for (size_t row = 0; row < n_out; ++row) {
        for (size_t col = 0; col < n_in; ++col) {
            const float value = 0.35f * std::sin(float(row * 17 + col) * 0.037f);
            weights[row * n_in + col] = FloatToHalf(value);
        }
    }

    std::vector<float> reference(n_out, 0.0f);
    for (size_t row = 0; row < n_out; ++row) {
        for (size_t col = 0; col < n_in; ++col)
            reference[row] += HalfToFloat(weights[row * n_in + col]) * input[col];
    }

    VulkanCompute compute;
    if (!compute.Initialize()) {
        std::printf("F16_VERIFY=INIT_FAIL\n");
        return 1;
    }
    std::vector<float> output(n_out, 0.0f);
    if (!compute.ExecuteF16Dot(weights.data(), weights.size() * sizeof(uint16_t),
                               input.data(), n_in, output.data(),
                               output.size() * sizeof(float), n_out)) {
        std::printf("F16_VERIFY=DISPATCH_FAIL\n");
        return 1;
    }

    double max_abs = 0.0;
    double max_rel = 0.0;
    bool finite = true;
    for (size_t i = 0; i < n_out; ++i) {
        finite = finite && std::isfinite(output[i]);
        const double diff = std::fabs(double(output[i]) - double(reference[i]));
        max_abs = std::max(max_abs, diff);
        max_rel = std::max(max_rel, diff / std::max(1.0, std::fabs(double(reference[i]))));
    }
    const bool pass = finite && max_abs <= 2.0e-3 && max_rel <= 2.0e-3;
    std::printf("F16_VERIFY rows=%zu cols=%zu max_abs=%.9g max_rel=%.9g finite=%d %s\n",
                n_out, n_in, max_abs, max_rel, finite ? 1 : 0,
                pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
