#pragma once
/* Host-side Q8_K activation quant for Vulkan Q6_K GEMV In=block_q8_K[]. */
#include "deep2/GGUFLoader.hpp"
#include <cmath>
#include <cstdint>

namespace q8k_act {

inline void quantize_row_q8_K(const float* x, Deep2::block_q8_K* y, size_t k) {
    const size_t nb = k / 256u;
    for (size_t i = 0; i < nb; ++i) {
        const float* xi = x + i * 256u;
        float amax = 0.f, maxv = 0.f;
        for (int j = 0; j < 256; ++j) {
            const float ax = std::fabs(xi[j]);
            if (ax > amax) { amax = ax; maxv = xi[j]; }
        }
        Deep2::block_q8_K& b = y[i];
        if (amax == 0.f) {
            b.d = 0.f;
            for (int j = 0; j < 256; ++j) b.qs[j] = 0;
            for (int j = 0; j < 16; ++j) b.bsums[j] = 0;
            continue;
        }
        const float iscale = -127.f / maxv;
        b.d = 1.f / iscale;
        for (int j = 0; j < 256; ++j) {
            int v = (int)std::round(iscale * xi[j]);
            if (v > 127) v = 127;
            if (v < -128) v = -128;
            b.qs[j] = (int8_t)v;
        }
        for (int j = 0; j < 16; ++j) {
            int s = 0;
            for (int ii = 0; ii < 16; ++ii) s += b.qs[j * 16 + ii];
            b.bsums[j] = (int16_t)s;
        }
    }
}

} // namespace q8k_act
