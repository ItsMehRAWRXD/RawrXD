#pragma once

#include "deep2/ReapQ4KToQ2K.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>

namespace Deep2 { namespace ReapQuant {

constexpr size_t Q3Bytes = 110;
using Q3Block = std::array<uint8_t, Q3Bytes>;

static_assert(sizeof(Q3Block) == Q3Bytes, "Q3_K block size must be 110 bytes");

inline bool DecodeQ3(const Q3Block& block, Values& output) noexcept {
    const float dAll = Half(LoadHalf(block.data() + 108));
    if (!std::isfinite(dAll)) return false;

    uint32_t aux[4]{};
    std::memcpy(aux, block.data() + 96, 12);
    const uint32_t mask1 = 0x03030303u;
    const uint32_t mask2 = 0x0f0f0f0fu;
    const uint32_t packed = aux[2];
    aux[2] = ((aux[0] >> 4) & mask2) | (((packed >> 4) & mask1) << 4);
    aux[3] = ((aux[1] >> 4) & mask2) | (((packed >> 6) & mask1) << 4);
    aux[0] = (aux[0] & mask2) | (((packed >> 0) & mask1) << 4);
    aux[1] = (aux[1] & mask2) | (((packed >> 2) & mask1) << 4);
    const auto* scales = reinterpret_cast<const int8_t*>(aux);
    const auto* q = block.data() + 32;
    const auto* high = block.data();
    uint8_t bit = 1;
    size_t scaleIndex = 0;
    size_t outputIndex = 0;
    for (unsigned chunk = 0; chunk < 2; ++chunk) {
        unsigned shift = 0;
        for (unsigned pair = 0; pair < 4; ++pair) {
            const float dl0 = dAll * float(scales[scaleIndex++] - 32);
            const float dl1 = dAll * float(scales[scaleIndex++] - 32);
            for (unsigned i = 0; i < 16; ++i) {
                const int low = int((q[i + 0] >> shift) & 3u);
                output[outputIndex++] = dl0 * float(low - ((high[i + 0] & bit) ? 0 : 4));
            }
            for (unsigned i = 0; i < 16; ++i) {
                const int low = int((q[i + 16] >> shift) & 3u);
                output[outputIndex++] = dl1 * float(low - ((high[i + 16] & bit) ? 0 : 4));
            }
            shift += 2;
            bit = static_cast<uint8_t>(bit << 1);
        }
        q += 32;
    }
    return outputIndex == 256;
}

inline bool EncodeQ3(const Values& input, Q3Block& output) noexcept {
    std::array<double, 16> steps{};
    double maximumStep = 0.0;
    for (unsigned group = 0; group < 16; ++group) {
        double maximum = 0.0;
        for (unsigned i = 0; i < 16; ++i) {
            const float value = input[group * 16 + i];
            if (!std::isfinite(value)) return false;
            maximum = std::max(maximum, std::abs(double(value)));
        }
        steps[group] = maximum / 3.0;
        maximumStep = std::max(maximumStep, steps[group]);
    }

    uint16_t dHalf = 0;
    if (maximumStep != 0.0) {
        if (!PositiveHalf(maximumStep / 31.0, dHalf) || Half(dHalf) == 0.0f)
            return false;
    }
    const double d = Half(dHalf);
    output.fill(0);

    std::array<unsigned, 16> scaleValues{};
    for (unsigned group = 0; group < 16; ++group) {
        const unsigned scale = d == 0.0
            ? 0u
            : std::min(31u, static_cast<unsigned>(std::floor(steps[group] / d + 0.5)));
        scaleValues[group] = scale;
        const unsigned encoded = scale + 32u;
        if (group < 8) output[96 + group] |= static_cast<uint8_t>(encoded & 0x0f);
        else output[96 + group - 8] |= static_cast<uint8_t>((encoded & 0x0f) << 4);
        output[96 + group % 4 + 8] |= static_cast<uint8_t>(
            ((encoded >> 4) & 3u) << (2u * (group / 4u)));
    }
    StoreHalf(output.data() + 108, dHalf);

    std::array<uint8_t, 256> low{};
    for (unsigned i = 0; i < 256; ++i) {
        const unsigned group = i / 16;
        const double step = d * double(scaleValues[group]);
        int q = step == 0.0 ? 0 : static_cast<int>(std::lround(double(input[i]) / step));
        q = std::clamp(q, -4, 3);
        if (q >= 0) {
            output[i % 32] |= static_cast<uint8_t>(1u << (i / 32));
            low[i] = static_cast<uint8_t>(q);
        } else {
            low[i] = static_cast<uint8_t>(q + 4);
        }
    }
    for (unsigned chunk = 0; chunk < 2; ++chunk) {
        for (unsigned i = 0; i < 32; ++i) {
            output[32 + chunk * 32 + i] =
                static_cast<uint8_t>(low[chunk * 128 + i] |
                    (low[chunk * 128 + i + 32] << 2) |
                    (low[chunk * 128 + i + 64] << 4) |
                    (low[chunk * 128 + i + 96] << 6));
        }
    }
    return true;
}

} } // namespace Deep2::ReapQuant
