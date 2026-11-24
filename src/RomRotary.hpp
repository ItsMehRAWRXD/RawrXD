#pragma once
#include <cmath>
#include <cstddef>

namespace deep2 {
enum class RotaryLayout { Interleaved, NeoX };
inline bool rotateHead(float* data, std::size_t headDim, std::size_t rotaryDim,
                       std::size_t position, double theta, double scale,
                       RotaryLayout layout) {
    if (!data || !rotaryDim || rotaryDim > headDim || rotaryDim % 2 ||
        !std::isfinite(theta) || theta <= 0 || !std::isfinite(scale) || scale <= 0 ||
        (layout != RotaryLayout::Interleaved && layout != RotaryLayout::NeoX)) return false;
    for (std::size_t j = 0; j < rotaryDim / 2; ++j) {
        const std::size_t a = layout == RotaryLayout::Interleaved ? 2*j : j;
        const std::size_t b = layout == RotaryLayout::Interleaved ? 2*j+1 : j+rotaryDim/2;
        const double angle = static_cast<double>(position) * scale *
            std::pow(theta, -2.0 * static_cast<double>(j) / static_cast<double>(rotaryDim));
        const double c = std::cos(angle), s = std::sin(angle);
        const float x = data[a], y = data[b];
        data[a] = static_cast<float>(x*c-y*s);
        data[b] = static_cast<float>(x*s+y*c);
    }
    return true;
}
}
