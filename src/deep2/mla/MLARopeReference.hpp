#pragma once
#include <vector>
#include <cmath>
#include <cstddef>
namespace rawrxd::mla {
enum class RopeLayout { Interleaved, SplitHalf };
inline bool rotateRope(std::vector<float>& values, const std::vector<double>& angles, RopeLayout layout) {
    if (values.empty() || values.size() % 2 || angles.size() != values.size() / 2) return false;
    const size_t half = values.size() / 2;
    auto result = values;
    for (size_t i = 0; i < half; ++i) {
        if (!std::isfinite(angles[i])) return false;
        const size_t a = layout == RopeLayout::Interleaved ? i * 2 : i;
        const size_t b = layout == RopeLayout::Interleaved ? i * 2 + 1 : i + half;
        const double c = std::cos(angles[i]), s = std::sin(angles[i]);
        const double x = values[a], y = values[b];
        result[a] = float(x * c - y * s);
        result[b] = float(x * s + y * c);
        if (!std::isfinite(result[a]) || !std::isfinite(result[b])) return false;
    }
    values.swap(result); return true;
}
}