// Synthetic multi-token, two-layer compressed-resident CPU inference parity.
#include "codec/resident_f32_matvec.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cmath>
#include <cstdint>
#include <vector>
#include <algorithm>
int main() {
    using namespace rawrxd::compression;
    constexpr std::size_t width = 1057, tokens = 6;
    std::vector<float> w1(width * width), w2(width * width);
    for (std::size_t r = 0; r < width; ++r)
        for (std::size_t c = 0; c < width; ++c) {
            w1[r * width + c] = r == c ? 0.50f : 0.0f;
            w2[r * width + c] = r == c ? 0.75f : 0.0f;
        }
    ChunkedResidentBytes a, b;
    auto status = a.assign(reinterpret_cast<const std::uint8_t*>(w1.data()),
                           w1.size() * sizeof(float), 4096);
#ifndef RAWRXD_TEST_REQUIRE_ZLIB
    if (status == Status::Unsupported) return 0;
#endif
    assert(status == Status::Ok);
    assert(b.assign(reinterpret_cast<const std::uint8_t*>(w2.data()),
                    w2.size() * sizeof(float), 4096) == Status::Ok);
    assert(a.compressedBytes() + b.compressedBytes() <
           (w1.size() + w2.size()) * sizeof(float));
    std::vector<float> state(width), ref(width), tmp(width), next(width);
    for (std::size_t i = 0; i < width; ++i)
        state[i] = ref[i] = static_cast<float>(int(i % 13) - 6) / 13.0f;
    for (std::size_t token = 0; token < tokens; ++token) {
        assert(residentF32Matvec(a, width, width, state.data(), tmp.data()) == Status::Ok);
        assert(residentF32Matvec(b, width, width, tmp.data(), next.data()) == Status::Ok);
        for (std::size_t i = 0; i < width; ++i) {
            float intermediate = 0.0f;
            for (std::size_t j = 0; j < width; ++j)
                intermediate += w1[i * width + j] * ref[j];
            float expected = 0.0f;
            for (std::size_t j = 0; j < width; ++j)
                expected += w2[i * width + j] * (j == i ? intermediate : 0.5f * ref[j]);
            // w2 is diagonal; the j!=i terms are exactly zero.
            assert(std::fabs(next[i] - expected) < 1e-5f);
            ref[i] = expected;
        }
        state.swap(next);
    }
    return 0;
}
