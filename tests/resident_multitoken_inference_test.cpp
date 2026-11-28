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
            w1[r * width + c] = r == c ? 0.50f : (int((r + c) % 7) - 3) * 0.0001f;
            w2[r * width + c] = r == c ? 0.75f : (int((r * 3 + c) % 11) - 5) * 0.0001f;
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
    std::vector<float> state(width), ref(width), tmp(width), next(width), refMid(width), refNext(width);
    for (std::size_t i = 0; i < width; ++i)
        state[i] = ref[i] = static_cast<float>(int(i % 13) - 6) / 13.0f;
    for (std::size_t token = 0; token < tokens; ++token) {
        assert(residentF32Matvec(a, width, width, state.data(), tmp.data()) == Status::Ok);
        assert(residentF32Matvec(b, width, width, tmp.data(), next.data()) == Status::Ok);
        // Independent dense F32 reference, including cross-channel mixing.
        for (std::size_t i = 0; i < width; ++i) {
            float sum = 0.0f;
            for (std::size_t j = 0; j < width; ++j)
                sum += w1[i * width + j] * ref[j];
            refMid[i] = sum;
        }
        for (std::size_t i = 0; i < width; ++i) {
            float sum = 0.0f;
            for (std::size_t j = 0; j < width; ++j)
                sum += w2[i * width + j] * refMid[j];
            refNext[i] = sum;
            assert(std::fabs(next[i] - refNext[i]) < 1e-5f);
        }
        ref.swap(refNext);
        state.swap(next);
    }
    return 0;
}
