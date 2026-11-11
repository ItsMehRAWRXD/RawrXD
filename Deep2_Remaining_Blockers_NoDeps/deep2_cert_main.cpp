// deep2_cert_main.cpp
#include "Deep2CorrectnessCert.hpp"
#include <cmath>
#include <cstdio>
#include <vector>

using namespace deep2cert;

static bool test_q4_0_nibble_order() {
    block_q4_0 b{};
    b.d = fp32_to_fp16(1.0f);
    for (std::size_t i = 0; i < 16; ++i) {
        // low = i mod 16, high = (15-i) mod 16
        b.qs[i] = std::uint8_t((i & 0xF) | (((15 - i) & 0xF) << 4));
    }

    float x[32]{};
    dequantize_q4_0_block(b, x);

    for (std::size_t i = 0; i < 16; ++i) {
        const float lo = float(int(i & 0xF) - 8);
        const float hi = float(int((15 - i) & 0xF) - 8);
        if (x[i] != lo || x[i + 16] != hi) return false;
    }
    return true;
}

static bool test_softmax() {
    float x[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    softmax_inplace(x, 4);
    double s = 0.0;
    for (float v : x) s += v;
    return std::abs(s - 1.0) < 1e-6 && x[3] > x[2] && x[2] > x[1] && x[1] > x[0];
}

static bool test_gqa_mapping() {
    constexpr std::size_t QH = 8;
    constexpr std::size_t KVH = 2;
    constexpr std::size_t D = 4;
    constexpr std::size_t T = 1;

    float q[QH * D]{};
    float k[T * KVH * D]{};
    float v[T * KVH * D]{};
    float out[QH * D]{};

    // With one token, softmax weight is 1. Each Q head must copy the V from
    // its grouped KV head: heads 0..3 -> KV0, heads 4..7 -> KV1.
    for (std::size_t d = 0; d < D; ++d) {
        v[d] = 10.0f + float(d);
        v[D + d] = 20.0f + float(d);
    }

    gqa_attention_one_token(q, k, v, out, QH, KVH, D, T);

    for (std::size_t h = 0; h < QH; ++h) {
        const float base = h < 4 ? 10.0f : 20.0f;
        for (std::size_t d = 0; d < D; ++d) {
            if (out[h * D + d] != base + float(d)) return false;
        }
    }
    return true;
}

static bool test_rmsnorm() {
    const float x[4] = {1, 2, 3, 4};
    const float w[4] = {1, 1, 1, 1};
    float y[4]{};
    rmsnorm(x, w, y, 4, 1e-5f);
    const Stats s = stats({y, 4});
    return s.finite == 4 && std::abs(s.rms - 1.0) < 1e-5;
}

int main() {
    struct T { const char* name; bool (*fn)(); };
    const T tests[] = {
        {"q4_0_nibble_order", test_q4_0_nibble_order},
        {"softmax", test_softmax},
        {"gqa_mapping", test_gqa_mapping},
        {"rmsnorm", test_rmsnorm},
    };

    int failed = 0;
    for (const auto& t : tests) {
        const bool ok = t.fn();
        std::printf("[D2SELFTEST] %-24s %s\n", t.name, ok ? "PASS" : "FAIL");
        failed += ok ? 0 : 1;
    }

    if (failed) {
        std::printf("[D2CERT_FAIL] selftests_failed=%d\n", failed);
        return 1;
    }

    std::printf("[D2CERT_OK] standalone_reference_layer_passed=true\n");
    return 0;
}
