#include "deep2/ReapQ3KCodec.hpp"
#include "ggml-quants.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <limits>

using namespace Deep2::ReapQuant;

static bool closeValues(const Values& a, const Values& b, float tolerance,
                        float& maxError) {
    maxError = 0.0f;
    for (size_t i = 0; i < Elements; ++i) {
        const float error = std::abs(a[i] - b[i]);
        maxError = std::max(maxError, error);
        if (error > tolerance) return false;
    }
    return true;
}

int main() {
    int pass = 0;
    int fail = 0;
    const auto check = [&](bool ok, const char* name) {
        std::printf("%s %s\n", ok ? "PASS" : "FAIL", name);
        ok ? ++pass : ++fail;
    };

    Values input{};
    for (size_t i = 0; i < input.size(); ++i) {
        const float wave = std::sin(float(i) * 0.071f) * 3.0f;
        input[i] = wave + float(int(i % 17) - 8) * 0.037f;
    }

    Q3Block encoded{};
    check(EncodeQ3(input, encoded), "native Q3_K encoder");
    check(encoded.size() == 110, "Q3_K physical block size");

    Values decoded{};
    float maxError = 0.0f;
    check(DecodeQ3(encoded, decoded), "native Q3_K decoder");
    check(closeValues(input, decoded, 1.6f, maxError), "native Q3_K finite reconstruction");

    block_q3_K ggmlEncoded{};
    quantize_row_q3_K_ref(input.data(), &ggmlEncoded, 256);
    Q3Block ggmlBytes{};
    std::memcpy(ggmlBytes.data(), &ggmlEncoded, ggmlBytes.size());
    Values reapDecoded{}, ggmlDecoded{};
    dequantize_row_q3_K(&ggmlEncoded, ggmlDecoded.data(), 256);
    check(DecodeQ3(ggmlBytes, reapDecoded), "decode GGML Q3_K block");
    check(closeValues(reapDecoded, ggmlDecoded, 1e-6f, maxError),
          "GGML/reference Q3_K decoder parity");

    block_q3_K nativeAsGgml{};
    std::memcpy(&nativeAsGgml, encoded.data(), encoded.size());
    Values nativeReference{};
    dequantize_row_q3_K(&nativeAsGgml, nativeReference.data(), 256);
    check(closeValues(decoded, nativeReference, 1e-6f, maxError),
          "native Q3_K encoding compatibility");

    const auto previous = encoded;
    input[37] = std::numeric_limits<float>::quiet_NaN();
    check(!EncodeQ3(input, encoded) && encoded == previous,
          "nonfinite Q3_K input rejected without publishing");

    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\n", pass, fail);
    return fail ? 1 : 0;
}
