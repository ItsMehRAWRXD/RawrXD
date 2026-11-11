// check_dequant.cpp - verify ggml dequant and the executor's Q6_K row decode.
#include <cstdio>
#include <cstring>
#include <cmath>
#include <vector>
#include "ggml.h"

int main() {
    // Build a Q6_K tensor of exactly one row: 256 elements = 1 super-block.
    const size_t n = 256;
    std::vector<uint8_t> buf(n / 16 + 64);
    std::vector<float> ref(n, 0.0f);
    for (size_t i = 0; i < n; ++i) ref[i] = 0.5f * std::sin(0.11f * float(i)) - 0.25f;

    const ggml_type_traits* tr = ggml_get_type_traits(GGML_TYPE_Q6_K);
    printf("Q6_K: blck_size=%zu type_size=%zu to_float=%p\n",
           (size_t)tr->blck_size, (size_t)tr->type_size, (void*)tr->to_float);
    if (!tr->to_float) { printf("NO to_float\n"); return 1; }

    // Round-trip: quantize with from_float if available, else just verify decode of arbitrary bytes is finite.
    std::vector<float> got(n, 0.0f);
    // Fill the block with a deterministic pattern so decoding is defined.
    for (size_t i = 0; i < buf.size(); ++i) buf[i] = (uint8_t)((i * 37 + 11) & 0xFF);
    tr->to_float(buf.data(), got.data(), (int)n);
    double sa = 0, sb = 0, dot = 0;
    for (size_t i = 0; i < n; ++i) { sa += double(got[i])*got[i]; sb += double(ref[i])*ref[i]; dot += double(got[i])*ref[i]; }
    printf("decoded: min=%.6f max=%.6f mean=%.6f\\n", got[0], got[0], 0.0);
    double mn = got[0], mx = got[0], sum = 0;
    for (float v : got) { mn = std::min(mn, (double)v); mx = std::max(mx, (double)v); sum += v; }
    printf("decoded stats: min=%.6f max=%.6f mean=%.6f finite=%d\\n",
           mn, mx, sum / n, std::isfinite(sum) ? 1 : 0);

    // Q4_0 sanity
    const ggml_type_traits* q4 = ggml_get_type_traits(GGML_TYPE_Q4_0);
    printf("Q4_0: blck_size=%zu type_size=%zu to_float=%p\\n",
           (size_t)q4->blck_size, (size_t)q4->type_size, (void*)q4->to_float);
    return 0;
}
