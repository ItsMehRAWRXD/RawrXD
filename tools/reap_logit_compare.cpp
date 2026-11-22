#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

int main(int argc, char **argv) {
    if (argc != 4) { std::fprintf(stderr, "usage: reap-logit-compare <reference.bin> <candidate.bin> <vocab>\n"); return 2; }
    const size_t vocab = std::strtoull(argv[3], nullptr, 10);
    if (vocab == 0 || vocab > (std::numeric_limits<size_t>::max)() / sizeof(float)) return 2;
    std::ifstream a(argv[1], std::ios::binary | std::ios::ate), b(argv[2], std::ios::binary | std::ios::ate);
    if (!a || !b) { std::fprintf(stderr, "LOGIT_COMPARE_FAIL=OPEN\n"); return 3; }
    const auto as = a.tellg(), bs = b.tellg();
    const auto expected = static_cast<std::streamoff>(vocab * sizeof(float));
    if (as != expected || bs != expected) { std::fprintf(stderr, "LOGIT_COMPARE_FAIL=SIZE reference=%lld candidate=%lld expected=%lld\n", (long long)as, (long long)bs, (long long)expected); return 4; }
    a.seekg(0); b.seekg(0); std::vector<float> x(vocab), y(vocab);
    if (!a.read(reinterpret_cast<char *>(x.data()), expected) || !b.read(reinterpret_cast<char *>(y.data()), expected)) return 5;
    double max_abs = 0, sum_sq = 0, dot = 0, nx = 0, ny = 0; size_t xi = 0, yi = 0;
    float xm = -std::numeric_limits<float>::infinity(), ym = xm;
    for (size_t i = 0; i < vocab; ++i) {
        if (!std::isfinite(x[i]) || !std::isfinite(y[i])) { std::fprintf(stderr, "LOGIT_COMPARE_FAIL=NONFINITE index=%zu\n", i); return 6; }
        if (x[i] > xm) { xm = x[i]; xi = i; } if (y[i] > ym) { ym = y[i]; yi = i; }
        const double d = static_cast<double>(x[i]) - y[i]; max_abs = (std::max)(max_abs, std::fabs(d)); sum_sq += d*d;
        dot += static_cast<double>(x[i]) * y[i]; nx += static_cast<double>(x[i])*x[i]; ny += static_cast<double>(y[i])*y[i];
    }
    const double rms = std::sqrt(sum_sq / vocab), cosine = dot / (std::sqrt(nx) * std::sqrt(ny));
    std::printf("LOGIT_COMPARE vocab=%zu max_abs=%.9g rms=%.9g cosine=%.12g ref_argmax=%zu candidate_argmax=%zu\n", vocab, max_abs, rms, cosine, xi, yi);
    return 0;
}
