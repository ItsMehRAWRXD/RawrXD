// gpu_quant_dot_verify.cpp
// RAWRXD_DEEP2_GPU_QUANT_DOT_001
//
// Verifies the native Vulkan quantised dot product (Q4_K x Q8_K and
// Q6_K x Q8_K) against an independent CPU reference that decodes the same GGML
// block layouts. Includes irregular dimensions, block boundaries and tails.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cstdint>
#include <vector>
#include <string>
#include <algorithm>
#include <array>
#include "vulkan_compute.h"

namespace {

// ---------------------------------------------------------------------------
// Independent CPU reference. Layout and arithmetic deliberately mirror ggml.
// ---------------------------------------------------------------------------
struct Q4K { uint16_t d, dmin; uint8_t scales[12]; uint8_t qs[128]; };
struct Q6K { uint8_t ql[128]; uint8_t qh[64]; int8_t scales[16]; uint16_t d; };
static_assert(sizeof(Q4K) == 144, "unexpected Q4_K layout");
static_assert(sizeof(Q6K) == 210, "unexpected Q6_K layout");

float HalfToFloat(uint16_t h) {
    const uint32_t sign = uint32_t(h & 0x8000u) << 16;
    const uint32_t exp = (h >> 10) & 31u;
    const uint32_t frac = h & 1023u;
    uint32_t bits;
    if (exp == 0) {
        if (frac == 0) bits = sign;
        else {
            uint32_t m = frac; int e = -14;
            while ((m & 1024u) == 0u) { m <<= 1; --e; }
            bits = sign | (uint32_t(e + 127) << 23) | ((m & 1023u) << 13);
        }
    } else if (exp == 31) bits = sign | 0x7f800000u | (frac << 13);
    else bits = sign | ((exp + 112u) << 23) | (frac << 13);
    float f; std::memcpy(&f, &bits, 4); return f;
}

void K4ScaleMin(const uint8_t s[12], unsigned group, int& scale, int& minv) {
    if (group < 4) { scale = int(s[group] & 63u); minv = int(s[group + 4] & 63u); }
    else {
        scale = int((s[group + 4] & 15u) | ((s[group - 4] >> 6) << 4));
        minv = int((s[group + 4] >> 4) | ((s[group] >> 6) << 4));
    }
}

// Deterministic synthetic Q8_K blocks so the reference needs no float input.
struct Q8Ref {
    float d;
    std::array<int8_t, 256> qs;
    std::array<int16_t, 16> bsums;
};

struct Packed {
    int kind;                       // 0 = Q4_K, 1 = Q6_K
    size_t n_out, n_in, n_blocks;
    std::vector<uint8_t> bytes;     // packed weights
    std::vector<Q8Ref> q8;          // quantised activations
    size_t blockBytes() const { return kind == 0 ? sizeof(Q4K) : sizeof(Q6K); }
    size_t stride() const { return n_blocks * blockBytes(); }
};

float DotQ4(const uint8_t* x, const Q8Ref& y) {
    Q4K w; std::memcpy(&w, x, sizeof(w));
    int32_t lanes[8] = {}; int32_t min_sum = 0;
    for (unsigned group = 0; group < 8; ++group) {
        int scale, minv; K4ScaleMin(w.scales, group, scale, minv);
        const uint8_t* q = w.qs + (group / 2) * 32;
        const bool high = (group & 1u) != 0;
        for (unsigned i = 0; i < 32; ++i) {
            const int weight = high ? int(q[i] >> 4) : int(q[i] & 15u);
            lanes[i & 7u] += scale * weight * int(y.qs[group * 32 + i]);
        }
        min_sum += minv * (int(y.bsums[2 * group]) + int(y.bsums[2 * group + 1]));
    }
    const float d = HalfToFloat(w.d) * y.d;
    const float dmin = HalfToFloat(w.dmin) * y.d;
    float sumf = 0.0f;
    for (unsigned i = 0; i < 8; ++i) sumf += d * float(lanes[i]);
    return sumf - dmin * float(min_sum);
}

float DotQ6(const uint8_t* x, const Q8Ref& y) {
    Q6K w; std::memcpy(&w, x, sizeof(w));
    int32_t lanes[8] = {};
    for (unsigned group = 0; group < 8; ++group) {
        const unsigned half = group / 4, part = group % 4;
        const unsigned shift4 = part >= 2 ? 4 : 0;
        const unsigned loff = half * 64 + (part & 1u) * 32;
        const unsigned hoff = half * 32;
        const unsigned qhoff = 2 * part;
        for (unsigned i = 0; i < 32; ++i) {
            const int low4 = int((w.ql[loff + i] >> shift4) & 15u);
            const int high2 = int((w.qh[hoff + i] >> qhoff) & 3u);
            const int quant = (low4 | (high2 << 4)) - 32;
            lanes[i & 7u] += int(w.scales[group * 2 + i / 16]) * quant * int(y.qs[group * 32 + i]);
        }
    }
    const float d = HalfToFloat(w.d) * y.d;
    float sumf = 0.0f;
    for (unsigned i = 0; i < 8; ++i) sumf += d * float(lanes[i]);
    return sumf;
}

void ReferenceMatVec(const Packed& p, std::vector<float>& out) {
    out.assign(p.n_out, 0.0f);
    for (size_t r = 0; r < p.n_out; ++r) {
        const uint8_t* rowData = p.bytes.data() + r * p.stride();
        float acc = 0.0f;
        for (size_t b = 0; b < p.n_blocks; ++b) {
            const uint8_t* blk = rowData + b * p.blockBytes();
            acc += (p.kind == 0) ? DotQ4(blk, p.q8[b]) : DotQ6(blk, p.q8[b]);
        }
        out[r] = acc;
    }
}

// Deterministic synthetic packed weights, exercising real nibble ranges.
Packed MakeCase(int kind, size_t n_out, size_t n_in) {
    Packed p;
    p.kind = kind;
    p.n_out = n_out;
    p.n_in = n_in;
    p.n_blocks = n_in / 256;

    // ---- quantised activations ----
    p.q8.resize(p.n_blocks);
    for (size_t b = 0; b < p.n_blocks; ++b) {
        Q8Ref& y = p.q8[b];
        // Non-trivial but bounded scale; varies per block.
        y.d = 0.03125f * float(b + 1) + 0.001f;
        int8_t mx = 1;
        for (unsigned j = 0; j < 256; ++j) {
            int v = int(std::lround(127.0 * std::sin(0.37 * double(j + b * 17))));
            v = std::max(-127, std::min(127, v));
            y.qs[j] = int8_t(v);
            if (std::abs(v) > std::abs(int(mx))) mx = int8_t(v);
        }
        for (unsigned j = 0; j < 16; ++j) {
            int s = 0;
            for (unsigned k = 0; k < 16; ++k) s += int(y.qs[16 * j + k]);
            y.bsums[j] = int16_t(s);
        }
        (void)mx;
    }

    // ---- packed weights ----
    p.bytes.assign(p.n_out * p.stride(), 0);
    for (size_t r = 0; r < p.n_out; ++r) {
        uint8_t* row = p.bytes.data() + r * p.stride();
        for (size_t b = 0; b < p.n_blocks; ++b) {
            uint8_t* blk = row + b * p.blockBytes();
            if (kind == 0) {
                Q4K* w = reinterpret_cast<Q4K*>(blk);
                // fp16 bits for small positive scales.
                w->d = 0x2C00;   // ~0.03125
                w->dmin = 0x3000; // ~0.0625
                for (int i = 0; i < 12; ++i)
                    w->scales[i] = uint8_t((r * 31 + b * 7 + i * 13) & 0xFFu);
                for (int i = 0; i < 128; ++i)
                    w->qs[i] = uint8_t((r * 17 + b * 5 + i * 3) & 0xFFu);
            } else {
                Q6K* w = reinterpret_cast<Q6K*>(blk);
                for (int i = 0; i < 128; ++i)
                    w->ql[i] = uint8_t((r * 19 + b * 11 + i * 2) & 0xFFu);
                for (int i = 0; i < 64; ++i)
                    w->qh[i] = uint8_t((r * 23 + b * 3 + i * 7) & 0xFFu);
                for (int i = 0; i < 16; ++i)
                    w->scales[i] = int8_t(((r * 29 + i * 5) % 7) - 3);
                w->d = 0x2C00;
            }
        }
    }
    return p;
}

// Flatten Q8 into the interleaved float layout the shader expects.
std::vector<float> BuildQ8Buffer(const Packed& p) {
    const size_t stride = 273;
    std::vector<float> v(p.n_blocks * stride, 0.0f);
    for (size_t b = 0; b < p.n_blocks; ++b) {
        float* base = v.data() + b * stride;
        base[0] = p.q8[b].d;
        for (unsigned i = 0; i < 256; ++i) base[1 + i] = float(p.q8[b].qs[i]);
        for (unsigned i = 0; i < 16; ++i) base[257 + i] = float(p.q8[b].bsums[i]);
    }
    return v;
}

struct Metrics { double cosine, rmse, max_abs, rel; bool finite; size_t worst; };

Metrics Compare(const std::vector<float>& g, const std::vector<float>& c) {
    Metrics m{};
    m.finite = true; m.worst = 0;
    double dot = 0, ng = 0, nc = 0, sq = 0, mx = 0;
    for (size_t i = 0; i < g.size(); ++i) {
        if (!std::isfinite(g[i])) m.finite = false;
        double d = double(g[i]) - double(c[i]);
        sq += d * d;
        if (std::fabs(d) > mx) { mx = std::fabs(d); m.worst = i; }
        dot += double(g[i]) * double(c[i]);
        ng += double(g[i]) * double(g[i]);
        nc += double(c[i]) * double(c[i]);
    }
    m.cosine = (ng > 0 && nc > 0) ? dot / (std::sqrt(ng) * std::sqrt(nc)) : 1.0;
    m.rmse = std::sqrt(sq / double(g.size()));
    m.max_abs = mx;
    double mag = std::sqrt(nc / double(g.size()));
    m.rel = (mag > 1e-12) ? m.rmse / mag : m.rmse;
    return m;
}

} // namespace

int main(int argc, char** argv) {
    const char* spv = (argc > 1) ? argv[1] : "F:\\rawrxd\\tools\\shaders\\quant_dot.spv";
    printf("=== RAWRXD_DEEP2_GPU_QUANT_DOT_001 ===\n");
    printf("shader: %s\n\n", spv);

    VulkanCompute vc;
    if (!vc.Initialize()) { printf("VULKAN_INIT=FAIL\n"); return 1; }
    printf("VULKAN_DEVICE=%s\n", vc.GetDeviceInfo().device_name.c_str());

    struct Case { int kind; size_t out, in; const char* label; };
    const Case cases[] = {
        {0, 8,   512,  "q4k_8x512"},
        {0, 33,  768,  "q4k_irregular_33x768"},
        {0, 1,   256,  "q4k_min_1x256"},
        {0, 17,  2048, "q4k_17x2048"},
        {1, 8,   512,  "q6k_8x512"},
        {1, 33,  768,  "q6k_irregular_33x768"},
        {1, 1,   256,  "q6k_min_1x256"},
        {1, 17,  2048, "q6k_17x2048"},
    };

    int pass = 0, total = 0;
    for (const Case& c : cases) {
        ++total;
        Packed p = MakeCase(c.kind, c.out, c.in);
        std::vector<float> cpu;
        ReferenceMatVec(p, cpu);

        std::vector<float> q8buf = BuildQ8Buffer(p);

        // Packed bytes must be padded to a u32 boundary for the shader buffer.
        std::vector<uint32_t> packed_u32((p.bytes.size() + 3) / 4, 0u);
        std::memcpy(packed_u32.data(), p.bytes.data(), p.bytes.size());

        std::vector<float> gpu(p.n_out, 0.0f);
        bool ok = vc.ExecuteQuantDot(packed_u32.data(), packed_u32.size() * 4,
                                     q8buf.data(), q8buf.size() * 4,
                                     gpu.data(), gpu.size() * 4,
                                     p.n_out, p.n_in, p.n_blocks, c.kind);
        if (!ok) {
            printf("%-24s kind=%d out=%-3zu in=%-5zu DISPATCH_FAIL\n",
                   c.label, c.kind, p.n_out, p.n_in);
            continue;
        }

        Metrics m = Compare(gpu, cpu);
        bool good = m.finite && m.cosine >= 0.999999 && m.rel <= 1e-4;
        if (good) ++pass;

        printf("%-24s kind=%d out=%-3zu in=%-5zu cos=%+.10f rel=%.2e max=%.2e finite=%d %s\n",
               c.label, c.kind, p.n_out, p.n_in, m.cosine, m.rel, m.max_abs,
               m.finite ? 1 : 0, good ? "PASS" : "FAIL");
    }

    printf("\nSHAPES_PASSED=%d/%d\n", pass, total);
    printf("VERDICT=%s\n", (pass == total) ? "PASS" : "FAIL");
    return (pass == total) ? 0 : 1;
}
