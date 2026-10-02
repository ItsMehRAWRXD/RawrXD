// fwht8_measure.cpp — settle FWHT8 throughput by measurement, not by port table.
//
// Three things, in order:
//   1. CORRECTNESS  : kernel vs scalar reference FWHT, on [1..8] and 1M random vectors
//   2. ORDER       : confirm the returned order is bitreverse_3 of natural FWHT
//   3. THROUGHPUT  : measured cycles/call on THIS machine (Zen 4), vs the
//                    port-model estimate. Independent blocks => throughput bound.
//
// The kernel is transcribed instruction-for-instruction from the reconstruction.

#include <immintrin.h>
#include <intrin.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

// ---------------------------------------------------------------------------
// The kernel, exactly as reconstructed. ymm0 in, ymm0 out.
// ---------------------------------------------------------------------------
static inline __m256 FWHT8_AVX2(__m256 v) {
    __m256 ymm0 = v;
    __m256 ymm1, ymm2, ymm3, ymm4, ymm5;

    ymm1 = _mm256_shuffle_ps(ymm0, ymm0, 0xB1);   // vshufps ymm1,ymm0,ymm0,0B1h
    ymm2 = _mm256_add_ps(ymm0, ymm1);            // vaddps  ymm2,ymm0,ymm1
    ymm3 = _mm256_sub_ps(ymm0, ymm1);            // vsubps  ymm3,ymm0,ymm1

    ymm1 = _mm256_shuffle_ps(ymm2, ymm2, 0x4E);  // vshufps ymm1,ymm2,ymm2,04Eh
    ymm4 = _mm256_shuffle_ps(ymm3, ymm3, 0x4E);  // vshufps ymm4,ymm3,ymm3,04Eh

    ymm5 = _mm256_add_ps(ymm2, ymm1);            // vaddps  ymm5,ymm2,ymm1
    ymm2 = _mm256_sub_ps(ymm2, ymm1);            // vsubps  ymm2,ymm2,ymm1
    ymm1 = _mm256_add_ps(ymm3, ymm4);            // vaddps  ymm1,ymm3,ymm4
    ymm3 = _mm256_sub_ps(ymm3, ymm4);            // vsubps  ymm3,ymm3,ymm4

    ymm4 = ymm5;                                 // vmovaps ymm4,ymm5 (eliminated)
    ymm4 = _mm256_blend_ps(ymm4, ymm2, 0x22);
    ymm4 = _mm256_blend_ps(ymm4, ymm1, 0x44);
    ymm4 = _mm256_blend_ps(ymm4, ymm3, 0x88);

    ymm1 = _mm256_permute2f128_ps(ymm4, ymm4, 0x01);
    ymm0 = _mm256_add_ps(ymm4, ymm1);
    ymm2 = _mm256_sub_ps(ymm4, ymm1);

    ymm3 = _mm256_unpacklo_ps(ymm0, ymm2);
    ymm1 = _mm256_unpackhi_ps(ymm0, ymm2);
    ymm0 = _mm256_permute2f128_ps(ymm3, ymm1, 0x20);

    return ymm0;
}

static void fwht8_scalar(const float* x, float* y) {
    float a[8];
    std::memcpy(a, x, sizeof(a));
    for (int len = 1; len < 8; len <<= 1)
        for (int i = 0; i < 8; i += len << 1)
            for (int j = 0; j < len; ++j) {
                const float u = a[i + j], v = a[i + j + len];
                a[i + j] = u + v;
                a[i + j + len] = u - v;
            }
    std::memcpy(y, a, sizeof(a));
}

static inline int bitrev3(int i) {
    int r = 0;
    for (int b = 0; b < 3; ++b) { r = (r << 1) | (i & 1); i >>= 1; }
    return r;
}

int main() {
    std::printf("RAWRXD_FWHT8_MEASURED_001\n");
    char cpu[64] = {0};
    {
        int r[4];
        for (int leaf = 0x80000002; leaf <= 0x80000004; ++leaf) {
            __cpuidex(r, leaf, 0);
            std::memcpy(cpu + (leaf - 0x80000002) * 16, r, 16);
        }
    }
    std::printf("cpu: %.48s\n", cpu);

    // ---------------- 1. correctness on the stated sanity vector ----------
    {
        float x[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        float nat[8], got[8];
        fwht8_scalar(x, nat);
        __m256 r = FWHT8_AVX2(_mm256_loadu_ps(x));
        _mm256_storeu_ps(got, r);
        std::printf("\ninput [1..8]\n  natural FWHT :");
        for (int i = 0; i < 8; ++i) std::printf(" %g", nat[i]);
        std::printf("\n  kernel out  :");
        for (int i = 0; i < 8; ++i) std::printf(" %g", got[i]);
        std::printf("\n  claimed     : 36 -16 -8 0 -4 0 0 0\n");

        bool match = true;
        for (int i = 0; i < 8; ++i)
            if (std::fabs(got[i] - nat[bitrev3(i)]) > 1e-4f) match = false;
        std::printf("  kernel == natural_FWHT[bitrev3(i)] : %d\n", match ? 1 : 0);
    }

    // ---------------- 2. correctness over random vectors -------------------
    {
        std::uint64_t s = 0x243F6A8885A308D3ull;
        auto rnd = [&]() { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return float(int(s >> 40) % 2001 - 1000) / 250.0f; };
        int bad = 0;
        const int N = 1000000;
        for (int i = 0; i < N; ++i) {
            float x[8], nat[8], got[8];
            for (int k = 0; k < 8; ++k) x[k] = rnd();
            fwht8_scalar(x, nat);
            _mm256_storeu_ps(got, FWHT8_AVX2(_mm256_loadu_ps(x)));
            for (int k = 0; k < 8; ++k)
                if (std::fabs(got[k] - nat[bitrev3(k)]) > 1e-3f) ++bad;
        }
        std::printf("\nrandom vectors tested: %d   element mismatches: %d\n", N, bad);
        std::printf("  KERNEL_CORRECT=%d\n", bad == 0 ? 1 : 0);
    }

    // ---------------- 3. throughput ---------------------------------------
    // 32 independent blocks == one 256-weight tensor. Enough ILP to saturate.
    //
    // The accumulator is carried across iterations on purpose: without it the
    // compiler proves the whole loop invariant and deletes it. A previous run
    // reported 252 TSC cycles for 6.4M calls, which is the dead-code tell.
    {
        const int B = 32;                 // blocks in flight
        const int ITER = 200000;
        alignas(32) float v[B][8];
        alignas(32) float out[B][8];
        alignas(32) float acc[B][8];
        for (int b = 0; b < B; ++b) {
            for (int k = 0; k < 8; ++k) v[b][k] = float(b * 8 + k) * 0.01f;
            for (int k = 0; k < 8; ++k) acc[b][k] = 0.0f;
        }

        for (int b = 0; b < B; ++b)
            _mm256_store_ps(out[b], FWHT8_AVX2(_mm256_load_ps(v[b])));
        _mm256_zeroupper();

        double sink = 0.0;
        const std::uint64_t t0 = __rdtsc();
        for (int it = 0; it < ITER; ++it) {
            for (int b = 0; b < B; ++b) {
                _mm256_store_ps(out[b], FWHT8_AVX2(_mm256_load_ps(v[b])));
                _mm256_store_ps(acc[b], _mm256_add_ps(_mm256_load_ps(acc[b]),
                                                      _mm256_load_ps(out[b])));
            }
        }
        const std::uint64_t t1 = __rdtsc();
        for (int b = 0; b < B; ++b) for (int k = 0; k < 8; ++k) sink += acc[b][k];

        const double calls = double(ITER) * B;
        const double tsc = double(t1 - t0);
        volatile double vs = sink;
        std::printf("\nthroughput: %d independent blocks (one 256-weight tensor)\n", B);
        std::printf("  total calls      : %.0f\n", calls);
        std::printf("  TSC cycles       : %.0f\n", tsc);
        std::printf("  TSC cycles/call  : %.4f\n", tsc / calls);
        std::printf("  TSC cycles/256w  : %.2f\n", tsc / double(ITER));
        std::printf("  NOTE: rdtsc on Zen4 is the invariant reference TSC (base clock),\n");
        std::printf("        so these are base-clock cycles, not core cycles.\n");
        std::printf("  port-model claim : 7 cycles/call (Intel Skylake), 5-7 (Zen4 est)\n");
        std::printf("  sink             : %.6g  (non-degenerate: %d)\n", (double)vs,
                    std::isfinite((double)vs) ? 1 : 0);
    }

    // ---------------- 4. latency: true serial dependency chain ------------
    // Each call consumes the previous result. The 1/sqrt(8) factor keeps the
    // chain numerically stationary so we never measure denormal or NaN
    // penalties -- an earlier run produced NaN here, which distorts timing.
    {
        alignas(32) float o[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        const int ITER = 500000;
        const int CHAIN = 8;
        const __m256 k = _mm256_set1_ps(0.35355339f);   // 1/sqrt(8)

        _mm256_store_ps(o, FWHT8_AVX2(_mm256_load_ps(o)));
        const std::uint64_t t0 = __rdtsc();
        for (int i = 0; i < ITER; ++i) {
            __m256 r = _mm256_load_ps(o);
            for (int j = 0; j < CHAIN; ++j)
                r = FWHT8_AVX2(_mm256_mul_ps(r, k));
            _mm256_store_ps(o, r);
        }
        const std::uint64_t t1 = __rdtsc();
        double s = 0.0;
        for (int k = 0; k < 8; ++k) s += o[k];
        volatile double vs = s;
        std::printf("\nlatency (true serial chain, %d calls/iter, 1 extra mul/call)\n", CHAIN);
        std::printf("  TSC cycles per serial FWHT8 : %.3f\n",
                    double(t1 - t0) / ITER / CHAIN);
        std::printf("  sink: %.6g  finite: %d\n", (double)vs, std::isfinite((double)vs) ? 1 : 0);
    }
    return 0;
}
