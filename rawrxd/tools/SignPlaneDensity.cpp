// RAWRXD_SIGNPLANE_DENSITY_002
//
// The last unmeasured item: does moving the sign into its own plane actually
// pay? Same N weights, two layouts, same work (flip the sign of every weight).
//
//   IN-BAND  bf16 : the sign shares a 16-bit word with the magnitude, so
//                   negating a sign costs a read+write of all 2N bytes.
//   SEPARATE       : N/8 bytes of sign plane. The magnitude is untouched.
//
// Pure intrinsics so there is no assembler/link step between the measurement
// and the number. The instruction sequence was already verified separately;
// this question is about BYTES, not about which register file issues the XOR.

#include <immintrin.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <chrono>

// ---- A: in-band bf16 negation, one 32-byte lane per iteration -------------
static void neg_inband(const std::uint8_t* src, std::uint8_t* dst, std::size_t n) {
    const __m256i mask = _mm256_set1_epi16(static_cast<short>(0x8000));
    std::size_t i = 0;
    for (; i + 32 <= n; i += 32) {
        __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(src + i));
        v = _mm256_xor_si256(v, mask);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(dst + i), v);
    }
    for (; i < n; i += 2) {
        std::uint16_t w;
        std::memcpy(&w, src + i, 2);
        w = static_cast<std::uint16_t>(w ^ 0x8000u);
        std::memcpy(dst + i, &w, 2);
    }
}

// ---- B: sign-plane inversion, one 32-byte (256 signs) per iteration -------
static void neg_plane(const std::uint8_t* src, std::uint8_t* dst, std::size_t n) {
    const __m256i ones = _mm256_set1_epi8(static_cast<char>(0xFF));
    std::size_t i = 0;
    for (; i + 32 <= n; i += 32) {
        __m256i v = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(src + i));
        v = _mm256_xor_si256(v, ones);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(dst + i), v);
    }
    for (; i < n; ++i)
        dst[i] = static_cast<std::uint8_t>(~src[i]);
}

int main() {
    std::printf("RAWRXD_SIGNPLANE_DENSITY_002\n");
    int fail = 0;

    // ---- correctness first ----
    {
        int bad = 0;
        for (std::size_t n : {std::size_t(32), std::size_t(33), std::size_t(64),
                              std::size_t(100), std::size_t(256), std::size_t(258),
                              std::size_t(1000)}) {
            std::vector<std::uint8_t> p(n + 64, 0), o(n + 64, 0);
            for (std::size_t i = 0; i < n; ++i) p[i] = std::uint8_t(i * 37 + 11);
            neg_plane(o.data(), p.data(), n);
            for (std::size_t i = 0; i < n; ++i)
                if (o[i] != static_cast<std::uint8_t>(~p[i])) { ++bad; break; }
        }
        std::printf("sign-plane NOT correctness across 7 sizes: %s\n", bad ? "FAIL" : "PASS");
        if (bad) ++fail;
    }

    for (std::size_t MiB : {std::size_t(1), std::size_t(64), std::size_t(512)}) {
        const std::size_t N = MiB << 20;          // weights
        const std::size_t inband = N * 2;          // bf16 bytes
        const std::size_t plane  = (N + 7) / 8;    // 1 bit per weight
        const int PASS = (MiB <= 64) ? 60 : 6;

        std::vector<std::uint8_t> w(inband), w2(inband);
        std::vector<std::uint8_t> pl(plane), pl2(plane);
        for (std::size_t i = 0; i < inband; ++i) w[i] = std::uint8_t(i * 31 + 7);
        for (std::size_t i = 0; i < plane;  ++i) pl[i] = std::uint8_t(i * 131 + 17);

        std::printf("\n=== %zu Mi weights ===\n", MiB);
        std::printf("  in-band bf16 : %12zu bytes\n", inband);
        std::printf("  sign plane   : %12zu bytes   (%.2fx less)\n",
                    plane, double(inband) / double(plane));

        auto bench = [&](auto&& fn, std::size_t bytes, const char* nm) {
            for (int p = 0; p < 2; ++p) fn();
            _mm256_zeroupper();
            const auto t0 = std::chrono::steady_clock::now();
            for (int p = 0; p < PASS; ++p) fn();
            const auto t1 = std::chrono::steady_clock::now();
            const double s = std::chrono::duration<double>(t1 - t0).count();
            std::printf("  %-22s %9.3f ms  %8.2f GB/s touched\n",
                        nm, s * 1e3, double(bytes) * PASS / 1e9 / s);
            return s;
        };

        const double ti = bench([&] { neg_inband(w2.data(), w.data(),  inband); },
                                inband, "in-band (2N B)");
        const double tp = bench([&] { neg_plane(pl2.data(), pl.data(), plane); },
                                plane,  "sign plane (N/8 B)");

        const double ratio = ti / tp;
        std::printf("\n  TIME in-band / plane = %.3fx\n", ratio);
        std::printf("  TRAFFIC ratio       = %.3fx\n", double(inband) / double(plane));
        std::printf("  verdicts: %s\n",
            ratio > 4.0  ? "PLANE WINS DECISIVELY (traffic-bound)" :
            ratio > 1.2  ? "plane wins" :
                           "NO WIN (latency-bound: work too small to be bandwidth-bound)");
        std::printf("  sink: %d %d\n", int(w2[0]), int(pl2[0]));
    }

    std::printf("\nDENSITY_MEASUREMENT=%s\n", fail ? "INCOMPLETE" : "COMPLETE");
    return fail ? 1 : 0;
}
