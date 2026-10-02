// "fake work" vs real work: a measured taxonomy.
//
// fake work    = rearranges instructions around work that is already bound by
//                bytes moved. Adds code, adds risk, moves no bytes.
// real work    = removes bytes. Changes what exists.
//
// Everything here is measured on the same machine, same buffer, same pass count.

#include <immintrin.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <chrono>

extern "C" void __cdecl nt_unaligned(void*, const void*, std::size_t);
extern "C" void __cdecl rep_movsb_loop(void*, const void*, std::size_t);
extern "C" void __cdecl manual_copy(void*, const void*, std::size_t);
extern "C" void __cdecl nt_unroll8(void*, const void*, std::size_t);
extern "C" void __cdecl nt_load_store(void*, const void*, std::size_t);
// NOTE: declared with a dummy 2nd arg so the COUNT lands in r8.
// A two-arg Win64 signature puts the count in RDX -- that mismatch crashed this.
extern "C" void __cdecl sign_plane(void*, std::size_t, std::size_t);
extern "C" void __cdecl inband_plain(void*, const void*, std::size_t);

int main() {
    std::printf("RAWRXD_FAKEWORK_VS_REALWORK_001\n");

    // ---- CLAIM: "NT store to unaligned = #GP" ----
    {
        std::vector<std::uint8_t> buf(4096 + 64, 0);
        std::vector<std::uint8_t> src(4096, 0x11);
        // deliberately unaligned: +4
        (void)0;
        int ok = 1;
        for (int off : {0, 1, 2, 3, 4, 8, 16}) {
            std::uint8_t* p = buf.data() + off;
            std::memset(buf.data(), 0, buf.size());
            nt_unaligned(p, src.data(), 256);
            ;
            for (std::size_t k = 0; k + 1 < 256; k += 2) {
                const std::uint16_t w = *reinterpret_cast<const std::uint16_t*>(p + k);
                if (w != 0x1100) { ok = 0; break; }
            }
        }
        std::printf("\nCLAIM 'NT store to unaligned = #GP':\n");
        std::printf("  unaligned NT store at offsets 0,1,2,3,4,8,16 : %s\n",
                    ok ? "NO FAULT -- claim is FALSE" : "faulted as claimed");
        std::printf("  vmovntdq has no alignment requirement; it faults only on\n");
        std::printf("  address-size faults. `vmovdqa` is the aligned one.\n");
    }

    // ---- fake work vs real work, same buffer ----
    const std::size_t N = 64ull << 20;          // 64 MiB, memory-bound
    const std::size_t inband = N * 2;            // 2N bytes for in-band
    const std::size_t plane  = (N + 7) / 8;      // N/8 bytes for the plane
    const int PASS = 12;

    std::vector<std::uint8_t> w(inband), w2(inband);
    std::vector<std::uint8_t> pl(plane), pl2(plane);
    for (std::size_t i = 0; i < inband; ++i) w[i]  = std::uint8_t(i * 31 + 7);
    for (std::size_t i = 0; i < plane;  ++i) pl[i] = std::uint8_t(i * 131 + 17);

    std::printf("\n64 Mi weights, %d passes (bytes touched differ by design):\n", PASS);
    std::printf("  in-band payload %zu B | sign plane %zu B (%.1fx less)\n\n",
                inband, plane, double(inband) / double(plane));

    auto bench = [&](auto&& fn, const char* nm, std::size_t touched) {
        for (int p = 0; p < 2; ++p) fn();
        _mm256_zeroupper();
        auto t0 = std::chrono::steady_clock::now();
        for (int p = 0; p < PASS; ++p) fn();
        auto t1 = std::chrono::steady_clock::now();
        const double s = std::chrono::duration<double>(t1 - t0).count();
        std::printf("  %-34s %8.2f ms  %7.2f GB/s\n",
                    nm, s * 1e3, double(touched) * PASS / 1e9 / s);
        return s;
    };

    std::printf("FAKE WORK -- rearranges instructions, moves the same bytes:\n");
    const double f_unroll = bench([&] { nt_unroll8(w2.data(), w.data(), inband); },
                                  "8x unroll + NT stores", inband);
    const double f_ntls   = bench([&] { nt_load_store(w2.data(), w.data(), inband); },
                                  "NT streaming load + NT store", inband);
    const double f_rep    = bench([&] { rep_movsb_loop(w2.data(), w.data(), inband); },
                                  "rep movsb (copy, not negate)", inband);
    const double f_man    = bench([&] { for (std::size_t i = 0; i < inband; i += 32)
                                          manual_copy(w2.data() + i, w.data() + i, 32); },
                                  "manual AVX2 copy loop", inband);
    const double base     = bench([&] { inband_plain(w2.data(), w.data(), inband); },
                                  "reference: plain in-band negate", inband);

    std::printf("\nREAL WORK -- removes bytes:\n");
    const double real = bench([&] { sign_plane(pl2.data(), 0, plane); },
                              "sign plane NOT (N/8 B)", plane);

    std::printf("\n  vs reference plain in-band negate:\n");
    std::printf("    8x unroll + NT        %.3fx\n", base / f_unroll);
    std::printf("    NT load + NT store    %.3fx\n", base / f_ntls);
    std::printf("    rep movsb vs manual   %.3fx  (ERMS claim)\n", f_man / f_rep);
    std::printf("\n    SIGN PLANE            %.3fx  <-- the only one that changes bytes\n",
                base / real);

    const double best_fake = std::min(std::min(f_unroll, f_ntls), std::min(f_rep, f_man));
    std::printf("\n  best fake work : %.3fx\n", base / best_fake);
    std::printf("  real work      : %.3fx\n", base / real);
    std::printf("  ratio real/fake: %.1fx\n", (base / real) / (base / best_fake));

    std::printf("\n  sinks: %d %d %d\n", int(w2[0]), int(pl2[0]), int(f_rep > 0));
    return 0;
}
