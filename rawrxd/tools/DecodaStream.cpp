// RAWRXD_DECODA_STREAM_001
//
// Streams DeepSeek-V2-Lite-Chat.Q4_K_M.gguf through Decoda v3's real encoder,
// using GGUFStream for memory-bounded block-aligned access. Nothing is ever
// materialized whole: peak decode buffer is fixed by the window, not the model.
//
// Per block-granular slice:
//   1. dequantize Q4_K/Q6_K/Q8_0/F32 -> float32   (inside GGUFStream)
//   2. Decoda::Tensor::encode(slice)              (real decoda.cpp)
//   3. reconstruct at each fidelity state, compare, accumulate
//
// Reports measured encode+decode throughput and the implied ns/token for the
// 2.196B active-parameter working set of DeepSeek-V2-Lite.

#include "deep2/GGUFLoader.hpp"
#include "deep2/GGUFStream.hpp"
#include "decoda/decoda.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>\n#include <cstring>\n#include <cstdlib>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    const std::string path = argc > 1 ? argv[1] : "";
    if (path.empty()) { std::printf("usage: <model.gguf> [max_slices]\n"); return 1; }
    const std::uint64_t SLICE_BUDGET = (argc > 2) ? std::strtoull(argv[2], nullptr, 10) : 4000ull;

    std::printf("RAWRXD_DECODA_STREAM_001\n");

    Deep2::GGUFLoader L;
    auto t0 = std::chrono::steady_clock::now();
    if (!L.load(path)) { std::printf("LOAD_FAILED\n"); return 1; }
    const double mapS = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t0).count();
    auto names = L.listTensors();
    std::printf("mapped in %.3f s (no whole-file copy)  tensors=%zu\n", mapS, names.size());

    auto& reg = Deep2::QuantKernelRegistry::Instance();
    reg.RegisterBuiltins();

    // Round each slice's element count up to a whole quant block, then treat it
    // as a single-column-per-row tensor whose row count fits Decoda's encoder.
    const std::uint32_t SLICE_BLOCKS = 512;   // decode window

    decoda::BuildOptions bo;
    bo.block_size = 64;
    bo.residual_bits = 12;
    bo.outlier_sigma = 3.0f;
    bo.store_exact_f32 = false;               // approximate tier only

    const struct { std::uint32_t planes; const char* nm; } states[] = {
        {0, "plane0"}, {2, "plane2"}, {4, "plane4"},
    };
    double err[3] = {0, 0, 0};

    std::uint64_t elems = 0, quantBytes = 0, slices = 0, tensors = 0, failed = 0, skipped = 0;
    double encS = 0, recS = 0, dqS = 0;
    double checksum = 0;
    std::size_t peakWindow = 0;

    for (const auto& nm : names) {
        Deep2::GGUFStream S(reg);
        S.setWindow(SLICE_BLOCKS);
        std::string err;
        if (!S.open(L, nm, &err)) { ++failed; continue; }
        const std::size_t be = S.blockElems();
        if (!be) { ++failed; continue; }
        ++tensors;
        peakWindow = std::max(peakWindow, S.workingSetBytes());

        Deep2::GGUFStream::Slice sl;
        while (slices < SLICE_BUDGET && S.next(sl)) {
            const std::size_t cnt = sl.elements;
            if (!cnt) continue;
            ++slices;
            elems += cnt;
            quantBytes += sl.blocks * S.blockBytes();

            const float* src = S.sliceData();
            if (!src) continue;

            // Round up to a whole quant block so Decoda sees a clean tensor.
            const std::size_t padded = ((cnt + be - 1) / be) * be;
            const std::uint32_t cols = static_cast<std::uint32_t>(
                std::min<std::size_t>(padded, 1u << 20));
            const std::uint32_t rows = static_cast<std::uint32_t>(padded / cols);
            if (!rows) continue;

            std::vector<float> host(padded, 0.0f);
            const auto a0 = std::chrono::steady_clock::now();
            std::memcpy(host.data(), src, cnt * sizeof(float));
            dqS += std::chrono::duration<double>(
                std::chrono::steady_clock::now() - a0).count();

            // ---- real Decoda encode ----
            const auto a1 = std::chrono::steady_clock::now();
            decoda::Tensor T;
            try {
                T = decoda::Tensor::encode(host.data(), rows, cols, bo);
            } catch (...) { continue; }
            encS += std::chrono::duration<double>(
                std::chrono::steady_clock::now() - a1).count();

            // ---- reconstruct each state, measure error ----
            const auto a2 = std::chrono::steady_clock::now();
            for (int si = 0; si < 3; ++si) {
                decoda::FidelityState st;
                st.include_outliers = true;
                st.residual_planes = states[si].planes;
                double num = 0, den = 0;
                for (std::uint32_t r = 0; r < rows; ++r)
                    for (std::uint32_t c = 0; c < cols; ++c) {
                        const std::size_t i = std::size_t(r) * cols + c;
                        if (i >= cnt) break;
                        const double g = T.reconstructedWeight(r, c, st);
                        const double d = g - double(host[i]);
                        num += d * d; den += double(host[i]) * double(host[i]);
                    }
                const double e = den > 0 ? std::sqrt(num / den) : 0.0;
                err[si] += e;
            }
            recS += std::chrono::duration<double>(
                std::chrono::steady_clock::now() - a2).count();
            checksum += double(host[0]) + double(T.reconstructedWeight(
                0, 0, decoda::FidelityState{}));
        }
        if (S.next(sl)) ++skipped;
    }

    const double totS = dqS + encS + recS;
    std::printf("\nstreamed %llu tensors (%llu failed), %llu slices\n",
                (unsigned long long)tensors, (unsigned long long)failed,
                (unsigned long long)slices);
    std::printf("  elements            : %llu\n", (unsigned long long)elems);
    std::printf("  quant bytes touched : %llu (%.2f GB)\n",
                (unsigned long long)quantBytes, double(quantBytes) / 1e9);
    std::printf("  peak decode window  : %.2f MB   (fixed, not model-dependent)\n",
                double(peakWindow) / (1024.0 * 1024.0));
    std::printf("\ntiming\n");
    std::printf("  dequant(copy)  : %8.3f s  %7.2f GB/s f32\n", dqS,
                double(elems) * 4 / 1e9 / std::max(dqS, 1e-9));
    std::printf("  decoda encode  : %8.3f s  %7.2f Melem/s\n", encS,
                double(elems) / 1e6 / std::max(encS, 1e-9));
    std::printf("  reconstruct x3 : %8.3f s\n", recS);
    std::printf("  total          : %8.3f s\n", totS);

    std::printf("\nmean rel_L2 per state (over all slices)\n");
    const std::uint32_t ns = states[0].planes ? 3u : 3u;
    for (int si = 0; si < 3; ++si)
        std::printf("  %-8s %.6f\n", states[si].nm, err[si] / double(std::max<std::uint64_t>(1, slices)));

    // implied ns/token: only the active slice of each tensor is decoded in practice,
    // so use the whole-element rate as a lower bound on decode cost per token.
    const double activeElems = 2196242432.0;
    const double elemsPerSec = double(elems) / std::max(totS, 1e-9);
    const double sPerTok = activeElems / elemsPerSec;
    std::printf("\nthroughput implication (whole-model rate applied to active set)\n");
    std::printf("  rate                 : %.3f Melem/s\n", elemsPerSec / 1e6);
    std::printf("  2.196B active params : %.3f ms/token  -> %.2f tok/s\n",
                sPerTok * 1e3, 1.0 / sPerTok);
    std::printf("  NOTE: this decodes EVERY element, not the 6-of-64 routed experts,\n");
    std::printf("        so it is a lower bound on tok/s by roughly the routing factor.\n");

    std::printf("\nchecksum %.6g\n", checksum);
    (void)ns;
    return 0;
}
