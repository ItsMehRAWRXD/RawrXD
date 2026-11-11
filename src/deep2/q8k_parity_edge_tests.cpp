// =============================================================================
// q8k_parity_edge_tests.cpp — edge cases for the ggml-exact Q8_K quantiser
// =============================================================================
// Covers the cases named in the acceptance criteria:
//   * zero blocks (all-zero activation)
//   * signed extrema (positive-max and negative-max blocks)
//   * rounding boundaries (exact halfway ties)
//   * saturation (values that drive qs past 127)
//   * partial super-blocks (n_in not a multiple of 256)
//   * a broad seed sweep
//
// Exit code 0 only when the PRODUCTION quantiser (src/deep2/Q8KQuant.h) matches
// the embedded ggml-reference oracle byte-for-byte on every case.
// =============================================================================
#include "Q8KParity.h"
#include "Q8KQuant.h"

#include <cstdio>
#include <cstring>
#include <vector>
#include <random>
#include <string>

using namespace RawrXD;
using json = nlohmann::json;

static int g_failures = 0;
static int g_checks = 0;

static void Check(const std::string& name,
                  const std::vector<float>& activation,
                  int64_t k) {
    ++g_checks;
    const int64_t nb = k / 256;
    std::vector<Deep2::Q8KBlock> ref(nb), prod(nb);
    Parity::QuantizeRowQ8KReference(activation.data(), ref.data(), k);
    Deep2::QuantizeRowQ8K(activation.data(), prod.data(), k);

    Parity::Q8KParityReport report =
        Parity::CompareQ8KBlocks(activation.data(), k, ref.data(), prod.data());

    const bool pass = report.fully_identical;
    std::printf("[%-46s] %s", name.c_str(), pass ? "PASS" : "FAIL");
    if (!pass) {
        ++g_failures;
        std::printf("  d=%lld qs=%lld(%lld vals) bsum=%lld",
                    (long long)report.d_bits_mismatches,
                    (long long)report.qs_mismatch_blocks,
                    (long long)report.qs_value_mismatches,
                    (long long)report.bsum_mismatch_blocks);
        if (report.first_difference) {
            std::printf("  verdict=%s", report.first_difference->Verdict().c_str());
        }
    }
    std::printf("\n");
}

// ---------------------------------------------------------------------------
int main() {
    std::printf("=== Q8_K edge-case suite (production vs ggml reference) ===\n\n");

    // ---- 1. Zero blocks: amax == 0 must give d=0, qs=0, bsums=0 ----
    {
        std::vector<float> z(256 * 4, 0.0f);
        Check("all-zero activation (4 blocks)", z, 256 * 4);
    }

    // ---- 2. Signed extrema: positive max, then negative max ----
    {
        std::vector<float> v(256 * 2, 0.0f);
        // block 0: positive extremum at index 7
        for (int i = 0; i < 256; ++i) v[i] = 0.01f * static_cast<float>(i % 7 - 3);
        v[7] = 2.5f;
        // block 1: negative extremum at index 200
        for (int i = 0; i < 256; ++i) v[256 + i] = -0.01f * static_cast<float>(i % 5 - 2);
        v[256 + 200] = -9.75f;
        Check("signed extrema (positive then negative)", v, 256 * 2);
    }

    // ---- 3. Rounding boundaries: exact halfway ties ----
    {
        std::vector<float> v(256, 0.0f);
        v[0] = 4.0f;                       // extremum -> d = 4/127
        const float d = 4.0f / 127.0f;
        for (int i = 1; i < 256; ++i) {
            // exact halfway values: (n + 0.5) * d for small n
            const float n = static_cast<float>(i % 4);
            v[i] = ((i % 8) < 4 ? 1.0f : -1.0f) * (n + 0.5f) * d;
        }
        Check("exact halfway rounding ties", v, 256);
    }

    // ---- 4. Saturation: values that drive the rounded qs past 127 ----
    {
        std::vector<float> v(256, 0.0f);
        // A single tiny extremum makes every other value saturate.
        v[0] = 1e-30f;
        for (int i = 1; i < 256; ++i) v[i] = 3.0f * ((i % 3) - 1.0f);
        Check("saturation (MIN(127,v) clamp)", v, 256);
    }

    // ---- 5. Denormal / near-zero mixture ----
    {
        std::vector<float> v(256, 0.0f);
        v[3] = std::numeric_limits<float>::min();   // smallest normal
        v[4] = 0.0f;
        v[5] = 1.0f;
        Check("denormal magnitude alongside zero", v, 256);
    }

    // ---- 6. Partial super-block: n_in not a multiple of 256 ----
    {
        const size_t n_in = 256 * 3 + 128;   // 3 full + 1 half block
        std::vector<float> v(n_in);
        std::mt19937 rng(7u);
        std::uniform_real_distribution<float> dist(-2.0f, 2.0f);
        for (auto& e : v) e = dist(rng);
        // The block-level oracle only compares whole 256-value blocks, so drive
        // it through the interleaved builder, which does handle partial tails.
        ++g_checks;
        std::vector<float> interleaved_prod((n_in + 255) / 256 * 273, 0.0f);
        Deep2::BuildInterleavedQ8K(v.data(), n_in, interleaved_prod.data());

        // Build the reference interleaved layout independently, block by block.
        std::vector<float> interleaved_ref(interleaved_prod.size(), 0.0f);
        const size_t n_sb = (n_in + 255) / 256;
        for (size_t b = 0; b < n_sb; ++b) {
            const size_t off = b * 256;
            const size_t elems = std::min<size_t>(256, n_in - off);
            std::vector<Deep2::Q8KBlock> blk(1);
            // Quantise only the populated prefix: pad with zeros to a full
            // block so the reference sees the same 256-value geometry.
            std::vector<float> padded(256, 0.0f);
            for (size_t i = 0; i < elems; ++i) padded[i] = v[off + i];
            Parity::QuantizeRowQ8KReference(padded.data(), blk.data(), 256);

            float* out = interleaved_ref.data() + b * 273;
            out[0] = blk[0].d;
            for (int i = 0; i < 256; ++i) out[1 + i] = static_cast<float>(blk[0].qs[i]);
            // Only the populated half-blocks carry a sum; the rest stay zero.
            const size_t groups = (elems + 15) / 16;
            for (size_t j = 0; j < groups; ++j) out[257 + j] = static_cast<float>(blk[0].bsums[j]);
        }

        Parity::Q8KParityReport report =
            Parity::CompareInterleavedQ8(interleaved_prod.data(),
                                         interleaved_ref.data(),
                                         static_cast<int64_t>(n_in));
        const bool pass = report.fully_identical;
        std::printf("[%-46s] %s", "partial super-block (3 full + 128 tail)", pass ? "PASS" : "FAIL");
        if (!pass) { ++g_failures; std::printf("  d=%lld qs=%lld", (long long)report.d_bits_mismatches, (long long)report.qs_mismatch_blocks); }
        std::printf("\n");
    }

    // ---- 7. Broad seed sweep: many random activations ----
    {
        int bad = 0;
        const int kSweepSeeds = 40;
        for (int s = 0; s < kSweepSeeds; ++s) {
            std::mt19937 rng(1000u + static_cast<unsigned>(s));
            // Vary block count and magnitude distribution per seed.
            std::uniform_int_distribution<int> nb_dist(1, 6);
            std::uniform_real_distribution<float> mag(0.001f, 50.0f);
            std::normal_distribution<float> noise(0.0f, 1.0f);
            const int nb = nb_dist(rng);
            const int64_t k = nb * 256;
            std::vector<float> v(k);
            for (auto& e : v) e = noise(rng) * mag(rng);
            // Alternating signed extrema so both scale branches are exercised.
            for (int b = 0; b < nb; ++b) {
                const float sign = (b % 2 == 0) ? 1.0f : -1.0f;
                v[b * 256 + (rng() % 256)] = sign * (mag(rng) + 1.0f);
            }
            std::vector<Deep2::Q8KBlock> ref(nb), prod(nb);
            Parity::QuantizeRowQ8KReference(v.data(), ref.data(), k);
            Deep2::QuantizeRowQ8K(v.data(), prod.data(), k);
            auto report = Parity::CompareQ8KBlocks(v.data(), k, ref.data(), prod.data());
            if (!report.fully_identical) {
                ++bad;
                if (bad <= 2) {
                    std::printf("   sweep seed %d: %s\n", s,
                        report.first_difference
                            ? report.first_difference->Verdict().c_str()
                            : "differs");
                }
            }
        }
        ++g_checks;
        const bool pass = (bad == 0);
        std::printf("[%-46s] %s", "seed sweep 40 random activations",
                    pass ? "PASS" : "FAIL");
        if (!pass) { ++g_failures; std::printf("  %d/%d seeds differ", bad, kSweepSeeds); }
        std::printf("\n");
    }

    std::printf("\n=== result: %d checks, %d failures ===\n", g_checks, g_failures);
    std::printf("%s\n", g_failures == 0 ? "ALL Q8_K EDGE CASES PASS" : "Q8_K EDGE CASES FAILED");
    return g_failures == 0 ? 0 : 1;
}
