// =============================================================================
// q8k_parity_tool.cpp — the decisive Q8_K byte-level experiment
// =============================================================================
// Usage:
//   q8k_parity_tool [--blocks N] [--seed S] [--json out.json] [--print-blocks]
//
// Generates a deterministic pseudo-random activation, quantizes it with BOTH
// the authoritative ggml reference (embedded, semantics verified against
// 3rdparty/ggml/src/ggml-quants.c:2555) and Deep2's current algorithm
// (copied verbatim from src/deep2/runtime_graph_executor.cpp:40 and :716),
// then reports the field-by-field decision table.
//
// Exit codes:
//   0  Q8_K blocks are byte-identical (d, qs, bsums)
//   1  Q8_K blocks differ; the verdict names the repair target
//   2  tool usage error
// =============================================================================
#include "Q8KParity.h"
#include "Q8KQuant.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <random>
#include <fstream>

using json = nlohmann::json;
using namespace RawrXD::Parity;

int main(int argc, char** argv) {
    int64_t n_blocks = 8;
    uint32_t seed = 12345u;
    std::string json_out;
    bool print_blocks = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--blocks" && i + 1 < argc)      n_blocks = std::atoll(argv[++i]);
        else if (a == "--seed" && i + 1 < argc)   seed = static_cast<uint32_t>(std::atoi(argv[++i]));
        else if (a == "--json" && i + 1 < argc)   json_out = argv[++i];
        else if (a == "--print-blocks")           print_blocks = true;
        else if (a == "--help" || a == "-h") {
            std::printf("Usage: %s [--blocks N] [--seed S] [--json out.json] [--print-blocks]\n", argv[0]);
            return 0;
        }
    }

    if (n_blocks <= 0 || n_blocks > 4096) {
        std::fprintf(stderr, "blocks must be in 1..4096\n");
        return 2;
    }

    const int64_t k = n_blocks * QK_K;
    std::vector<float> x(k);
    std::mt19937 rng(seed);
    // A realistic activation mix: a dominant signed extremum per block plus
    // small tails, so both scale and rounding paths are exercised.
    std::uniform_real_distribution<float> small(-1.0f, 1.0f);
    for (int64_t b = 0; b < n_blocks; ++b) {
        for (int i = 0; i < QK_K; ++i) {
            x[b * QK_K + i] = small(rng) * 0.05f;
        }
        // Force a dominant extremum, alternating sign so both the positive-max
        // and negative-max branches of the reference scale are covered.
        const int extremum_index = static_cast<int>(rng() % QK_K);
        const float sign = (b % 2 == 0) ? 1.0f : -1.0f;
        x[b * QK_K + extremum_index] = sign * (3.5f + 0.5f * small(rng));

        // Exact halfway cases, computed from the extremum this block actually
        // uses, so the reference and the candidate provably disagree about the
        // rounding tie. ggml's nearest_int is half-to-even; std::lround is
        // half-away-from-zero. With d = |extremum|/127, the tie value is
        // (n + 0.5) * d for integer n.
        const float extremum = x[b * QK_K + extremum_index];
        const float d_scale = std::fabs(extremum) / 127.0f;
        for (int h = 0; h < 4 && d_scale > 0.0f; ++h) {
            const int idx = static_cast<int>(rng() % QK_K);
            if (idx == extremum_index) continue;
            const float tie = (1.0f + static_cast<float>(h)) * d_scale;
            x[b * QK_K + idx] = (h % 2 == 0) ? tie : -tie;
        }
    }

    const int64_t nb = k / QK_K;
    std::vector<Q8KBlock> ref(nb), d2(nb), fix(nb);
    QuantizeRowQ8KReference(x.data(), ref.data(), k);
    QuantizeRowQ8KDeep2Current(x.data(), d2.data(), k);
    RawrXD::Deep2::QuantizeRowQ8K(x.data(), fix.data(), k);

    Q8KParityReport report = CompareQ8KBlocks(x.data(), k, ref.data(), d2.data());
    Q8KParityReport fixed = CompareQ8KBlocks(x.data(), k, ref.data(), fix.data());

    std::printf("=== BEFORE the fix (Deep2's previous quantiser) ===\n");
    std::printf("blocks_compared      : %lld\n", static_cast<long long>(report.blocks_compared));
    std::printf("d bit mismatches     : %lld\n", static_cast<long long>(report.d_bits_mismatches));
    std::printf("blocks with qs diff  : %lld (values: %lld)\n",
                static_cast<long long>(report.qs_mismatch_blocks),
                static_cast<long long>(report.qs_value_mismatches));
    std::printf("blocks with bsum diff: %lld (values: %lld)\n",
                static_cast<long long>(report.bsum_mismatch_blocks),
                static_cast<long long>(report.bsum_value_mismatches));
    std::printf("fully identical      : %s\n", report.fully_identical ? "YES" : "NO");

    std::printf("\n=== AFTER the Q8KQuant.h fix (production) ===\n");
    std::printf("d bit mismatches     : %lld\n", static_cast<long long>(fixed.d_bits_mismatches));
    std::printf("blocks with qs diff  : %lld (values: %lld)\n",
                static_cast<long long>(fixed.qs_mismatch_blocks),
                static_cast<long long>(fixed.qs_value_mismatches));
    std::printf("blocks with bsum diff: %lld (values: %lld)\n",
                static_cast<long long>(fixed.bsum_mismatch_blocks),
                static_cast<long long>(fixed.bsum_value_mismatches));
    std::printf("fully identical      : %s\n", fixed.fully_identical ? "YES" : "NO");

    // BEFORE-only diagnostics. Printed from `report` (the old quantiser) so a
    // passing AFTER result is never contradicted by leftover before-fix output.
    if (report.first_difference) {
        const auto& d = *report.first_difference;
        std::printf("\n--- BEFORE only: first divergent block %d ---\n", d.block_index);
        std::printf("d bits match        : %s\n", d.d_bits_match ? "yes" : "NO");
        std::printf("qs[256] match       : %s (%d mismatches, first at %d)\n",
                    d.qs_match ? "yes" : "NO", d.qs_mismatches, d.first_qs_index);
        std::printf("bsums[16] match     : %s (%d mismatches)\n",
                    d.bsums_match ? "yes" : "NO", d.bsum_mismatches);

        // Show the scale side by side.
        const Q8KBlock& r = ref[d.block_index];
        const Q8KBlock& c = d2[d.block_index];
        uint32_t rb = 0, cb = 0;
        std::memcpy(&rb, &r.d, 4);
        std::memcpy(&cb, &c.d, 4);
        std::printf("\nscale d:\n");
        std::printf("  ggml  ref : %.9g  (bits 0x%08X)\n", r.d, rb);
        std::printf("  deep2 old : %.9g  (bits 0x%08X)\n", c.d, cb);
        std::printf("  d bit patterns identical: %s\n", rb == cb ? "yes" : "NO");

        if (!d.qs_match) {
            std::printf("\nqs[%d] (first differing index):\n", d.first_qs_index);
            std::printf("  ggml  ref : %d\n", r.qs[d.first_qs_index]);
            std::printf("  deep2 old : %d\n", c.qs[d.first_qs_index]);
        }
        if (!d.bsums_match) {
            std::printf("\nbsums (first differing group of 16 values):\n");
            for (int i = 0; i < 16; ++i) {
                if (r.bsums[i] != c.bsums[i]) {
                    std::printf("  bsums[%2d] ref=%d deep2_old=%d\n", i, r.bsums[i], c.bsums[i]);
                    break;
                }
            }
        }

        std::printf("\nVERDICT (before): %s\n", d.Verdict().c_str());
    }



    std::printf("\n=== FINAL VERDICT ===\n");
    std::printf("Q8_K packing parity: %s\n", fixed.fully_identical ? "PASS" : "FAIL");
    if (!fixed.fully_identical && fixed.first_difference) {
        std::printf("remaining cause: %s\n",
                    fixed.first_difference->Verdict().c_str());
    }
    std::printf("\n=== decision table (for any remaining divergence) ===\n");
    std::printf("d bits differ  -> scale selection/calculation (signed extremum)\n");
    std::printf("d same, qs diff-> rounding or clamp semantics (nearest_int + MIN(127,v))\n");
    std::printf("qs same, bsum diff -> signed accumulation or grouping\n");
    std::printf("all fields same -> divergence is downstream (Q4_K/Q6_K decode or dot)\n");

    if (!json_out.empty()) {
        std::ofstream f(json_out);
        if (f) {
            json j = fixed.ToJson();          // the AFTER report is authoritative
            j["tool"] = "q8k_parity";
            j["k"] = static_cast<int64_t>(k);
            j["seed"] = seed;
            j["parity"] = fixed.fully_identical ? "PASS" : "FAIL";
            j["before"] = report.ToJson();    // retained for the audit trail
            f << j.dump(2);
            std::printf("\nJSON written: %s\n", json_out.c_str());
        } else {
            std::fprintf(stderr, "cannot write %s\n", json_out.c_str());
        }
    }

    return fixed.fully_identical ? 0 : 1;
}
