// =============================================================================
// Q8KParity.cpp — byte-level Q8_K differential implementation
// =============================================================================
#include "Q8KParity.h"
#include <sstream>
#include <set>

namespace RawrXD {
namespace Parity {

json Q8KParityReport::ToJson() const {
    json j;
    j["blocks_compared"]      = blocks_compared;
    j["d_bits_mismatches"]     = d_bits_mismatches;
    j["qs_mismatch_blocks"]   = qs_mismatch_blocks;
    j["bsum_mismatch_blocks"] = bsum_mismatch_blocks;
    j["qs_value_mismatches"]  = qs_value_mismatches;
    j["bsum_value_mismatches"] = bsum_value_mismatches;
    j["first_bad_block"]      = first_bad_block;
    j["fully_identical"]      = fully_identical;
    j["distinct_verdicts"]   = distinct_verdicts;
    if (first_difference) {
        const auto& d = *first_difference;
        j["first_difference"] = {
            {"block_index", d.block_index},
            {"d_bits_match", d.d_bits_match},
            {"qs_match", d.qs_match},
            {"bsums_match", d.bsums_match},
            {"qs_mismatches", d.qs_mismatches},
            {"bsum_mismatches", d.bsum_mismatches},
            {"first_qs_index", d.first_qs_index},
            {"verdict", d.Verdict()},
        };
    }
    return j;
}

Q8KParityReport CompareQ8KBlocks(const float* activation, int64_t k,
                                  const Q8KBlock* reference,
                                  const Q8KBlock* candidate,
                                  int64_t max_detail_blocks) {
    Q8KParityReport report;
    if (!activation || !reference || !candidate || k <= 0) {
        return report;
    }

    const int64_t nb = k / QK_K;
    report.blocks_compared = nb;

    std::set<std::string> verdicts;

    for (int64_t b = 0; b < nb; ++b) {
        const Q8KBlock& r = reference[b];
        const Q8KBlock& c = candidate[b];

        // --- d: compare the 32-bit bit patterns, not the float value ---
        uint32_t r_bits = 0, c_bits = 0;
        std::memcpy(&r_bits, &r.d, sizeof(uint32_t));
        std::memcpy(&c_bits, &c.d, sizeof(uint32_t));
        const bool d_match = (r_bits == c_bits);

        // --- qs: all 256 quantized bytes ---
        int qs_mismatches = 0;
        int first_qs_index = -1;
        for (int i = 0; i < QK_K; ++i) {
            if (r.qs[i] != c.qs[i]) {
                ++qs_mismatches;
                if (first_qs_index < 0) first_qs_index = i;
            }
        }
        const bool qs_match = (qs_mismatches == 0);

        // --- bsums: 16 half-block sums ---
        int bsum_mismatches = 0;
        for (int i = 0; i < QK_K / 16; ++i) {
            if (r.bsums[i] != c.bsums[i]) ++bsum_mismatches;
        }
        const bool bsums_match = (bsum_mismatches == 0);

        if (!d_match)   ++report.d_bits_mismatches;
        if (!qs_match)  { ++report.qs_mismatch_blocks; report.qs_value_mismatches += qs_mismatches; }
        if (!bsums_match) { ++report.bsum_mismatch_blocks; report.bsum_value_mismatches += bsum_mismatches; }

        const bool identical = d_match && qs_match && bsums_match;
        if (!identical && report.first_bad_block < 0) {
            report.first_bad_block = static_cast<int>(b);
            Q8KBlockDiff diff;
            diff.block_index    = static_cast<int>(b);
            diff.d_bits_match   = d_match;
            diff.qs_match       = qs_match;
            diff.bsums_match    = bsums_match;
            diff.qs_mismatches  = qs_mismatches;
            diff.bsum_mismatches = bsum_mismatches;
            diff.first_qs_index = first_qs_index;
            report.first_difference = diff;
            verdicts.insert(diff.Verdict());
        }
        else if (!identical && report.first_bad_block >= 0 &&
                 static_cast<int64_t>(verdicts.size()) < max_detail_blocks) {
            Q8KBlockDiff d2;
            d2.block_index = static_cast<int>(b);
            d2.d_bits_match = d_match;
            d2.qs_match = qs_match;
            d2.bsums_match = bsums_match;
            d2.qs_mismatches = qs_mismatches;
            d2.bsum_mismatches = bsum_mismatches;
            d2.first_qs_index = first_qs_index;
            verdicts.insert(d2.Verdict());
        }
    }

    report.fully_identical = (report.d_bits_mismatches == 0 &&
                              report.qs_mismatch_blocks == 0 &&
                              report.bsum_mismatch_blocks == 0);
    report.distinct_verdicts.assign(verdicts.begin(), verdicts.end());
    return report;
}

Q8KParityReport DiffDeep2VsReference(const float* activation, int64_t k) {
    if (k <= 0) return {};
    const int64_t nb = k / QK_K;
    std::vector<Q8KBlock> ref(nb);
    std::vector<Q8KBlock> deep2(nb);
    QuantizeRowQ8KReference(activation, ref.data(), k);
    QuantizeRowQ8KDeep2Current(activation, deep2.data(), k);
    return CompareQ8KBlocks(activation, k, ref.data(), deep2.data());
}

Q8KParityReport CompareInterleavedQ8(const float* deep2_interleaved,
                                     const float* ggml_interleaved,
                                     int64_t n_in) {
    Q8KParityReport report;
    const int64_t nb = n_in / QK_K;
    report.blocks_compared = nb;

    std::set<std::string> verdicts;

    for (int64_t b = 0; b < nb; ++b) {
        const float* d8 = deep2_interleaved + b * 273;
        const float* gf = ggml_interleaved  + b * 273;

        uint32_t d_bits = 0, g_bits = 0;
        float dv = d8[0], gv = gf[0];
        std::memcpy(&d_bits, &dv, sizeof(uint32_t));
        std::memcpy(&g_bits, &gv, sizeof(uint32_t));
        const bool d_match = (d_bits == g_bits);

        int qs_mismatches = 0;
        for (int i = 0; i < QK_K; ++i) {
            if (d8[1 + i] != gf[1 + i]) ++qs_mismatches;
        }
        const bool qs_match = (qs_mismatches == 0);

        int bsum_mismatches = 0;
        for (int i = 0; i < 16; ++i) {
            if (d8[257 + i] != gf[257 + i]) ++bsum_mismatches;
        }
        const bool bsums_match = (bsum_mismatches == 0);

        if (!d_match) ++report.d_bits_mismatches;
        if (!qs_match) { ++report.qs_mismatch_blocks; report.qs_value_mismatches += qs_mismatches; }
        if (!bsums_match) { ++report.bsum_mismatch_blocks; report.bsum_value_mismatches += bsum_mismatches; }

        if ((!d_match || !qs_match || !bsums_match) && report.first_bad_block < 0) {
            report.first_bad_block = static_cast<int>(b);
            Q8KBlockDiff diff;
            diff.block_index = static_cast<int>(b);
            diff.d_bits_match = d_match;
            diff.qs_match = qs_match;
            diff.bsums_match = bsums_match;
            diff.qs_mismatches = qs_mismatches;
            diff.bsum_mismatches = bsum_mismatches;
            diff.first_qs_index = -1;
            for (int i = 0; i < QK_K; ++i) {
                if (d8[1 + i] != gf[1 + i]) { diff.first_qs_index = i; break; }
            }
            report.first_difference = diff;
            verdicts.insert(diff.Verdict());
        }
    }

    report.fully_identical = (report.d_bits_mismatches == 0 &&
                              report.qs_mismatch_blocks == 0 &&
                              report.bsum_mismatch_blocks == 0);
    report.distinct_verdicts.assign(verdicts.begin(), verdicts.end());
    return report;
}

} // namespace Parity
} // namespace RawrXD
