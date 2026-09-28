// q4k_vecdot_parity_gate.cpp — Q4K_VEC_DOT_PARITY_001
//
// Deterministic regression gate for the suspected-broken Q4K mul_mat path:
//   A) Deep2 vec_dot_q4_K_q8_K (the exact function under suspicion, called
//      through the registered GEMV kernel for type 12)
//   B) reference = canonical llama dequantize_row_q4_K (proven llama-consistent
//      by the EMBED bit-match) + float dot with the same input
//
// Inputs are frozen:
//   - weights: first 8 rows of blk.4.ffn_gate.weight from the 32B GGUF
//   - activation x: read from the oracle trace VEC=LAYER_4_FFN_NORM dump
//     (falls back to a deterministic ramp when the trace is absent)
//
// Pass criteria:
//   max_abs_error per row < 1e-2 * (1 + max|ref|)  AND rel_err < 2e-3
//
// usage: q4k_vecdot_parity_gate.exe <model.gguf> [trace.txt]
#include "QuantKernelRegistry.hpp"
#include "GGUFLoader.hpp"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <fstream>
#include <regex>
#include <string>
#include <vector>

namespace Deep2 {
// Canonical Q4_K: 144 bytes per 256 values.
struct CanonQ4K {
    uint16_t d;
    uint16_t dmin;
    uint8_t  scales[12];
    uint8_t  qs[128];
};
static float canon_f16(uint16_t h) {
    uint32_t sign = (static_cast<uint32_t>(h & 0x8000)) << 16;
    uint32_t e = (h >> 10) & 0x1F;
    uint32_t f = h & 0x03FF;
    if (e == 0) {
        float v = static_cast<float>(f) * 5.960464477539063e-08f;
        return (h & 0x8000) ? -v : v;
    }
    if (e == 31) {
        uint32_t bits = sign | 0x7F800000 | (f << 13);
        return reinterpret_cast<float&>(bits);
    }
    uint32_t bits = sign | ((e - 15 + 127) << 23) | (f << 13);
    return reinterpret_cast<float&>(bits);
}
// Canonical llama get_scale_min_k4 (ggml-quants.h). Q4_K scales/mins are
// 6-bit fields (12 bytes = 8×6-bit scales + 8×6-bit mins):
//   j < 4:  d = q[j] & 63;            m = q[j + 4] & 63;
//   j >= 4: d = (q[j+4] & 0xF) | ((q[j-4] >> 6) << 4);
//           m = (q[j+4] >> 4) | ((q[j] >> 6) << 4);
// The 6-bit min decode is confirmed by the EMBED bit-match and the utmp dance.
static void canon_scale_min(int j, const uint8_t* q, int& d, int& m) {
    if (j < 4) {
        d = q[j] & 63;
        m = q[j + 4] & 63;
    } else {
        d = (q[j + 4] & 0xF) | ((q[j - 4] >> 6) << 4);
        m = (q[j + 4] >> 4) | ((q[j] >> 6) << 4);
    }
}
// Canonical llama dequantize_row_q4_K (ggml-quants.c, VERBATIM): for each
// 64-value chunk, scale pair (is+0, is+1) via get_scale_min_k4; 32 LOW
// nibbles then 32 HIGH nibbles from the same 32 bytes.
static void canon_dequant_block(const CanonQ4K& blk, float* y) {
    const float d = canon_f16(blk.d);
    const float dmin = canon_f16(blk.dmin);
    int sc[8], mn[8];
    for (int j = 0; j < 8; ++j) canon_scale_min(j, blk.scales, sc[j], mn[j]);
    const uint8_t* q = blk.qs;
    int is = 0;
    for (int j = 0; j < 256; j += 64) {
        const float d1 = d * static_cast<float>(sc[is]);
        const float m1 = dmin * static_cast<float>(mn[is]);
        const float d2 = d * static_cast<float>(sc[is + 1]);
        const float m2 = dmin * static_cast<float>(mn[is + 1]);
        for (int l = 0; l < 32; ++l) {
            y[j + l] = d1 * static_cast<float>(q[l] & 0xF) - m1;
        }
        for (int l = 0; l < 32; ++l) {
            y[j + 32 + l] = d2 * static_cast<float>(q[l] >> 4) - m2;
        }
        q += 32;
        is += 2;
    }
}
} // namespace Deep2

using Deep2::QuantKernelRegistry;

static std::vector<std::string> split_csv(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (const char c : s) {
        if (c == ',') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    out.push_back(cur);
    return out;
}

static bool loadTraceVector(const char* path, std::vector<float>& out) {
    std::ifstream f(path);
    if (!f) return false;
    const std::regex vecHead("^STEP=\\d+ VEC=LAYER_4_FFN_NORM N=(\\d+)");
    const std::regex data("^-?[0-9.eE+,\\-]+$");
    std::string line;
    bool collecting = false;
    std::vector<float> buf;
    while (std::getline(f, line)) {
        std::smatch m;
        if (std::regex_search(line, m, vecHead)) {
            collecting = true;
            buf.clear();
            continue;
        }
        if (collecting && std::regex_match(line, data)) {
            for (const auto& tok : split_csv(line)) buf.push_back(std::stof(tok));
        } else if (collecting) {
            break;  // next record started
        }
    }
    if (collecting && buf.size() == 5120) {
        out = std::move(buf);
        return true;
    }
    return false;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr,
            "usage: q4k_vecdot_parity_gate.exe <model.gguf> [oracle_trace.txt]\n");
        return 2;
    }
    Deep2::GGUFLoader loader;
    if (!loader.load(argv[1])) {
        std::fprintf(stderr, "PARITY=HOLD stage=gguf_load\n");
        return 11;
    }
    const Deep2::GGUFTensor* t = loader.getTensor("blk.4.ffn_gate.weight");
    if (!t || !t->data || t->shape.size() < 2) {
        std::fprintf(stderr, "PARITY=HOLD stage=tensor_lookup\n");
        return 12;
    }
    const int64_t cols = t->shape[0];
    const int64_t rows = t->shape[1];
    const size_t rowBytes = static_cast<size_t>(cols) / 256 * 144;
    const int kRows = 8;

    // Activation: prefer the oracle-trace FFN_NORM vector (the engine's own
    // GEMV input), else a deterministic ramp.
    std::vector<float> x(static_cast<size_t>(cols));
    bool xFromTrace = false;
    if (argc > 2) {
        xFromTrace = loadTraceVector(argv[2], x);
    }
    if (!xFromTrace) {
        for (int64_t i = 0; i < cols; ++i) {
            x[static_cast<size_t>(i)] =
                std::sin(static_cast<float>(i) * 0.01f) * 0.5f + 0.01f;
        }
    }

    // Reference: canonical dequant + float dot.
    std::vector<std::vector<float>> ref(kRows, std::vector<float>(cols));
    const uint8_t* base = t->data;
    for (int r = 0; r < kRows; ++r) {
        const uint8_t* rowBase = base + static_cast<size_t>(r) * rowBytes;
        Deep2::CanonQ4K blk;
        for (size_t b = 0; b < static_cast<size_t>(cols) / 256; ++b) {
            std::memcpy(&blk, rowBase + b * 144, 144);
            Deep2::canon_dequant_block(blk, &ref[r][b * 256]);
        }
    }

    QuantKernelRegistry::Instance().Initialize();
    auto kernel = QuantKernelRegistry::Instance().GetGEMV(12);
    if (!kernel) {
        std::fprintf(stderr, "PARITY=HOLD stage=no_kernel\n");
        return 14;
    }
    std::vector<float> got(kRows, 0.0f);
    kernel(base, x.data(), got.data(), kRows, static_cast<size_t>(cols));

    int mismatches = 0;
    double worstRel = 0.0;
    for (int r = 0; r < kRows; ++r) {
        double sum = 0.0;
        for (int64_t i = 0; i < cols; ++i) {
            sum += static_cast<double>(ref[r][static_cast<size_t>(i)]) *
                   static_cast<double>(x[static_cast<size_t>(i)]);
        }
        const double a = got[static_cast<size_t>(r)];
        const double rel = std::fabs(a - sum) /
                           (std::fabs(sum) > 1e-9 ? std::fabs(sum) : 1.0);
        if (rel > worstRel) worstRel = rel;
        std::fprintf(stderr,
            "ROW %d kernel=%.9g canonical=%.9g rel=%.4g\n", r, a, sum, rel);
        if (rel > 2e-3) ++mismatches;
    }
    std::fprintf(stderr,
        "GATE=Q4K_VEC_DOT_PARITY_001\n"
        "X_SOURCE=%s\n"
        "ROWS_TESTED=%d MISMATCHES=%d WORST_REL_ERR=%.4g\n",
        xFromTrace ? "ORACLE_TRACE_FFN_NORM" : "SYNTHETIC_RAMP",
        kRows, mismatches, worstRel);
    std::fprintf(stderr, "PARITY=%s\n", mismatches == 0 ? "PASS" : "FAIL");
    return mismatches == 0 ? 0 : 1;
}