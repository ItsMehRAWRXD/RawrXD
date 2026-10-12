// ============================================================================
// deep2_q5_decode_check  --  RAWRXD_DEEP2_LEGACY_QUANT_GPU_001
// ============================================================================
// Decode the first Q5_0 block of a tensor two ways - ggml's own
// dequantize_row_q5_0 and the shader's interpretation (qh as a little-endian
// u32; low nibble -> element j, high nibble -> element j+16; 5th bits at qh
// bits j and j+12) - and print both, so a mismatch is visible directly instead
// of inferred from a logit.
//
// Usage:
//   deep2_q5_decode_check.exe --model <gguf> --tensor <name> [--row N]
// ============================================================================
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "universal_gguf.hpp"

using namespace RawrXD::Deep2::Universal;

static uint16_t rd16(const uint8_t* p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

int main(int argc, char* argv[])
{
    std::string model, tensor;
    size_t row = 0;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--model" && i + 1 < argc) model = argv[++i];
        else if (a == "--tensor" && i + 1 < argc) tensor = argv[++i];
        else if (a == "--row" && i + 1 < argc) row = (size_t)std::strtoull(argv[++i], nullptr, 10);
    }
    if (model.empty() || tensor.empty()) {
        std::printf("usage: deep2_q5_decode_check.exe --model <gguf> --tensor <name> [--row N]\n");
        return 1;
    }
    const IngestReport& rep = Ingest(model, false);
    if (!rep.ok) { std::printf("INGEST_FAIL: %s\n", rep.error.c_str()); return 1; }
    const TensorRec* found = nullptr;
    for (const TensorRec& t : rep.tensors) {
        if (t.name == tensor) { found = &t; break; }
    }
    if (!found) { std::printf("tensor not found: %s\n", tensor.c_str()); return 1; }
    if (found->ggml_type != GGML_TYPE_Q5_0) {
        std::printf("tensor %s is not Q5_0 (type=%d)\n", tensor.c_str(), (int)found->ggml_type);
        return 1;
    }
    if (found->dims.size() < 2) { std::printf("tensor not 2-D\n"); return 1; }
    const size_t n_in = (size_t)found->dims[0];
    const size_t n_out = (size_t)found->dims[1];
    if (row >= n_out) { std::printf("row %zu out of range (n_out=%zu)\n", row, n_out); return 1; }
    const size_t row_bytes = (n_in / 32u) * 22u;
    const uint8_t* base = reinterpret_cast<const uint8_t*>(found->data) + row * row_bytes;

    std::printf("tensor=%s dims=[%zu,%zu] row=%zu row_bytes=%zu bytes=%zu\n",
                tensor.c_str(), n_in, n_out, row, row_bytes, found->bytes);
    std::printf("block0 raw:");
    for (int i = 0; i < 22; ++i) std::printf(" %02X", base[i]);
    std::printf("\n");

    // --- ggml's decoder (via the type table the runtime links) ---
    const ggml_type_traits* tr = ggml_get_type_traits(GGML_TYPE_Q5_0);
    std::vector<float> ref(n_in, 0.0f);
    tr->to_float(base, ref.data(), (int)n_in);

    // --- the shader's interpretation, replicated bit for bit ---
    std::vector<float> mine(n_in, 0.0f);
    for (size_t blk = 0; blk < n_in / 32u; ++blk) {
        const uint8_t* b = base + blk * 22u;
        uint16_t hb = rd16(b);
        const float dw = ggml_fp16_to_fp32((ggml_fp16_t)hb);
        const uint32_t qh = (uint32_t)b[2] | ((uint32_t)b[3] << 8) |
                            ((uint32_t)b[4] << 16) | ((uint32_t)b[5] << 24);
        for (size_t j = 0; j < 16u; ++j) {
            const uint32_t qsb = b[6 + j];
            const int h0 = (int)((qh >> (j + 0u)) & 1u);
            const int h1 = (int)((qh >> (j + 16u)) & 1u);
            const int w0 = (int)(qsb & 0x0Fu) | (h0 << 4);
            const int w1 = (int)(qsb >> 4) | (h1 << 4);
            mine[blk * 32u + j] = (float)(w0 - 16) * dw;
            mine[blk * 32u + j + 16u] = (float)(w1 - 16) * dw;
        }
    }

    size_t nbad = 0;
    double worst = 0.0;
    for (size_t i = 0; i < n_in; ++i) {
        const double d = std::fabs((double)ref[i] - (double)mine[i]);
        if (d > worst) worst = d;
        if (d != 0.0 && ++nbad <= 8)
            std::printf("  first mismatch at i=%zu: ggml=%.7f shader=%.7f\n", i, ref[i], mine[i]);
    }
    std::printf("mismatches=%zu worst_abs=%.6g  (elements=%zu)\n", nbad, worst, n_in);
    std::printf("ggml[0..7]:");
    for (int i = 0; i < 8; ++i) std::printf(" %.5f", ref[i]);
    std::printf("\nshader[0..7]:");
    for (int i = 0; i < 8; ++i) std::printf(" %.5f", mine[i]);
    std::printf("\n");
    return 0;
}
