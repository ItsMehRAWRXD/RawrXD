// ============================================================================
// deep2_legacy_quant_probe  --  RAWRXD_DEEP2_LEGACY_QUANT_GPU_001
// ============================================================================
// Enumerates every non-k-quant quantised tensor in a GGUF and reports the
// exact geometry a GPU dot kernel would need: row bytes, n_out, and whether
// n_in divides the 32-value legacy block size and the 256-value Q8 activation
// super-block. This is the geometry evidence behind routing legacy types
// (Q5_0/Q8_0/Q4_0/Q4_1/Q5_1) through the GPU quant-dot kernel instead of the
// CPU row-at-a-time dequantiser.
//
// Usage:
//   deep2_legacy_quant_probe.exe --model <gguf>
// ============================================================================
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "universal_gguf.hpp"

using namespace RawrXD::Deep2::Universal;

static const char* TypeName(uint32_t t)
{
    switch (t) {
    case 0: return "F32";
    case 1: return "F16";
    case 2: return "Q4_0";
    case 3: return "Q4_1";
    case 6: return "Q5_0";
    case 7: return "Q5_1";
    case 8: return "Q8_0";
    case 10: return "Q2_K";
    case 11: return "Q3_K";
    case 12: return "Q4_K";
    case 13: return "Q5_K";
    case 14: return "Q6_K";
    case 15: return "Q8_K";
    default: return "?";
    }
}

// ggml type_size / blck_size for the legacy quant types the OpLinear CPU path
// handles today (mirrors ggml_get_type_traits; kept local so this probe links
// without the full ggml table).
static bool LegacyGeometry(uint32_t t, size_t& blck, size_t& ts)
{
    switch (t) {
    case 2: blck = 32; ts = 18; return true;  // Q4_0
    case 3: blck = 32; ts = 20; return true;  // Q4_1
    case 6: blck = 32; ts = 22; return true;  // Q5_0
    case 7: blck = 32; ts = 24; return true;  // Q5_1
    case 8: blck = 32; ts = 34; return true;  // Q8_0
    default: return false;
    }
}

int main(int argc, char* argv[])
{
    std::string model;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--model" && i + 1 < argc)
            model = argv[++i];
    }
    if (model.empty()) {
        std::printf("usage: deep2_legacy_quant_probe.exe --model <gguf>\n");
        return 1;
    }
    const IngestReport& rep = Ingest(model, false);
    if (!rep.ok) {
        std::printf("MODEL=%s\nGGUF_PARSE_OK=FAIL\nINGEST_ERROR=%s\n", model.c_str(), rep.error.c_str());
        return 1;
    }
    // Full inventory first (the earlier version reported a bare zero, which
    // cannot distinguish "no quantised tensors" from "unsupported type" or
    // "rejected geometry"). Every ggml type in the file is counted, then every
    // quantised tensor is classified by where it executes.
    std::printf("MODEL=%s\n", model.c_str());
    std::printf("GGUF_PARSE_OK=PASS\n");
    std::printf("ARCHITECTURE=%s\n", rep.spec.architecture.c_str());
    std::printf("TENSOR_COUNT=%zu\n", rep.tensors.size());
    std::printf("QUANT_TYPE_HISTOGRAM=");
    bool first = true;
    for (const auto& kv : rep.type_histogram) {
        std::printf("%s%s x%zu", first ? "" : " ", TypeName(kv.first), kv.second);
        first = false;
    }
    std::printf("\n");

    size_t quantized = 0, gpu_kernels = 0, legacy = 0, usable_matmul = 0, rejected = 0;
    std::string first_reason;
    for (const TensorRec& t : rep.tensors) {
        const ggml_type_traits* tr = ggml_get_type_traits(t.ggml_type);
        const bool is_quant = tr && tr->is_quantized;
        if (is_quant) {
            ++quantized;
            // GPU kernel coverage: Q4_K/Q6_K (kinds 0/1) and Q5_0/Q8_0
            // (legacy kinds 2/3) all have quant-dot shaders.
            const bool has_gpu = (t.ggml_type == GGML_TYPE_Q4_K || t.ggml_type == GGML_TYPE_Q6_K ||
                                  t.ggml_type == GGML_TYPE_Q5_0 || t.ggml_type == GGML_TYPE_Q8_0);
            if (has_gpu)
                ++gpu_kernels;
        }
        size_t blck = 0, ts = 0;
        if (!LegacyGeometry(t.ggml_type, blck, ts))
            continue;
        ++legacy;
        if (t.dims.size() < 2) {
            ++rejected;
            if (first_reason.empty()) first_reason = t.name + ": 1-D tensor, not a projection";
            continue;
        }
        const size_t n_in = (size_t)t.dims[0];
        const size_t n_out = (size_t)t.dims[1];
        if (n_in % blck != 0) {
            ++rejected;
            if (first_reason.empty()) first_reason = t.name + ": n_in not a multiple of the block size";
            continue;
        }
        const size_t row_bytes = (n_in / blck) * ts;
        const size_t need = row_bytes * n_out;
        if (t.bytes < need) {
            ++rejected;
            if (first_reason.empty()) first_reason = t.name + ": byte span short of row_bytes * n_out";
            continue;
        }
        ++usable_matmul;
    }
    std::printf("QUANTIZED_TENSORS=%zu\n", quantized);
    std::printf("SUPPORTED_QUANT_TENSORS=%zu\n", gpu_kernels);
    std::printf("LEGACY_QUANT_TENSORS=%zu\n", legacy);
    std::printf("USABLE_MATMUL_SHAPES=%zu\n", usable_matmul);
    std::printf("REJECTED_SHAPES=%zu\n", rejected);
    std::printf("FIRST_REJECTION_REASON=%s\n", first_reason.empty() ? "<none>" : first_reason.c_str());

    // Per-tensor detail for the legacy quant types (Q4_0/Q4_1/Q5_0/Q5_1/Q8_0)
    // and for F16/F32 matmul tensors: the latter are the remaining CPU-path
    // population on models like qwen3 (36 F16 tensors).
    for (const TensorRec& t : rep.tensors) {
        size_t blck = 0, ts = 0;
        const bool isLegacyQuant = LegacyGeometry(t.ggml_type, blck, ts);
        if (!isLegacyQuant && t.ggml_type != GGML_TYPE_F16 && t.ggml_type != GGML_TYPE_F32)
            continue;
        if (!isLegacyQuant) {
            if (t.dims.size() < 2)
                continue;
            std::printf("  %-44s %-5s dims=[%zu,%zu] bytes=%zu%s\n", t.name.c_str(), TypeName(t.gguf_type),
                        (size_t)t.dims[0], (size_t)t.dims[1], t.bytes,
                        (t.ggml_type == GGML_TYPE_F16 ? "  (F16 matmul: CPU path today)" : ""));
            continue;
        }
        if (t.dims.size() < 2) {
            std::printf("  %-44s %-5s 1-D\n", t.name.c_str(), TypeName(t.gguf_type));
            continue;
        }
        const size_t n_in = (size_t)t.dims[0];
        const size_t n_out = (size_t)t.dims[1];
        const size_t row_bytes = (n_in / blck) * ts;
        const size_t need = row_bytes * n_out;
        const bool tail = (n_in % 256) != 0;
        std::printf("  %-44s %-5s dims=[%zu,%zu] row_bytes=%-8zu need=%-12zu bytes=%-12zu %s%s%s\n",
                    t.name.c_str(), TypeName(t.gguf_type), n_in, n_out, row_bytes, need,
                    t.bytes,
                    (t.bytes >= need) ? "OK" : "SHORT",
                    (n_in % blck != 0) ? " NIN%32!=0" : "",
                    tail ? "  (Q8 activation has a partial tail)" : "");
    }
    return 0;
}
