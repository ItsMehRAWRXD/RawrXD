/*
 * BATCH2_V_PROJ_001 — isolate first genuine oracle FAIL at V_0.
 * Frozen input: ATTN_NORM_0 (exact Deep2↔llama).
 * Compare production Q4_K×Q8_K GEMV on blk.0.attn_{k,v} vs oracle dumps.
 */
#include "GGUFLoader.hpp"
#include "QuantKernelRegistry.hpp"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#include <direct.h>
#define MKDIR(p) _mkdir(p)
#else
#include <sys/stat.h>
#define MKDIR(p) mkdir(p, 0755)
#endif

using Deep2::GGUFLoader;
using Deep2::QuantKernelRegistry;
using Deep2::GGMLType;

static bool loadF32(const char* path, size_t n, std::vector<float>& out) {
    FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    out.resize(n);
    const bool ok = std::fread(out.data(), 4, n, f) == n;
    std::fclose(f);
    return ok;
}

static uint64_t fnv1a(const float* a, size_t n) {
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < n; ++i) {
        uint32_t bits = 0;
        std::memcpy(&bits, &a[i], 4);
        for (int b = 0; b < 4; ++b) {
            h ^= (bits >> (8 * b)) & 0xFFu;
            h *= 1099511628211ull;
        }
    }
    return h;
}

static double l2norm(const float* a, size_t n) {
    double ss = 0;
    for (size_t i = 0; i < n; ++i) ss += (double)a[i] * (double)a[i];
    return std::sqrt(ss);
}

static void cmp(const char* tag, const float* a, const float* b, size_t n, FILE* vf) {
    double maxAbs = 0, maxRel = 0, ss = 0;
    int first = -1, larg = -1, exact = 0;
    for (size_t i = 0; i < n; ++i) {
        const double da = std::fabs((double)a[i] - (double)b[i]);
        ss += da * da;
        if (da > maxAbs) { maxAbs = da; larg = (int)i; }
        const float den = std::max(std::fabs(a[i]), std::fabs(b[i]));
        const double r = den > 0.f ? da / (double)den : 0.0;
        if (r > maxRel) maxRel = r;
        if (da <= 1e-6) ++exact;
        else if (first < 0) first = (int)i;
    }
    const char* gate = maxAbs <= 1e-6 ? "PASS" : (maxAbs <= 1e-5 ? "INSPECT" : "FAIL");
    std::printf("%s gate=%s n=%zu exact=%d max_abs=%.6e max_rel=%.6e rms=%.6e first_bad=%d largest=%d "
                "fnvA=%016llx fnvB=%016llx L2A=%.6e L2B=%.6e\n",
                tag, gate, n, exact, maxAbs, maxRel, std::sqrt(ss / (double)n), first, larg,
                (unsigned long long)fnv1a(a, n), (unsigned long long)fnv1a(b, n),
                l2norm(a, n), l2norm(b, n));
    if (vf) {
        std::fprintf(vf,
            "%s\n  shape=%zu\n  FNV_A=%016llx\n  FNV_B=%016llx\n  L2_A=%.17g\n  L2_B=%.17g\n"
            "  max_abs_diff=%.17g\n  max_rel_diff=%.17g\n  first_bad_index=%d\n  PASS/FAIL=%s\n",
            tag, n, (unsigned long long)fnv1a(a, n), (unsigned long long)fnv1a(b, n),
            l2norm(a, n), l2norm(b, n), maxAbs, maxRel, first, gate);
    }
}

static void runGemv(const char* name, const Deep2::TensorInfo* t, const float* x,
                    std::vector<float>& y) {
    const size_t cols = t->dimensions.size() > 0 ? (size_t)t->dimensions[0] : 0;
    const size_t rows = t->dimensions.size() > 1 ? (size_t)t->dimensions[1] : 0;
    y.assign(rows, 0.f);
    auto& reg = QuantKernelRegistry::Instance();
    if (reg.GetRegisteredCount() == 0) reg.Initialize();
    auto kernel = reg.GetGEMV((int)t->type);
    std::printf("%s type=%d rows=%zu cols=%zu size=%llu data=%p kernel=%p\n",
                name, (int)t->type, rows, cols, (unsigned long long)t->size, t->data, (void*)kernel);
    if (!kernel) {
        std::fprintf(stderr, "NO_KERNEL for %s\n", name);
        return;
    }
    kernel((const uint8_t*)t->data, x, y.data(), rows, cols);
}

int main() {
    const char* modelPath =
        R"(F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf)";
    const char* oracle =
        R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_ORACLE_V2)";
    const char* outDir =
        R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_V_PROJ_001)";
    MKDIR(R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001)");
    MKDIR(outDir);

    Deep2::GGUFLoadOptions opt;
    opt.mmap = true;
    opt.loadTensors = true;
    opt.verbose = false;
    auto lr = GGUFLoader::Load(modelPath, opt);
    if (!lr.success) {
        std::fprintf(stderr, "GGUF_LOAD_FAIL: %s\n", lr.error);
        return 2;
    }

    const auto* tk = lr.GetTensor("blk.0.attn_k.weight");
    const auto* tv = lr.GetTensor("blk.0.attn_v.weight");
    if (!tk || !tv || !tk->data || !tv->data) {
        std::fprintf(stderr, "MISSING k/v tensors\n");
        return 2;
    }

    std::vector<float> attnNorm, deep2K, llamaK, deep2V, llamaV;
    if (!loadF32((std::string(oracle) + "\\deep2_ATTN_NORM_0_pos0_layer0_full_n2048_seq901.bin").c_str(), 2048, attnNorm) ||
        !loadF32((std::string(oracle) + "\\deep2_K_PRE_ROPE_0_pos0_layer0_full_n256_seq903.bin").c_str(), 256, deep2K) ||
        !loadF32((std::string(oracle) + "\\llama_K_PRE_ROPE_0_pos0_layer0_full_n256_seq051.bin").c_str(), 256, llamaK) ||
        !loadF32((std::string(oracle) + "\\deep2_V_0_pos0_layer0_full_n256_seq904.bin").c_str(), 256, deep2V) ||
        !loadF32((std::string(oracle) + "\\llama_V_0_pos0_layer0_full_n256_seq045.bin").c_str(), 256, llamaV)) {
        std::fprintf(stderr, "ORACLE_LOAD_FAIL\n");
        return 2;
    }

    FILE* vf = std::fopen((std::string(outDir) + "\\verdict.txt").c_str(), "w");
    if (vf) {
        std::fprintf(vf,
            "BATCH2_V_PROJ_001\n"
            "authority=CPU llama Q4_K x Q8_K mul_mat\n"
            "input=ATTN_NORM_0 frozen fnv=%016llx L2=%.17g\n"
            "stop_rule=first genuine full-shape FAIL was V_0 on ORACLE_V2 ladder\n\n",
            (unsigned long long)fnv1a(attnNorm.data(), attnNorm.size()),
            l2norm(attnNorm.data(), attnNorm.size()));
    }

    std::vector<float> gemvK, gemvV;
    runGemv("blk.0.attn_k.weight", tk, attnNorm.data(), gemvK);
    runGemv("blk.0.attn_v.weight", tv, attnNorm.data(), gemvV);

    cmp("K_gemv_vs_deep2", gemvK.data(), deep2K.data(), 256, vf);
    cmp("K_gemv_vs_llama", gemvK.data(), llamaK.data(), 256, vf);
    cmp("K_deep2_vs_llama", deep2K.data(), llamaK.data(), 256, vf);
    cmp("V_gemv_vs_deep2", gemvV.data(), deep2V.data(), 256, vf);
    cmp("V_gemv_vs_llama", gemvV.data(), llamaV.data(), 256, vf);
    cmp("V_deep2_vs_llama", deep2V.data(), llamaV.data(), 256, vf);

    // Raw weight identity: first 64 bytes of K vs V must differ
    const uint8_t* pk = (const uint8_t*)tk->data;
    const uint8_t* pv = (const uint8_t*)tv->data;
    int same = 0;
    for (int i = 0; i < 64; ++i) if (pk[i] == pv[i]) ++same;
    std::printf("weight_hdr K!=V bytes_differ_in_first64=%d (expect ~64)\n", 64 - same);
    if (vf) {
        std::fprintf(vf, "\nweight_ptr_k=%p weight_ptr_v=%p first64_equal_bytes=%d\n",
                     (void*)pk, (void*)pv, same);
        std::fprintf(vf,
            "\nINTERPRETATION\n"
            "If V_gemv MATCHES deep2 and DIFFS llama => Deep2 LinearW OK; llama V_0 dump not raw wv@x OR llama used different weights.\n"
            "If V_gemv MATCHES llama and DIFFS deep2 => Deep2 dump/path diverged from QuantKernelRegistry Q8_K GEMV.\n"
            "If V_gemv DIFFS both => weight dims/type/load bug in this harness.\n");
        std::fclose(vf);
    }
    return 0;
}
