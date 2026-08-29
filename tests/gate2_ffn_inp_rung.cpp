// GATE2_FFN_INP_0 — next ladder rung after Track B PRE_O/O_PROJ closed under expand(V)
// Authority dumps: BATCH2_ATTN_OUT_LOC (ids=[1,21521,9312] pos=0)
// Do not use invalidated llama ATTN_PRE_O dump as X for this rung.
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static bool loadF32(const char* path, size_t n, std::vector<float>& out) {
    FILE* f = nullptr;
#ifdef _MSC_VER
    if (fopen_s(&f, path, "rb") != 0 || !f) return false;
#else
    f = std::fopen(path, "rb");
    if (!f) return false;
#endif
    out.resize(n);
    const bool ok = std::fread(out.data(), sizeof(float), n, f) == n;
    std::fclose(f);
    return ok;
}

struct Cmp {
    double maxAbs = 0;
    int largest = -1;
    int firstBad = -1;
    const char* gate = "FAIL";
};

static Cmp cmp(const float* a, const float* b, size_t n,
               double passEps = 1e-6, double inspectEps = 1e-5) {
    Cmp r;
    for (size_t i = 0; i < n; ++i) {
        const double d = std::fabs((double)a[i] - (double)b[i]);
        if (d > r.maxAbs) {
            r.maxAbs = d;
            r.largest = (int)i;
        }
        if (r.firstBad < 0 && d > passEps) r.firstBad = (int)i;
    }
    if (r.maxAbs <= passEps) r.gate = "PASS";
    else if (r.maxAbs <= inspectEps) r.gate = "INSPECT";
    else r.gate = "FAIL";
    return r;
}

static void printCmp(const char* tag, const Cmp& r, size_t n) {
    std::printf("%s gate=%s n=%zu max_abs=%.6e first_bad=%d largest=%d\n",
                tag, r.gate, n, r.maxAbs, r.firstBad, r.largest);
}

int main(int argc, char** argv) {
    const char* dumpDir = argc > 1 ? argv[1]
        : R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_ATTN_OUT_LOC)";
    const std::string b = std::string(dumpDir) + "\\";
    const size_t H = 2048;

    std::printf("GATE2_FFN_INP_0\n");
    std::printf("canonical_ids=[1,21521,9312] pos=0\n");
    std::printf("PRE_O_AUTHORITY=GQA_expand(V)  (llama PRE_O dump INVALIDATED)\n");
    std::printf("dump_dir=%s\n\n", dumpDir);

    std::vector<float> dFfn, lFfn, dOut, lOut, dNorm, lNorm, recon(H);

    const bool okD =
        loadF32((b + "deep2_FFN_INP_0_pos0_layer0_full_n2048_seq010.bin").c_str(), H, dFfn) &&
        loadF32((b + "deep2_ATTN_OUT_0_pos0_layer0_full_n2048_seq009.bin").c_str(), H, dOut) &&
        loadF32((b + "deep2_ATTN_NORM_0_pos0_layer0_full_n2048_seq002.bin").c_str(), H, dNorm);
    // Residual input to attn is usually the block input (pre-norm), not ATTN_NORM.
    // FFN_INP = block_input + ATTN_OUT. Try POST residual sources if present.
    std::vector<float> dIn;
    const bool hasBlockIn =
        loadF32((b + "deep2_PROMPT_EMBED_pos0_layer0_full_n2048_seq001.bin").c_str(), H, dIn) ||
        loadF32((b + "deep2_embd_pos0_layer0_full_n2048_seq001.bin").c_str(), H, dIn);

    if (!okD) {
        std::fprintf(stderr, "FAIL: missing deep2 FFN_INP/ATTN_OUT dumps\n");
        return 1;
    }

    const bool okL =
        loadF32((b + "llama_FFN_INP_0_pos0_layer0_full_n2048_seq108.bin").c_str(), H, lFfn) &&
        loadF32((b + "llama_ATTN_OUT_0_pos0_layer0_full_n2048_seq105.bin").c_str(), H, lOut);

    // Deep2 self-consistency: FFN_INP should equal residual_in + ATTN_OUT.
    // Prefer PROMPT_EMBED as layer0 residual_in when available.
    if (hasBlockIn) {
        for (size_t i = 0; i < H; ++i) recon[i] = dIn[i] + dOut[i];
        std::printf("=== deep2 FFN_INP vs (EMBED + ATTN_OUT) ===\n");
        printCmp("deep2_FFN_INP_residual", cmp(dFfn.data(), recon.data(), H), H);
    } else {
        std::printf("NOTE: block input dump not found — skip residual self-check\n");
    }

    // Cross-side compare (may FAIL if llama path used invalid PRE_O → ATTN_OUT)
    if (okL) {
        std::printf("\n=== FFN_INP_0 deep2 vs llama ===\n");
        const Cmp c = cmp(dFfn.data(), lFfn.data(), H);
        printCmp("FFN_INP_0", c, H);

        std::printf("\n=== ATTN_OUT_0 deep2 vs llama (context) ===\n");
        printCmp("ATTN_OUT_0", cmp(dOut.data(), lOut.data(), H), H);

        std::printf("\n=== DISPOSITION ===\n");
        if (std::strcmp(c.gate, "PASS") == 0 || std::strcmp(c.gate, "INSPECT") == 0) {
            std::printf("FFN_INP_0 gate=%s — proceed to FFN_NORM / GATE / UP\n", c.gate);
        } else {
            std::printf("FFN_INP_0 gate=FAIL — likely inherits llama ATTN_OUT gap from "
                        "invalidated PRE_O dump.\n");
            std::printf("authority_action: re-dump llama with fixed kqv_out-0 cb "
                        "(LLAMA_PRE_O_DUMP_HYGIENE_001), OR compare Deep2 FFN_INP against "
                        "reconstructed residual using O(expand(V)) not native llama ATTN_OUT.\n");
        }
    } else {
        std::printf("WARN: llama FFN_INP/ATTN_OUT dumps missing\n");
    }

    std::printf("\nprobe_fix=F:/~dev/rawrxd/tools/parity_ref/llama_ref_parity_probe.cpp\n");
    std::printf("  - kqv_out-0 always on cb_eval want list\n");
    std::printf("  - ATTN_PRE_O_0 dumped from kqv_out flatten (2D/3D)\n");
    std::printf("  - attn_out src audit renamed ATTN_PRE_O_SRC1 (not authority)\n");
    return 0;
}
