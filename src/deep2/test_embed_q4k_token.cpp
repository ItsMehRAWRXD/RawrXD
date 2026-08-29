/*
 * test_embed_q4k_token.cpp — EMBED-Q4K-001
 * Freeze token_embd.weight rows (esp. token 35) vs ggml Q4_K dequant.
 *
 * Usage: test_embed_q4k_token.exe [model.gguf] [token_id=35] [out_dir]
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
#define MKDIR(p) mkdir((p), 0755)
#endif

namespace {

struct BlockQ4K {
    uint16_t d;
    uint16_t dmin;
    uint8_t scales[12];
    uint8_t qs[128];
};
static_assert(sizeof(BlockQ4K) == 144, "block_q4_K");

static float fp16ToF32(uint16_t h) {
    uint32_t sign = (h >> 15) & 0x1u;
    uint32_t exp = (h >> 10) & 0x1Fu;
    uint32_t mant = h & 0x3FFu;
    uint32_t f;
    if (exp == 0) {
        if (mant == 0) f = sign << 31;
        else {
            int e = -1;
            do { e++; mant <<= 1; } while (!(mant & 0x400u));
            mant &= 0x3FFu;
            f = (sign << 31) | ((uint32_t)(127 - 15 - e) << 23) | (mant << 13);
        }
    } else if (exp == 31) {
        f = (sign << 31) | (0xFFu << 23) | (mant << 13);
    } else {
        f = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13);
    }
    float r;
    std::memcpy(&r, &f, 4);
    return r;
}

static inline void ggmlGetScaleMinK4(int j, const uint8_t* q, uint8_t* d, uint8_t* m) {
    if (j < 4) {
        *d = q[j] & 63;
        *m = q[j + 4] & 63;
    } else {
        *d = (q[j + 4] & 0xF) | ((q[j - 4] >> 6) << 4);
        *m = (q[j + 4] >> 4) | ((q[j - 0] >> 6) << 4);
    }
}

static void ggmlDequantRow(const BlockQ4K* blocks, size_t numBlocks, float* y, size_t n) {
    for (size_t b = 0; b < numBlocks; ++b) {
        const BlockQ4K& blk = blocks[b];
        const uint8_t* q = blk.qs;
        const float d = fp16ToF32(blk.d);
        const float minv = fp16ToF32(blk.dmin);
        int is = 0;
        uint8_t sc, m;
        float* yp = y + b * 256;
        for (int j = 0; j < 256; j += 64) {
            ggmlGetScaleMinK4(is + 0, blk.scales, &sc, &m);
            const float d1 = d * sc, m1 = minv * m;
            ggmlGetScaleMinK4(is + 1, blk.scales, &sc, &m);
            const float d2 = d * sc, m2 = minv * m;
            for (int l = 0; l < 32; ++l) {
                size_t i0 = b * 256 + (size_t)is * 32 + (size_t)l;
                size_t i1 = i0 + 32;
                if (i0 < n) yp[(size_t)is * 32 + (size_t)l] = d1 * (float)(q[l] & 0xF) - m1;
                if (i1 < n) yp[(size_t)is * 32 + 32 + (size_t)l] = d2 * (float)(q[l] >> 4) - m2;
            }
            q += 32;
            is += 2;
        }
    }
}

static double l2norm(const float* a, size_t n) {
    double s = 0;
    for (size_t i = 0; i < n; ++i) s += (double)a[i] * (double)a[i];
    return std::sqrt(s);
}

static size_t nonzeroBytes(const uint8_t* p, size_t n) {
    size_t c = 0;
    for (size_t i = 0; i < n; ++i) if (p[i]) ++c;
    return c;
}

static void hex32(FILE* f, const uint8_t* p) {
    for (int i = 0; i < 32; ++i) std::fprintf(f, "%02X%s", p[i], i == 31 ? "" : " ");
}

} // namespace

int main(int argc, char** argv) {
    const char* modelPath =
        R"(F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf)";
    int focusTok = 35;
    const char* outDir =
        R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\EMBED_Q4K_001)";
    if (argc >= 2) modelPath = argv[1];
    if (argc >= 3) focusTok = std::atoi(argv[2]);
    if (argc >= 4) outDir = argv[3];
    MKDIR(R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001)");
    MKDIR(outDir);

    std::printf("EMBED-Q4K-001\nmodel=%s\nfocus_token=%d\nout=%s\n", modelPath, focusTok, outDir);

    Deep2::GGUFLoadOptions opt;
    opt.mmap = true;
    opt.loadTensors = true;
    Deep2::GGUFLoadResult lr = Deep2::GGUFLoader::Load(modelPath, opt);
    if (!lr.success) {
        std::fprintf(stderr, "GGUF_LOAD_FAIL: %s\n", lr.error);
        return 2;
    }

    const Deep2::TensorInfo* te = lr.GetTensor("token_embd.weight");
    if (!te || !te->data) {
        std::fprintf(stderr, "MISSING token_embd.weight\n");
        return 2;
    }

    const size_t hidden = te->dimensions.size() > 0 ? (size_t)te->dimensions[0] : 0;
    const size_t vocab = te->dimensions.size() > 1 ? (size_t)te->dimensions[1] : 0;
    const size_t numBlocks = hidden / 256;
    const size_t rowBytes = numBlocks * sizeof(BlockQ4K);

    std::printf("token_embd type=%d dims=[%zu,%zu] sizeBytes=%zu rowBytes=%zu\n",
                (int)te->type, hidden, vocab, te->size, rowBytes);

    FILE* meta = std::fopen((std::string(outDir) + "\\tensor_meta.txt").c_str(), "w");
    if (meta) {
        std::fprintf(meta,
            "name=token_embd.weight\ntype=%d\nhidden=%zu\nvocab=%zu\n"
            "sizeBytes=%zu\nrowBytes=%zu\nblocks_per_row=%zu\n"
            "focus_token=%d\n",
            (int)te->type, hidden, vocab, te->size, rowBytes, numBlocks, focusTok);
        std::fclose(meta);
    }

    if ((int)te->type != (int)Deep2::GGMLType::GGML_TYPE_Q4_K) {
        std::fprintf(stderr, "EXPECTED Q4_K type=12 got %d\n", (int)te->type);
        return 3;
    }

    Deep2::QuantKernelRegistry::Instance().Initialize();
    auto prodDq = Deep2::QuantKernelRegistry::Instance().GetDequant((int)Deep2::GGMLType::GGML_TYPE_Q4_K);

    const int probes[] = {1, focusTok, 0, 2, 29966};
    FILE* vf = std::fopen((std::string(outDir) + "\\verdict.txt").c_str(), "w");
    FILE* det = std::fopen((std::string(outDir) + "\\row_probe.txt").c_str(), "w");

    bool focusRawZero = false, focusScalarZero = false, focusProdZero = false;
    bool focusScalarOk = false, focusProdOk = false;

    for (int tok : probes) {
        if (tok < 0 || (size_t)tok >= vocab) continue;
        const uint8_t* row = (const uint8_t*)te->data + (size_t)tok * rowBytes;
        const size_t nz = nonzeroBytes(row, rowBytes);
        const BlockQ4K* blocks = reinterpret_cast<const BlockQ4K*>(row);

        std::vector<float> ggml(hidden), prod(hidden, 0.f);
        ggmlDequantRow(blocks, numBlocks, ggml.data(), hidden);
        if (prodDq) prodDq(row, prod.data(), hidden);

        const double l2g = l2norm(ggml.data(), hidden);
        const double l2p = l2norm(prod.data(), hidden);
        double maxAbs = 0;
        for (size_t i = 0; i < hidden; ++i) {
            double d = std::fabs((double)ggml[i] - (double)prod[i]);
            if (d > maxAbs) maxAbs = d;
        }

        std::printf("token=%d raw_nz=%zu/%zu d0=0x%04x dmin0=0x%04x ggml_l2=%.9e prod_l2=%.9e max_abs=%.9e\n",
                    tok, nz, rowBytes, blocks[0].d, blocks[0].dmin, l2g, l2p, maxAbs);

        if (det) {
            std::fprintf(det, "token=%d\nraw_nz=%zu/%zu\nfirst32=", tok, nz, rowBytes);
            hex32(det, row);
            std::fprintf(det, "\nblock0 d=0x%04x dmin=0x%04x\n", blocks[0].d, blocks[0].dmin);
            std::fprintf(det, "ggml_l2=%.17g prod_l2=%.17g max_abs=%.9e\n\n", l2g, l2p, maxAbs);
        }

        if (tok == focusTok) {
            focusRawZero = (nz == 0);
            focusScalarZero = !(l2g > 0.0 && std::isfinite(l2g));
            focusProdZero = !(l2p > 0.0 && std::isfinite(l2p));
            focusScalarOk = !focusScalarZero;
            focusProdOk = !focusProdZero && maxAbs == 0.0;
            FILE* rawf = std::fopen((std::string(outDir) + "\\token35_row_raw.bin").c_str(), "wb");
            if (rawf) { std::fwrite(row, 1, rowBytes, rawf); std::fclose(rawf); }
            FILE* gf = std::fopen((std::string(outDir) + "\\token35_ggml_f32.bin").c_str(), "wb");
            if (gf) { std::fwrite(ggml.data(), 4, hidden, gf); std::fclose(gf); }
            FILE* pf = std::fopen((std::string(outDir) + "\\token35_prod_f32.bin").c_str(), "wb");
            if (pf) { std::fwrite(prod.data(), 4, hidden, pf); std::fclose(pf); }
        }
    }

    const char* classif = "UNKNOWN";
    if (focusRawZero) classif = "RAW_ROW_BYTES_ZERO => tensor offset / row addressing";
    else if (focusScalarZero) classif = "RAW_OK_SCALAR_DEQUANT_ZERO => Q4_K dequant impl";
    else if (focusProdZero) classif = "SCALAR_OK_PROD_ZERO => embedding dispatch / GetDequant";
    else if (!focusProdOk) classif = "PROD_DIFFERS_FROM_GGML => numerical Q4_K parity";
    else classif = "ROW_OK_OFFLINE => investigate caller sequence / runtime residency";

    if (vf) {
        std::fprintf(vf,
            "EMBED-Q4K-001\n"
            "focus_token=%d\n"
            "raw_row_bytes=%s\n"
            "scalar_ggml_dequant=%s\n"
            "production_GetDequant=%s\n"
            "classification=%s\n"
            "AGENT-E2E-002b=BLOCKED\n"
            "BLOCKER_CLASS=DEEP2_INFERENCE\n"
            "FIRST_RUNTIME_FAILURE=TOKEN_EMBED_Q4K\n"
            "note=BOS token=1 previously matched; row-dependent defects possible\n",
            focusTok,
            focusRawZero ? "ZERO" : "NONZERO",
            focusScalarOk ? "NONZERO" : "ZERO",
            focusProdZero ? "ZERO" : (focusProdOk ? "MATCH_GGML" : "DIFF_OR_NONZERO"),
            classif);
        std::fclose(vf);
    }
    if (det) std::fclose(det);

    std::printf("classification=%s\n", classif);
    // Exit 0 if offline row is healthy (points at runtime/caller); 1 if row path broken.
    return focusScalarOk && !focusRawZero ? 0 : 1;
}
