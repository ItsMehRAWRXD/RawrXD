/*
 * Ingest existing deep2_*.bin dumps into DUMP_MANIFEST.jsonl (collision-proof naming optional rename).
 * Usage: ingest_deep2_dumps.exe <src_dir_with_old_deep2_bins> <oracle_v2_dir>
 */
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <windows.h>

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

static bool ingestOne(const char* srcPath, const char* stage, int pos, int nelem,
                      const char* dstDir, int seq) {
    FILE* f = std::fopen(srcPath, "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (sz != nelem * 4) { std::fclose(f); std::printf("SIZE_SKIP %s got=%ld expect=%d\n", srcPath, sz, nelem*4); return false; }
    std::vector<float> v((size_t)nelem);
    std::fread(v.data(), 1, (size_t)sz, f);
    std::fclose(f);
    uint64_t fnv = fnv1a(v.data(), v.size());
    double l2 = l2norm(v.data(), v.size());

    char stem[1024];
    std::snprintf(stem, sizeof(stem), "%s\\deep2_%s_pos%d_layer0_full_n%d_seq%03d",
                  dstDir, stage, pos, nelem, seq);
    char binPath[1100], manPath[1100];
    std::snprintf(binPath, sizeof(binPath), "%s.bin", stem);
    std::snprintf(manPath, sizeof(manPath), "%s.manifest.txt", stem);

    FILE* exist = std::fopen(binPath, "rb");
    if (exist) { std::fclose(exist); std::printf("EXISTS_SKIP %s\n", binPath); return false; }

    FILE* out = std::fopen(binPath, "wb");
    if (!out) return false;
    std::fwrite(v.data(), 1, (size_t)sz, out);
    std::fclose(out);

    FILE* mf = std::fopen(manPath, "w");
    if (mf) {
        std::fprintf(mf,
            "side=deep2\nstage=%s\npos=%d\nlayer=0\nhead=-1\nhead_tag=full\n"
            "dtype=f32\nnelem=%d\nnbytes=%ld\nfnv=%016llx\nl2=%.17g\nseq=%d\npath=%s\n"
            "source=%s\n",
            stage, pos, nelem, sz, (unsigned long long)fnv, l2, seq, binPath, srcPath);
        std::fclose(mf);
    }
    char idxPath[1024];
    std::snprintf(idxPath, sizeof(idxPath), "%s\\DUMP_MANIFEST.jsonl", dstDir);
    FILE* idx = std::fopen(idxPath, "a");
    if (idx) {
        std::fprintf(idx,
            "{\"side\":\"deep2\",\"stage\":\"%s\",\"pos\":%d,\"layer\":0,\"head\":-1,"
            "\"nelem\":%d,\"nbytes\":%ld,\"fnv\":\"%016llx\",\"l2\":%.17g,\"seq\":%d,\"bin\":\"%s\"}\n",
            stage, pos, nelem, sz, (unsigned long long)fnv, l2, seq, binPath);
        std::fclose(idx);
    }
    std::printf("INGEST %s fnv=%016llx n=%d\n", stage, (unsigned long long)fnv, nelem);
    return true;
}

int main(int argc, char** argv) {
    const char* src = argc > 1 ? argv[1]
        : R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_Q_ELEMDIFF)";
    const char* dst = argc > 2 ? argv[2]
        : R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_ORACLE_V2)";

    struct Item { const char* stage; int n; };
    Item items[] = {
        {"PROMPT_EMBED", 2048},
        {"ATTN_NORM_0", 2048},
        {"Q_PRE_ROPE_0", 2048},
        {"K_PRE_ROPE_0", 256},
        {"V_0", 256},
        {"Q_POST_ROPE_0", 2048},
        {"K_POST_ROPE_0", 256},
        {"ATTN_OUT_0", 2048},
        {"FFN_INP_0", 2048},
        {"FFN_NORM_0", 2048},
        {"FFN_DOWN_0", 2048},
        {"POST_FFN_0", 2048},
        {"LAYER_OUT_0", 2048},
        {"LAYER_OUT_1", 2048},
        {"LAYER_OUT_2", 2048},
        {"LAYER_OUT_21", 2048},
        {"PROMPT_FINAL_NORM", 2048},
    };
    int seq = 900; // keep deep2 seq high / distinct from llama seq
    for (const auto& it : items) {
        char path[1024];
        std::snprintf(path, sizeof(path), "%s\\deep2_%s_pos0.bin", src, it.stage);
        ingestOne(path, it.stage, 0, it.n, dst, seq++);
    }
    return 0;
}
