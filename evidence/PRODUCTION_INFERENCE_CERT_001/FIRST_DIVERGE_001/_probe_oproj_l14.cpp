/* Offline: host Q4_K GEMV blk.14.attn_output vs PRE_O/OUT dumps.
 * PROMOTE=0 — probe only. */
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <cmath>
#include "QuantKernelRegistry.hpp"

static bool read_f32(const char* path, std::vector<float>& out) {
    FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (n <= 0 || (n % 4) != 0) {
        std::fclose(f);
        return false;
    }
    out.resize(static_cast<size_t>(n) / 4);
    if (std::fread(out.data(), 1, static_cast<size_t>(n), f) != (size_t)n) {
        std::fclose(f);
        return false;
    }
    std::fclose(f);
    return true;
}

static bool read_gguf_q4k(const char* path, const char* name,
                          std::vector<uint8_t>& data, uint32_t& rows,
                          uint32_t& cols) {
    FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    char magic[4];
    if (std::fread(magic, 1, 4, f) != 4 || std::memcmp(magic, "GGUF", 4)) {
        std::fclose(f);
        return false;
    }
    uint32_t ver = 0;
    std::fread(&ver, 4, 1, f);
    uint64_t n_tensors = 0, n_kv = 0;
    std::fread(&n_tensors, 8, 1, f);
    std::fread(&n_kv, 8, 1, f);
    auto skip_val = [&](uint32_t t) {
        if (t == 8) {
            uint64_t n = 0;
            std::fread(&n, 8, 1, f);
            std::fseek(f, (long)n, SEEK_CUR);
        } else if (t == 9) {
            uint32_t at = 0;
            uint64_t n = 0;
            std::fread(&at, 4, 1, f);
            std::fread(&n, 8, 1, f);
            if (at == 8) {
                for (uint64_t i = 0; i < n; i++) {
                    uint64_t sl = 0;
                    std::fread(&sl, 8, 1, f);
                    std::fseek(f, (long)sl, SEEK_CUR);
                }
            } else {
                static int sz[] = {1, 1, 2, 2, 4, 4, 4, 8, 0, 0, 1, 1, 8};
                std::fseek(f, (long)(sz[at] * n), SEEK_CUR);
            }
        } else {
            static int sz[] = {1, 1, 2, 2, 4, 4, 4, 8, 0, 0, 1, 1, 8};
            std::fseek(f, sz[t], SEEK_CUR);
        }
    };
    for (uint64_t i = 0; i < n_kv; i++) {
        uint64_t klen = 0;
        std::fread(&klen, 8, 1, f);
        std::fseek(f, (long)klen, SEEK_CUR);
        uint32_t t = 0;
        std::fread(&t, 4, 1, f);
        skip_val(t);
    }
    struct Info {
        std::string nm;
        uint64_t dims[2];
        uint32_t typ;
        uint64_t off;
        int nd;
    };
    std::vector<Info> infos;
    for (uint64_t i = 0; i < n_tensors; i++) {
        uint64_t nlen = 0;
        std::fread(&nlen, 8, 1, f);
        std::string nm(nlen, '\0');
        std::fread(nm.data(), 1, (size_t)nlen, f);
        uint32_t nd = 0;
        std::fread(&nd, 4, 1, f);
        Info info;
        info.nm = nm;
        info.nd = (int)nd;
        for (uint32_t d = 0; d < nd; d++) {
            uint64_t v = 0;
            std::fread(&v, 8, 1, f);
            if (d < 2) info.dims[d] = v;
        }
        std::fread(&info.typ, 4, 1, f);
        std::fread(&info.off, 8, 1, f);
        infos.push_back(info);
    }
    long pos = std::ftell(f);
    pos = (pos + 31) & ~31L;
    long base = pos;
    for (auto& info : infos) {
        if (info.nm != name) continue;
        if (info.typ != 12) {
            std::fclose(f);
            return false;
        }
        cols = (uint32_t)info.dims[0];
        rows = (uint32_t)info.dims[1];
        size_t bytes = (size_t)rows * ((cols + 255u) / 256u) * 144u;
        data.resize(bytes);
        std::fseek(f, base + (long)info.off, SEEK_SET);
        if (std::fread(data.data(), 1, bytes, f) != bytes) {
            std::fclose(f);
            return false;
        }
        std::fclose(f);
        return true;
    }
    std::fclose(f);
    return false;
}

static float max_abs(const std::vector<float>& a, const std::vector<float>& b,
                     int* peak) {
    float mx = 0.f;
    int pi = -1;
    size_t n = a.size() < b.size() ? a.size() : b.size();
    for (size_t i = 0; i < n; i++) {
        float d = std::fabs(a[i] - b[i]);
        if (d > mx) {
            mx = d;
            pi = (int)i;
        }
    }
    if (peak) *peak = pi;
    return mx;
}

int main() {
    const char* gguf = R"(G:\~dev\rawrxd\models\tinyllama.gguf)";
    const char* stage =
        R"(G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001\_cmp_attn_out14_stage)";
    const char* gref =
        R"(G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001\stage_dump_gpu_fix)";
    Deep2::QuantKernelRegistry::Instance().Initialize();
    auto gemv = Deep2::QuantKernelRegistry::Instance().GetGEMV(12);
    if (!gemv) {
        std::printf("NO_GEMV\n");
        return 2;
    }
    std::vector<uint8_t> w;
    uint32_t rows = 0, cols = 0;
    if (!read_gguf_q4k(gguf, "blk.14.attn_output.weight", w, rows, cols)) {
        std::printf("WO_LOAD_FAIL\n");
        return 3;
    }
    std::printf("wo rows=%u cols=%u bytes=%zu\n", rows, cols, w.size());
    std::vector<float> pre_d, out_d, out_l, pre_l;
    char p[512];
    std::snprintf(p, sizeof(p),
                  "%s\\deep2_ATTN_PRE_O_14_pos0_layer0_full_n2048_seq264.bin",
                  stage);
    if (!read_f32(p, pre_d)) {
        std::printf("PRE_D_FAIL\n");
        return 4;
    }
    std::snprintf(p, sizeof(p),
                  "%s\\deep2_ATTN_OUT_14_pos0_layer0_full_n2048_seq265.bin",
                  stage);
    if (!read_f32(p, out_d)) {
        std::printf("OUT_D_FAIL\n");
        return 5;
    }
    std::snprintf(p, sizeof(p), "%s\\llama_ATTN_OUT_14.bin", stage);
    if (!read_f32(p, out_l)) {
        std::printf("OUT_L_FAIL\n");
        return 6;
    }
    std::snprintf(p, sizeof(p),
                  "%s\\llama_ATTN_PRE_O_14_pos0_layer0_full_n2048_seq1955.bin",
                  gref);
    if (!read_f32(p, pre_l)) {
        std::printf("PRE_L_FAIL\n");
        return 7;
    }
    int peak = -1;
    std::printf("PRE_O deep vs llama maxAbs=%.6e peak=%d\n",
                max_abs(pre_d, pre_l, &peak), peak);
    std::printf("OUT deep vs llama maxAbs=%.6e peak=%d\n",
                max_abs(out_d, out_l, &peak), peak);

    std::vector<float> pred_d(rows), pred_l(rows), dpre(cols), dout(rows),
        amp(rows);
    gemv(w.data(), pre_d.data(), pred_d.data(), rows, cols);
    gemv(w.data(), pre_l.data(), pred_l.data(), rows, cols);
    std::printf("host(pre_d) vs deep2_OUT maxAbs=%.6e peak=%d\n",
                max_abs(pred_d, out_d, &peak), peak);
    std::printf("host(pre_d) vs llama_OUT maxAbs=%.6e peak=%d\n",
                max_abs(pred_d, out_l, &peak), peak);
    std::printf("host(pre_l) vs llama_OUT maxAbs=%.6e peak=%d\n",
                max_abs(pred_l, out_l, &peak), peak);
    std::printf("host(pre_l) vs deep2_OUT maxAbs=%.6e peak=%d\n",
                max_abs(pred_l, out_d, &peak), peak);
    for (uint32_t i = 0; i < cols; i++) dpre[i] = pre_d[i] - pre_l[i];
    for (uint32_t i = 0; i < rows; i++) dout[i] = out_d[i] - out_l[i];
    gemv(w.data(), dpre.data(), amp.data(), rows, cols);
    float ainf = 0.f, oinf = 0.f;
    for (uint32_t i = 0; i < rows; i++) {
        ainf = std::fmax(ainf, std::fabs(amp[i]));
        oinf = std::fmax(oinf, std::fabs(dout[i]));
    }
    std::printf("||W*dPRE||_inf=%.6e ||dOUT||_inf=%.6e WdPRE_vs_dOUT maxAbs=%.6e\n",
                ainf, oinf, max_abs(amp, dout, &peak));
    const float host_vs_deep = max_abs(pred_d, out_d, &peak);
    if (host_vs_deep < 1e-4f) {
        std::printf("VERDICT=RUNTIME_O_PROJ_MATCHES_HOST_Q4K\n");
        std::printf("ROOT=O_PROJ_AMPLIFY_OF_PRE_O_RESIDUAL\n");
    } else {
        std::printf("VERDICT=RUNTIME_O_PROJ_NE_HOST_Q4K maxAbs=%.6e\n",
                    host_vs_deep);
        std::printf("ROOT=O_PROJ_SPV_OR_WEIGHT_PATH_MISMATCH\n");
    }
    std::printf("PROMOTE=0 TIP_CLIMB=HOLD\n");
    return 0;
}
