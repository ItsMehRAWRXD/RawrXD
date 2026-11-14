/* Offline: host Q4_K GEMV blk.2.ffn_down vs ACT/DOWN dumps.
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
            std::printf("TYPE=%u want Q4_K=12\n", info.typ);
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
    const char* dump =
        R"(G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001\stage_dump_ffn_down_2_q6spv)";
    const char* gref =
        R"(G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001\FIRST_DIVERGE_001\stage_dump_gpu_ref)";
    Deep2::QuantKernelRegistry::Instance().Initialize();
    auto gemv = Deep2::QuantKernelRegistry::Instance().GetGEMV(12);
    if (!gemv) {
        std::printf("NO_GEMV\n");
        return 2;
    }
    std::vector<uint8_t> w;
    uint32_t rows = 0, cols = 0;
    if (!read_gguf_q4k(gguf, "blk.2.ffn_down.weight", w, rows, cols)) {
        std::printf("W_LOAD_FAIL\n");
        return 3;
    }
    std::printf("ffn_down_2 Q4_K rows=%u cols=%u bytes=%zu\n", rows, cols,
                w.size());
    std::vector<float> act_d, dn_d, act_l, dn_l;
    char p[512];
    std::snprintf(p, sizeof(p),
                  "%s\\deep2_FFN_ACT_2_pos0_layer0_full_n5632_seq054.bin", dump);
    if (!read_f32(p, act_d)) {
        std::printf("ACT_D_FAIL\n");
        return 4;
    }
    std::snprintf(p, sizeof(p),
                  "%s\\deep2_FFN_DOWN_2_pos0_layer0_full_n2048_seq055.bin",
                  dump);
    if (!read_f32(p, dn_d)) {
        std::printf("DN_D_FAIL\n");
        return 5;
    }
    std::snprintf(p, sizeof(p),
                  "%s\\llama_FFN_ACT_2_pos0_layer0_full_n5632_seq287.bin",
                  gref);
    if (!read_f32(p, act_l)) {
        std::printf("ACT_L_FAIL\n");
        return 6;
    }
    std::snprintf(p, sizeof(p),
                  "%s\\llama_FFN_DOWN_2_pos0_layer0_full_n2048_seq289.bin",
                  gref);
    if (!read_f32(p, dn_l)) {
        std::printf("DN_L_FAIL\n");
        return 7;
    }
    int peak = -1;
    std::printf("ACT deep vs llama maxAbs=%.6e peak=%d\n",
                max_abs(act_d, act_l, &peak), peak);
    std::printf("DOWN deep vs llama maxAbs=%.6e peak=%d\n",
                max_abs(dn_d, dn_l, &peak), peak);

    std::vector<float> host_d(rows, 0.f), host_l(rows, 0.f);
    gemv(w.data(), act_d.data(), host_d.data(), rows, cols);
    gemv(w.data(), act_l.data(), host_l.data(), rows, cols);
    std::printf("host(ACT_d) vs deep2_DOWN maxAbs=%.6e peak=%d\n",
                max_abs(host_d, dn_d, &peak), peak);
    std::printf("host(ACT_d) vs llama_DOWN maxAbs=%.6e peak=%d\n",
                max_abs(host_d, dn_l, &peak), peak);
    std::printf("host(ACT_l) vs llama_DOWN maxAbs=%.6e peak=%d\n",
                max_abs(host_l, dn_l, &peak), peak);
    std::printf("host(ACT_l) vs deep2_DOWN maxAbs=%.6e peak=%d\n",
                max_abs(host_l, dn_d, &peak), peak);

    const float host_vs_deep = max_abs(host_d, dn_d, &peak);
    const float host_vs_llama = max_abs(host_d, dn_l, &peak);
    if (host_vs_deep < 1e-6f) {
        std::printf("VERDICT=RUNTIME_FFN_DOWN_MATCHES_HOST_Q4K\n");
        std::printf("ROOT=Q4KxQ8K_AMPLIFY_OF_ACT_YD_RESIDUAL\n");
    } else if (host_vs_llama < host_vs_deep) {
        std::printf("VERDICT=RUNTIME_FFN_DOWN_NE_HOST_Q4K maxAbs=%.6e\n",
                    host_vs_deep);
        std::printf("ROOT=Q4K_SPV_OR_LAYOUT_OR_ACCUM_MISMATCH\n");
    } else {
        std::printf("VERDICT=RUNTIME_AND_HOST_BOTH_OFF_LLAMA "
                    "host_vs_deep=%.6e host_vs_llama=%.6e\n",
                    host_vs_deep, host_vs_llama);
        std::printf("ROOT=ACT_YD_AMPLIFY_OR_SHARED_KERNEL_GAP\n");
    }
    std::printf("PROMOTE=0 TIP_CLIMB=HOLD\n");
    return 0;
}
