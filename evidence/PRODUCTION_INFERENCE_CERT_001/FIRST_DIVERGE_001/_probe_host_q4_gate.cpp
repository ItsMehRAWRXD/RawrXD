/* Offline: host Q4_K×Q8_K GEMV on C740 FFN_NORM_2 vs BATCH2 GATE.
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
    if (n <= 0 || (n % 4) != 0) { std::fclose(f); return false; }
    out.resize(static_cast<size_t>(n) / 4);
    if (std::fread(out.data(), 1, static_cast<size_t>(n), f) != (size_t)n) {
        std::fclose(f); return false;
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
        std::fclose(f); return false;
    }
    uint32_t ver = 0; std::fread(&ver, 4, 1, f);
    uint64_t n_tensors = 0, n_kv = 0;
    std::fread(&n_tensors, 8, 1, f); std::fread(&n_kv, 8, 1, f);
    auto skip_val = [&](uint32_t t) {
        if (t == 8) { uint64_t n=0; std::fread(&n,8,1,f); std::fseek(f,(long)n,SEEK_CUR); }
        else if (t == 9) {
            uint32_t at=0; uint64_t n=0; std::fread(&at,4,1,f); std::fread(&n,8,1,f);
            if (at == 8) {
                for (uint64_t i=0;i<n;i++){ uint64_t sl=0; std::fread(&sl,8,1,f); std::fseek(f,(long)sl,SEEK_CUR);}
            } else {
                static int sz[]={1,1,2,2,4,4,4,8,0,0,1,1,8};
                std::fseek(f,(long)(sz[at]*n),SEEK_CUR);
            }
        } else {
            static int sz[]={1,1,2,2,4,4,4,8,0,0,1,1,8};
            std::fseek(f,sz[t],SEEK_CUR);
        }
    };
    for (uint64_t i=0;i<n_kv;i++){
        uint64_t klen=0; std::fread(&klen,8,1,f); std::fseek(f,(long)klen,SEEK_CUR);
        uint32_t t=0; std::fread(&t,4,1,f); skip_val(t);
    }
    struct Info { std::string nm; uint64_t dims[2]; uint32_t typ; uint64_t off; int nd; };
    std::vector<Info> infos;
    for (uint64_t i=0;i<n_tensors;i++){
        uint64_t nlen=0; std::fread(&nlen,8,1,f);
        std::string nm(nlen,'\0'); std::fread(nm.data(),1,(size_t)nlen,f);
        uint32_t nd=0; std::fread(&nd,4,1,f);
        Info info; info.nm=nm; info.nd=(int)nd;
        for (uint32_t d=0;d<nd;d++){ uint64_t v=0; std::fread(&v,8,1,f); if(d<2) info.dims[d]=v; }
        std::fread(&info.typ,4,1,f); std::fread(&info.off,8,1,f);
        infos.push_back(info);
    }
    long pos = std::ftell(f); pos = (pos + 31) & ~31L; long base = pos;
    for (auto& info : infos) {
        if (info.nm != name) continue;
        cols = (uint32_t)info.dims[0]; rows = (uint32_t)info.dims[1];
        size_t bytes = (size_t)rows * cols / 256u * 144u;
        data.resize(bytes);
        std::fseek(f, base + (long)info.off, SEEK_SET);
        if (std::fread(data.data(),1,bytes,f) != bytes) { std::fclose(f); return false; }
        std::fclose(f); return true;
    }
    std::fclose(f); return false;
}

int main() {
    const char* xin_path =
        "G:/~dev/rawrxd/evidence/PRODUCTION_INFERENCE_CERT_001/FIRST_DIVERGE_001/"
        "stage_dump_ffn_act2_c740_after/deep2_FFN_NORM_2_pos0_layer0_full_n2048_seq051.bin";
    const char* ref_path =
        "G:/~dev/rawrxd/evidence/PRODUCTION_INFERENCE_CERT_001/FIRST_DIVERGE_001/"
        "stage_dump_ffn_act2_c740_after_ref/llama_FFN_GATE_2_pos0_layer0_full_n5632_seq283.bin";
    const char* spv_path =
        "G:/~dev/rawrxd/evidence/PRODUCTION_INFERENCE_CERT_001/FIRST_DIVERGE_001/"
        "stage_dump_ffn_act2_c740_after/deep2_FFN_GATE_2_pos0_layer0_full_n5632_seq052.bin";
    const char* gguf = "G:/~dev/rawrxd/models/tinyllama.gguf";

    std::vector<float> xin, ref, spv;
    if (!read_f32(xin_path, xin) || !read_f32(ref_path, ref) || !read_f32(spv_path, spv)) {
        std::fprintf(stderr, "READ_FAIL\n"); return 2;
    }
    std::vector<uint8_t> w; uint32_t rows=0, cols=0;
    if (!read_gguf_q4k(gguf, "blk.2.ffn_gate.weight", w, rows, cols)) {
        std::fprintf(stderr, "GGUF_FAIL\n"); return 3;
    }
    std::fprintf(stderr, "rows=%u cols=%u xin=%zu\n", rows, cols, xin.size());
    Deep2::QuantKernelRegistry::Instance().Initialize();
    auto gemv = Deep2::QuantKernelRegistry::Instance().GetGEMV(12);
    if (!gemv) { std::fprintf(stderr, "NO_GEMV\n"); return 4; }
    std::vector<float> out(rows, 0.f);
    gemv(w.data(), xin.data(), out.data(), rows, cols);
    float mx_ref=0, mx_spv=0; int i_ref=-1, i_spv=-1;
    for (uint32_t i=0;i<rows;i++){
        float d1=std::fabs(out[i]-ref[i]); if(d1>mx_ref){mx_ref=d1;i_ref=(int)i;}
        float d2=std::fabs(spv[i]-ref[i]); if(d2>mx_spv){mx_spv=d2;i_spv=(int)i;}
    }
    std::printf("HOST_vs_REF maxAbs=%.6e peak=%d\n", mx_ref, i_ref);
    std::printf("SPV_vs_REF  maxAbs=%.6e peak=%d\n", mx_spv, i_spv);
    std::printf("peak5475 host=%.9e ref=%.9e spv=%.9e\n",
                out[5475], ref[5475], spv[5475]);
    std::printf("PROMOTE=0\n");
    return 0;
}
