// gguf_tensor_meta.cpp — print tensor metadata for expert tensors.
// Robust binary parse with explicit widths; no PowerShell coercion hazards.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

struct R {
    std::FILE* f = nullptr;
    bool ok(const char* what) {
        if (!std::ferror(f)) return true;
        std::fprintf(stderr, "IO_ERROR at %s\n", what);
        return false;
    }
    uint8_t  u8 () { uint8_t v; std::fread(&v,1,1,f); return v; }
    uint16_t u16(){ uint16_t v; std::fread(&v,2,1,f); return v; }
    uint32_t u32(){ uint32_t v; std::fread(&v,4,1,f); return v; }
    uint64_t u64(){ uint64_t v; std::fread(&v,8,1,f); return v; }
    std::string str(){ uint64_t n=u64(); std::string s; s.resize((size_t)n); if(n) std::fread(&s[0],1,(size_t)n,f); return s; }
    void skip(int64_t n){ std::fseek(f, (long)n, SEEK_CUR); }
};

// GGUF v3 value types (spec order):
// 0 u8  1 i8  2 u16  3 i16  4 u32  5 i32  6 f32  7 bool  8 STRING  9 ARRAY
// 10 u64  11 i64  12 f64
// NOTE: an earlier PowerShell attempt used a 1-based enum here and desynced the
// stream, which is what produced the bogus "type 8 = u8 array" reading.
static void skip_val(R& r, uint32_t t) {
    switch (t) {
        case 0: r.u8(); break;
        case 1: r.u8(); break;
        case 2: r.u16(); break;
        case 3: r.u16(); break;
        case 4: r.u32(); break;
        case 5: r.u32(); break;
        case 6: { uint32_t v; std::fread(&v,4,1,r.f); } break;
        case 7: r.u8(); break;               // bool, 1 byte
        case 8: r.str(); break;              // string: u64 len + bytes
        case 9: {                            // array: u32 elem_type + u64 count + payload
            uint32_t et = r.u32();
            uint64_t n  = r.u64();
            int w = 0;
            switch (et) {
                case 0: case 1: case 7: w = 1; break;
                case 2: case 3:         w = 2; break;
                case 4: case 5: case 6: w = 4; break;
                case 10: case 11: case 12: w = 8; break;
                case 8: { for (uint64_t i=0;i<n;i++) r.str(); w = -1; } break;
                default: break;
            }
            if (w > 0) r.skip((int64_t)(n * (uint64_t)w));
            break;
        }
        case 10: r.u64(); break;
        case 11: r.u64(); break;
        case 12: { uint64_t v; std::fread(&v,8,1,r.f); } break;
        default: std::fprintf(stderr,"bad kv type %u\n",t); break;
    }
}

int main(int argc, char** argv) {
    const char* path = (argc>1)? argv[1] : "F:\\OllamaModels\\DeepSeek-R1-Q4_K_M-COMPLETE\\DeepSeek-R1-Q4_K_M-00001-of-00011.gguf";
    R r; r.f = std::fopen(path, "rb");
    if (!r.f) { std::printf("FAIL_OPEN\n"); return 2; }
    char magic[4]; std::fread(magic,1,4,r.f);
    uint32_t ver = r.u32();
    uint64_t nTensors = r.u64();
    uint64_t nKV = r.u64();
    std::printf("GGUF ver=%u tensors=%llu kv=%llu\n", ver,
        (unsigned long long)nTensors, (unsigned long long)nKV);

    for (uint64_t i=0;i<nKV;i++) {
        std::string key = r.str();
        uint32_t vt = r.u32();
        if (key.find("architecture")!=std::string::npos ||
            key.find("expert")!=std::string::npos ||
            key.find("embedding_length")!=std::string::npos ||
            key.find("head_count")!=std::string::npos ||
            key.find("context_length")!=std::string::npos) {
            std::printf("KV %s type=%u", key.c_str(), vt);
            if (vt == 8) { std::string s = r.str(); std::printf(" = %s\n", s.c_str()); continue; }
            skip_val(r, vt);
            std::printf("\n");
            continue;
        }
        skip_val(r, vt);
    }
    std::printf("KV_DONE\n");

    for (uint64_t i=0;i<nTensors;i++) {
        std::string name = r.str();
        uint32_t nd = r.u32();
        std::vector<uint64_t> dims(nd);
        for (uint32_t j=0;j<nd;j++) dims[j]=r.u64();
        uint32_t ttype=r.u32();
        uint64_t toff=r.u64();
        bool want = (name.find("ffn_gate_exps")!=std::string::npos) ||
                    (name.find("ffn_down_exps")!=std::string::npos);
        if (want) {
            std::printf("T[%llu] %s ndim=%u dims=[", (unsigned long long)i, name.c_str(), nd);
            for (uint32_t j=0;j<nd;j++) std::printf("%llu%s",(unsigned long long)dims[j], j+1<nd?",":"");
            std::printf("] type=%u relOff=%llu\n", ttype, (unsigned long long)toff);
        }
    }
    std::fclose(r.f);
    return 0;
}