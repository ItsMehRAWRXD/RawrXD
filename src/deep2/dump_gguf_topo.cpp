// dump_gguf_topo.cpp — header+tensor names only (no weight payload)
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
static uint32_t U32(FILE* f) { uint32_t v=0; fread(&v,1,4,f); return v; }
static uint64_t U64(FILE* f) { uint64_t v=0; fread(&v,1,8,f); return v; }
static std::string Str(FILE* f) {
    uint64_t n = U64(f);
    if (n == 0 || n > (1u << 20)) return {};
    std::string s(n, 0); fread(s.data(), 1, (size_t)n, f); return s;
}
static void SkipVal(FILE* f, uint32_t t) {
    switch (t) {
    case 0: case 1: case 7: fseek(f,1,SEEK_CUR); break;
    case 2: case 3: fseek(f,2,SEEK_CUR); break;
    case 4: case 5: case 6: fseek(f,4,SEEK_CUR); break;
    case 8: Str(f); break;
    case 9: { uint32_t et=U32(f); uint64_t n=U64(f);
        for (uint64_t i=0;i<n;i++) SkipVal(f, et); break; }
    case 10: case 11: case 12: fseek(f,8,SEEK_CUR); break;
    default: break;
    }
}
int main(int argc, char** argv) {
    if (argc < 2) { printf("usage: dump_gguf_topo <file.gguf>\n"); return 1; }
    FILE* f = fopen(argv[1], "rb");
    if (!f) { printf("open fail\n"); return 1; }
    if (U32(f) != 0x46554747) { printf("not gguf\n"); return 1; }
    uint32_t ver = U32(f); uint64_t nt = U64(f); uint64_t nm = U64(f);
    printf("ver=%u tensors=%llu kv=%llu\n", ver, nt, nm);
    for (uint64_t i = 0; i < nm; i++) {
        std::string k = Str(f); uint32_t t = U32(f);
        if (t == 4) { uint32_t v=U32(f); printf("META %s = %u\n", k.c_str(), v); }
        else if (t == 5) { int32_t v=0; fread(&v,1,4,f); printf("META %s = %d\n", k.c_str(), v); }
        else if (t == 6) { float v=0; fread(&v,1,4,f); printf("META %s = %g\n", k.c_str(), v); }
        else if (t == 8) { std::string v=Str(f); printf("META %s = %s\n", k.c_str(), v.c_str()); }
        else if (t == 10) { uint64_t v=U64(f); printf("META %s = %llu\n", k.c_str(), v); }
        else if (t == 7) { uint8_t v=0; fread(&v,1,1,f); printf("META %s = %u\n", k.c_str(), v); }
        else { SkipVal(f, t); }
    }
    const char* tname[] = {"F32","F16","Q4_0","Q4_1","Q4_2","Q4_3","Q5_0","Q5_1","Q8_0","Q8_1",
        "Q2_K","Q3_K","Q4_K","Q5_K","Q6_K","Q8_K"};
    int shown = 0;
    for (uint64_t i = 0; i < nt; i++) {
        std::string n = Str(f); uint32_t nd = U32(f);
        uint64_t d[8] = {};
        for (uint32_t j = 0; j < nd && j < 8; j++) d[j] = U64(f);
        uint32_t ty = U32(f); uint64_t off = U64(f);
        if (shown < 80 || n.find("output") != std::string::npos ||
            n.find("blk.0.attn") != std::string::npos || n.find("blk.1.ffn") != std::string::npos) {
            printf("T %s type=%u(%s) nd=%u dims=%llu,%llu,%llu off=%llu\n",
                   n.c_str(), ty, ty < 16 ? tname[ty] : "?", nd,
                   d[0], d[1], d[2], off);
            ++shown;
        }
    }
    fclose(f);
    return 0;
}
