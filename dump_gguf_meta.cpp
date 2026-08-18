// Standalone GGUF metadata dumper — no dependencies
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

static uint32_t ReadU32(FILE* f) { uint32_t v; fread(&v, 1, 4, f); return v; }
static uint64_t ReadU64(FILE* f) { uint64_t v; fread(&v, 1, 8, f); return v; }
static std::string ReadStr(FILE* f) {
    uint64_t n = ReadU64(f);
    if (n == 0 || n > 1024*1024) return "";
    std::string s(n, '\0');
    fread(s.data(), 1, n, f);
    return s;
}

int main(int argc, char** argv) {
    const char* path = (argc > 1) ? argv[1] :
        "F:/OllamaModels/Kimi-K2-Instruct-0905-GGUF/Q4_K_M/Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf";
    FILE* f = fopen(path, "rb");
    if (!f) { printf("Cannot open %s\n", path); return 1; }

    uint32_t magic = ReadU32(f);
    if (magic != 0x46554747) { printf("Not GGUF\n"); return 1; }
    uint32_t version = ReadU32(f);
    uint64_t n_tensors = ReadU64(f);
    uint64_t n_meta = ReadU64(f);
    printf("Version: %u  Tensors: %llu  Metadata: %llu\n", version, n_tensors, n_meta);

    for (uint64_t i = 0; i < n_meta; ++i) {
        std::string key = ReadStr(f);
        uint32_t vtype = ReadU32(f);
        std::string val;
        if (vtype == 0) { uint8_t v; fread(&v,1,1,f); val = std::to_string(v); }
        else if (vtype == 1) { int8_t v; fread(&v,1,1,f); val = std::to_string(v); }
        else if (vtype == 2) { uint16_t v; fread(&v,1,2,f); val = std::to_string(v); }
        else if (vtype == 3) { int16_t v; fread(&v,1,2,f); val = std::to_string(v); }
        else if (vtype == 4) { uint32_t v; fread(&v,1,4,f); val = std::to_string(v); }
        else if (vtype == 5) { int32_t v; fread(&v,1,4,f); val = std::to_string(v); }
        else if (vtype == 6) { float v; fread(&v,1,4,f); val = std::to_string(v); }
        else if (vtype == 7) { uint8_t v; fread(&v,1,1,f); val = v ? "true" : "false"; }
        else if (vtype == 8) { val = ReadStr(f); }
        else if (vtype == 9) {
            uint32_t etype = ReadU32(f);
            uint64_t ecnt = ReadU64(f);
            val = "[array:" + std::to_string(ecnt) + "]";
            for (uint64_t j = 0; j < ecnt; ++j) {
                if (etype == 0) { uint8_t v; fread(&v,1,1,f); }
                else if (etype == 1) { int8_t v; fread(&v,1,1,f); }
                else if (etype == 2) { uint16_t v; fread(&v,1,2,f); }
                else if (etype == 3) { int16_t v; fread(&v,1,2,f); }
                else if (etype == 4) { uint32_t v; fread(&v,1,4,f); }
                else if (etype == 5) { int32_t v; fread(&v,1,4,f); }
                else if (etype == 6) { float v; fread(&v,1,4,f); }
                else if (etype == 7) { uint8_t v; fread(&v,1,1,f); }
                else if (etype == 8) { ReadStr(f); }
                else if (etype == 10) { uint64_t v; fread(&v,1,8,f); }
                else if (etype == 11) { int64_t v; fread(&v,1,8,f); }
                else if (etype == 12) { double v; fread(&v,1,8,f); }
            }
        }
        else if (vtype == 10) { uint64_t v; fread(&v,1,8,f); val = std::to_string(v); }
        else if (vtype == 11) { int64_t v; fread(&v,1,8,f); val = std::to_string(v); }
        else if (vtype == 12) { double v; fread(&v,1,8,f); val = std::to_string(v); }
        else { val = "UNKNOWN"; }
        printf("%s = %s\n", key.c_str(), val.c_str());
    }
    fclose(f);
    return 0;
}
