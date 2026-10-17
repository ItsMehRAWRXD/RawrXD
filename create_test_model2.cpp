// Minimal GGUF model with just essential metadata
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>
#include <string>

static void writeU32(std::ofstream& f, uint32_t v) { f.write((const char*)&v, 4); }
static void writeU64(std::ofstream& f, uint64_t v) { f.write((const char*)&v, 8); }
static void writeU8(std::ofstream& f, uint8_t v) { f.write((const char*)&v, 1); }
static void writeStr(std::ofstream& f, const std::string& s) {
    uint64_t len = s.size();
    f.write((const char*)&len, 8);
    f.write(s.data(), s.size());
}
static void writeF32(std::ofstream& f, float v) { f.write((const char*)&v, 4); }

static void pad32(std::ofstream& f) {
    auto pos = f.tellp();
    uint64_t rem = (uint64_t)pos % 32;
    if (rem) {
        uint64_t pad = 32 - rem;
        std::vector<uint8_t> zeros(pad, 0);
        f.write((const char*)zeros.data(), pad);
    }
}

static void writeKVString(std::ofstream& f, const std::string& key, const std::string& val) {
    writeStr(f, key);
    writeU8(f, 8);
    writeStr(f, val);
}

static void writeKVU32(std::ofstream& f, const std::string& key, uint32_t val) {
    writeStr(f, key);
    writeU8(f, 4);
    writeU32(f, val);
}

int main() {
    const std::string path = "F:\\rawrxd\\test_min2.gguf";
    std::ofstream f(path, std::ios::binary);
    if (!f) { std::fprintf(stderr, "Cannot create %s\n", path.c_str()); return 1; }

    const char magic[4] = {'G', 'G', 'U', 'F'};
    f.write(magic, 4);
    writeU32(f, 3);
    writeU64(f, 1); // 1 tensor
    writeU64(f, 2); // 2 KV entries

    writeKVString(f, "general.architecture", "llama");
    writeKVU32(f, "general.file_type", 1);

    pad32(f);

    // Tensor: token_embd.weight
    writeStr(f, "token_embd.weight");
    writeU32(f, 2);
    uint32_t dims[2] = {64, 64};
    f.write((const char*)dims, 8);
    writeU32(f, 0); // F32

    pad32(f);
    uint64_t tensorDataOffset = (uint64_t)f.tellp();
    auto curPos = f.tellp();
    f.seekp(curPos - std::streamoff(8));
    writeU64(f, tensorDataOffset);
    f.seekp(curPos);

    std::vector<float> weights(64 * 64, 0.01f);
    f.write((const char*)weights.data(), weights.size() * 4);

    f.close();
    std::printf("Created %s\n", path.c_str());
    return 0;
}
