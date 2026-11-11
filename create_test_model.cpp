// Create a minimal valid GGUF model for testing multi-token output.
// Format: GGUF v3 - strings are uint64 length-prefixed (NOT null-terminated)
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
    writeU32(f, 8); // string type (uint32, not uint8!)
    writeStr(f, val);
}

static void writeKVU32(std::ofstream& f, const std::string& key, uint32_t val) {
    writeStr(f, key);
    writeU32(f, 4); // uint32 type
    writeU32(f, val);
}

static void writeKVF32(std::ofstream& f, const std::string& key, float val) {
    writeStr(f, key);
    writeU32(f, 6); // float32 type
    writeF32(f, val);
}

static void writeKVArrayString(std::ofstream& f, const std::string& key, const std::vector<std::string>& vals) {
    writeStr(f, key);
    writeU32(f, 9); // array type
    writeU32(f, 8); // element type = string (uint32, not uint8!)
    uint64_t count = vals.size();
    f.write((const char*)&count, 8);
    for (const auto& v : vals) {
        writeStr(f, v); // string = uint64 len + bytes
    }
}

static void writeKVArrayI32(std::ofstream& f, const std::string& key, const std::vector<int32_t>& vals) {
    writeStr(f, key);
    writeU32(f, 9); // array type
    writeU32(f, 5); // element type = int32
    uint64_t count = vals.size();
    f.write((const char*)&count, 8);
    f.write((const char*)vals.data(), count * 4);
}

int main() {
    const std::string path = "F:\\rawrxd\\test_min_model.gguf";
    std::ofstream f(path, std::ios::binary);
    if (!f) {
        std::fprintf(stderr, "Cannot create %s\n", path.c_str());
        return 1;
    }

    // Header: GGUF magic, version 3, tensor count (u64), kv count (u64)
    const char magic[4] = {'G', 'G', 'U', 'F'};
    f.write(magic, 4);
    writeU32(f, 3); // version
    writeU64(f, 1); // tensor count: 1 (token_embd.weight)
    writeU64(f, 13); // KV count

    // KV pairs (all required metadata)
    writeKVString(f, "general.architecture", "llama");
    writeKVU32(f, "general.file_type", 1); // F32
    
    // tokenizer.ggml.tokens - array of strings
    std::vector<std::string> tokens;
    for (int i = 0; i < 64; i++) {
        tokens.push_back("token_" + std::to_string(i));
    }
    writeKVArrayString(f, "tokenizer.ggml.tokens", tokens);
    
    // tokenizer.ggml.token_type - array of int32 (all = 1, i.e., normal)
    std::vector<int32_t> tokenTypes(64, 1);
    writeKVArrayI32(f, "tokenizer.ggml.token_type", tokenTypes);
    
    writeKVU32(f, "llama.context_length", 512);
    writeKVU32(f, "llama.embedding_length", 64);
    writeKVU32(f, "llama.block_count", 1);
    writeKVU32(f, "llama.feed_forward_length", 128);
    writeKVU32(f, "llama.attention.head_count", 2);
    writeKVU32(f, "llama.attention.head_count_kv", 2);
    writeKVF32(f, "llama.attention.layer_norm_rms_epsilon", 0.00001f);
    writeKVF32(f, "llama.attention.rotary_embedding_scale", 1.0f);

    pad32(f);

    // Tensor metadata: token_embd.weight
    writeStr(f, "token_embd.weight"); // length-prefixed name
    writeU32(f, 2); // 2 dimensions
    uint32_t dims[2] = {64, 64}; // vocab_size=64, embedding_length=64
    f.write((const char*)dims, 8);
    writeU32(f, 0); // type F32

    // Record the offset where tensor data will start (after padding)
    pad32(f);
    uint64_t tensorDataOffset = (uint64_t)f.tellp();

    // Go back and write the offset (8 bytes before current position)
    auto curPos = f.tellp();
    f.seekp(curPos - std::streamoff(8));
    writeU64(f, tensorDataOffset);
    f.seekp(curPos);

    // Tensor data: 64*64*4 = 16384 bytes of F32 weights
    std::vector<float> weights(64 * 64, 0.01f);
    f.write((const char*)weights.data(), weights.size() * 4);

    f.close();
    std::printf("Created %s\n", path.c_str());

    return 0;
}
