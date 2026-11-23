#include "Deep2Engine.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace {
constexpr std::uint32_t kGgufMagic = 0x46554747u;
constexpr std::uint32_t kMetaUint32 = 4;
constexpr std::uint32_t kMetaFloat32 = 6;
constexpr std::uint32_t kMetaString = 8;
constexpr std::uint32_t kF32 = 0;
constexpr std::uint32_t kQ8_0 = 8;
constexpr std::size_t kHidden = 64;
constexpr std::size_t kVocab = 1024;
constexpr std::size_t kQ8RowBytes = 68;

#define CHECK(expr) do { if (!(expr)) { \
    std::fprintf(stderr, "synthetic Deep2 GGUF E2E failed at line %d: %s\\n", \
                 __LINE__, #expr); \
    return __LINE__; \
} } while (0)

void putU32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    for (unsigned i = 0; i < 4; ++i)
        out.push_back(static_cast<std::uint8_t>(value >> (i * 8)));
}
void putU64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (unsigned i = 0; i < 8; ++i)
        out.push_back(static_cast<std::uint8_t>(value >> (i * 8)));
}
void putString(std::vector<std::uint8_t>& out, const std::string& value) {
    putU64(out, static_cast<std::uint64_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}
void putMetaString(std::vector<std::uint8_t>& out,
                   const std::string& key, const std::string& value) {
    putString(out, key);
    putU32(out, kMetaString);
    putString(out, value);
}
void putMetaU32(std::vector<std::uint8_t>& out,
                const std::string& key, std::uint32_t value) {
    putString(out, key);
    putU32(out, kMetaUint32);
    putU32(out, value);
}
void putMetaF32(std::vector<std::uint8_t>& out,
                const std::string& key, float value) {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    putString(out, key);
    putU32(out, kMetaFloat32);
    putU32(out, bits);
}
std::uint64_t alignUp(std::uint64_t value, std::uint64_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

struct TensorDef {
    std::string name;
    std::vector<std::uint64_t> dims;
    std::uint32_t type = kF32;
    std::vector<std::uint8_t> bytes;
    std::uint64_t offset = 0;
};

TensorDef makeF32(const std::string& name,
                  std::vector<std::uint64_t> dims,
                  std::size_t count, float value) {
    TensorDef tensor;
    tensor.name = name;
    tensor.dims = std::move(dims);
    tensor.type = kF32;
    tensor.bytes.resize(count * sizeof(float));
    std::vector<float> values(count, value);
    std::memcpy(tensor.bytes.data(), values.data(), tensor.bytes.size());
    return tensor;
}

TensorDef makeQ8Embedding() {
    TensorDef tensor;
    tensor.name = "token_embd.weight";
    tensor.dims = {kHidden, kVocab};
    tensor.type = kQ8_0;
    tensor.bytes.assign(kVocab * kQ8RowBytes, 0);
    for (std::size_t row = 0; row < kVocab; ++row) {
        const std::size_t dim = row % kHidden;
        const std::size_t block = dim / 32;
        const std::size_t inBlock = dim % 32;
        for (std::size_t b = 0; b < 2; ++b) {
            const std::size_t blockOffset = row * kQ8RowBytes + b * 34;
            tensor.bytes[blockOffset] = 0x00;
            tensor.bytes[blockOffset + 1] = 0x3C; // F16(1.0)
        }
        if (dim != 1 || row == 1) {
            tensor.bytes[row * kQ8RowBytes + block * 34 + 2 + inBlock] =
                row == 1 ? 127 : 1;
        }
    }
    return tensor;
}

bool writeSyntheticGguf(const std::filesystem::path& path) {
    std::vector<TensorDef> tensors;
    tensors.reserve(11);
    tensors.push_back(makeQ8Embedding());
    tensors.push_back(makeF32("output_norm.weight", {kHidden}, kHidden, 1.0001234f));
    tensors.push_back(makeF32("blk.0.attn_norm.weight", {kHidden}, kHidden, 1.0001234f));
    tensors.push_back(makeF32("blk.0.attn_q.weight", {kHidden, kHidden}, kHidden * kHidden, 0.0f));
    tensors.push_back(makeF32("blk.0.attn_k.weight", {kHidden, kHidden}, kHidden * kHidden, 0.0f));
    tensors.push_back(makeF32("blk.0.attn_v.weight", {kHidden, kHidden}, kHidden * kHidden, 0.0f));
    tensors.push_back(makeF32("blk.0.attn_output.weight", {kHidden, kHidden}, kHidden * kHidden, 0.0f));
    tensors.push_back(makeF32("blk.0.ffn_norm.weight", {kHidden}, kHidden, 1.0001234f));
    tensors.push_back(makeF32("blk.0.ffn_gate.weight", {kHidden, kHidden}, kHidden * kHidden, 0.0f));
    tensors.push_back(makeF32("blk.0.ffn_up.weight", {kHidden, kHidden}, kHidden * kHidden, 0.0f));
    tensors.push_back(makeF32("blk.0.ffn_down.weight", {kHidden, kHidden}, kHidden * kHidden, 0.0f));

    std::uint64_t dataBytes = 0;
    for (auto& tensor : tensors) {
        dataBytes = alignUp(dataBytes, 32);
        tensor.offset = dataBytes;
        if (tensor.bytes.size() >
            std::numeric_limits<std::uint64_t>::max() - dataBytes)
            return false;
        dataBytes += static_cast<std::uint64_t>(tensor.bytes.size());
    }

    std::vector<std::uint8_t> file;
    putU32(file, kGgufMagic);
    putU32(file, 3);
    putU64(file, static_cast<std::uint64_t>(tensors.size()));
    putU64(file, 11);

    putMetaString(file, "general.architecture", "llama");
    putMetaU32(file, "general.alignment", 32);
    putMetaU32(file, "llama.embedding_length", static_cast<std::uint32_t>(kHidden));
    putMetaU32(file, "llama.block_count", 1);
    putMetaU32(file, "llama.attention.head_count", 4);
    putMetaU32(file, "llama.attention.head_count_kv", 4);
    putMetaU32(file, "llama.feed_forward_length", static_cast<std::uint32_t>(kHidden));
    putMetaU32(file, "llama.context_length", 16);
    putMetaF32(file, "llama.attention.layer_norm_rms_epsilon", 1.0e-5f);
    putMetaU32(file, "llama.rope.dimension_count", 16);
    putMetaF32(file, "llama.rope.freq_base", 10000.0f);

    for (const auto& tensor : tensors) {
        putString(file, tensor.name);
        putU32(file, static_cast<std::uint32_t>(tensor.dims.size()));
        for (const auto dim : tensor.dims) putU64(file, dim);
        putU32(file, tensor.type);
        putU64(file, tensor.offset);
    }

    const std::uint64_t dataStart = alignUp(file.size(), 32);
    if (dataStart > std::numeric_limits<std::size_t>::max() ||
        dataBytes > std::numeric_limits<std::size_t>::max() -
                        static_cast<std::size_t>(dataStart))
        return false;
    file.resize(static_cast<std::size_t>(dataStart), 0);
    for (const auto& tensor : tensors) {
        const std::uint64_t absolute = dataStart + tensor.offset;
        if (absolute > std::numeric_limits<std::size_t>::max()) return false;
        if (file.size() < static_cast<std::size_t>(absolute))
            file.resize(static_cast<std::size_t>(absolute), 0);
        file.insert(file.end(), tensor.bytes.begin(), tensor.bytes.end());
    }

    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) return false;
    stream.write(reinterpret_cast<const char*>(file.data()),
                 static_cast<std::streamsize>(file.size()));
    stream.flush();
    return stream.good();
}

void enableCompressionForTest() {
#if defined(_WIN32)
    _putenv_s("RAWRXD_COMPRESS_F32", "1");
    _putenv_s("RAWRXD_COMPRESS_F32_MAX_ABS_ERROR", "0");
    _putenv_s("RAWRXD_COMPRESS_F32_BUDGET_MB", "32");
    _putenv_s("RAWRXD_COMPRESS_QUANTIZED_BYTES", "1");
#else
    setenv("RAWRXD_COMPRESS_F32", "1", 1);
    setenv("RAWRXD_COMPRESS_F32_MAX_ABS_ERROR", "0", 1);
    setenv("RAWRXD_COMPRESS_F32_BUDGET_MB", "32", 1);
    setenv("RAWRXD_COMPRESS_QUANTIZED_BYTES", "1", 1);
#endif
}
}

int main() {
    enableCompressionForTest();
    const auto path = std::filesystem::temp_directory_path() /
        "rawrxd_deep2_synthetic_compressed_runtime.gguf";
    std::error_code ec;
    std::filesystem::remove(path, ec);
    CHECK(writeSyntheticGguf(path));

    int generated[2] = {-1, -1};
    Deep2::InferenceStats stats{};
    {
        Deep2::Deep2Engine engine;
        Deep2::EngineConfig config{};
        config.maxSeqLen = 16;
        config.useKVCache = true;
        config.useThreadPool = false;
        config.numThreads = 0;
        config.pinThreads = false;
        CHECK(engine.initialize(config));
        CHECK(engine.loadModel(path.string()));
        CHECK(engine.isModelLoaded());

        const auto& weights = engine.getModelWeights();
        CHECK(weights.tokenEmbed.type == static_cast<int>(Deep2::GGMLType::GGML_TYPE_Q8_0));
        CHECK(weights.tokenEmbed.compressedBytes != nullptr);
        CHECK(weights.tokenEmbed.compressedBytes->residentBytes() <
              weights.tokenEmbed.sizeBytes);
        CHECK(weights.layers.size() == 1);
        CHECK(weights.layers[0].attnNorm.compressedF32 != nullptr);
        bool hasLosslessF32Chunk = false;
        for (const auto& chunk : weights.layers[0].attnNorm.compressedF32->chunks()) {
            if (chunk.encoding == RawrXD::TensorCompression::Encoding::LZ4)
                hasLosslessF32Chunk = true;
        }
        CHECK(hasLosslessF32Chunk);

        Deep2::GenerationOptions generation{};
        generation.maxTokens = 2;
        generation.temperature = 0.0f;
        generation.topK = 1;
        engine.configureGeneration(generation);
        const int prompt = 1;
        const std::size_t count = engine.generate(
            &prompt, 1, generated, 2, &stats);
        CHECK(count == 2);
        CHECK(stats.tokensGenerated == 2);
        CHECK(generated[0] == 1 && generated[1] == 1);

        engine.unloadModel();
    }
    std::filesystem::remove(path, ec);
    std::puts("DEEP2_SYNTHETIC_GGUF_LOAD=PASS");
    std::puts("DEEP2_SYNTHETIC_F32_LOSSLESS_RESIDENCY=PASS");
    std::puts("DEEP2_SYNTHETIC_Q8_0_COMPRESSED_EMBEDDING=PASS");
    std::puts("DEEP2_SYNTHETIC_CPU_INFERENCE=PASS");
    std::puts("DEEP2_SYNTHETIC_TWO_TOKEN_GENERATION=PASS");
    return 0;
}
