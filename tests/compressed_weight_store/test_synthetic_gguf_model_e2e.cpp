#include "../../src/deep2/GGUFLoader.hpp"
#include "../../src/deep2/compression/GGUFCompressedResidency.hpp"
#include "../../src/deep2/compression/StoredTensorMatvec.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

#define REQUIRE(x) do { if (!(x)) { std::cerr << "FAIL: " #x << " at " << __LINE__ << "\n"; return 1; } } while (false)

namespace {
void put32(std::vector<std::uint8_t>& b, std::uint32_t v) {
    for (unsigned i=0;i<4;++i) b.push_back(static_cast<std::uint8_t>(v>>(8*i)));
}
void put64(std::vector<std::uint8_t>& b, std::uint64_t v) {
    for (unsigned i=0;i<8;++i) b.push_back(static_cast<std::uint8_t>(v>>(8*i)));
}
void putString(std::vector<std::uint8_t>& b, const std::string& s) {
    put64(b, s.size()); b.insert(b.end(), s.begin(), s.end());
}
void align32(std::vector<std::uint8_t>& b) {
    while (b.size() % 32) b.push_back(0);
}
std::vector<std::uint8_t> makeQ4ModelTensor(std::size_t rows) {
    std::vector<std::uint8_t> bytes(rows * 18, 0);
    for (std::size_t row=0; row<rows; ++row) {
        const std::size_t base=row*18;
        bytes[base]=0x00; bytes[base+1]=0x3c; // fp16 scale = 1
        for (std::size_t i=0;i<16;++i) bytes[base+2+i]=0x98;
    }
    return bytes;
}
bool writeSyntheticGGUF(const std::filesystem::path& path,
                        const std::vector<std::uint8_t>& embedding,
                        const std::vector<std::uint8_t>& projection) {
    std::vector<std::uint8_t> file;
    put32(file, 0x46554747u); // "GGUF" little-endian
    put32(file, 3);           // GGUF v3
    put64(file, 2);           // tensor count
    put64(file, 0);           // metadata count

    // token_embd.weight: [input width=32, vocab rows=64], Q4_0
    putString(file, "token_embd.weight");
    put32(file, 2); put64(file, 32); put64(file, 64);
    put32(file, 2); put64(file, 0);

    // blk.0.attn_q.weight: [input width=32, output rows=64], Q4_0
    putString(file, "blk.0.attn_q.weight");
    put32(file, 2); put64(file, 32); put64(file, 64);
    put32(file, 2); put64(file, embedding.size());

    align32(file);
    if (file.size() % 32 != 0 || embedding.size() % 32 != 0) return false;
    file.insert(file.end(), embedding.begin(), embedding.end());
    file.insert(file.end(), projection.begin(), projection.end());

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(reinterpret_cast<const char*>(file.data()),
              static_cast<std::streamsize>(file.size()));
    return out.good();
}
struct DirectReader {
    const std::vector<std::uint8_t>& bytes;
    std::size_t size() const { return bytes.size(); }
    void read(std::size_t offset, std::uint8_t* out, std::size_t count) const {
        if (offset > bytes.size() || count > bytes.size()-offset)
            throw std::out_of_range("direct GGUF fixture range");
        std::memcpy(out, bytes.data()+offset, count);
    }
};
}

int main() {
    constexpr std::size_t rows=64, cols=32, rowBytes=18;
    const auto embedding=makeQ4ModelTensor(rows);
    const auto projection=makeQ4ModelTensor(rows);
    const auto path=std::filesystem::temp_directory_path() /
        "rawrxd_synthetic_compressed_model_e2e.gguf";
    REQUIRE(writeSyntheticGGUF(path, embedding, projection));

    Deep2::GGUFLoader loader;
    REQUIRE(loader.load(path.string()));
    REQUIRE(loader.loaded());
    REQUIRE(loader.version()==3);
    REQUIRE(loader.tensorCount()==2);
    const auto* mappedEmbedding=loader.getTensor("token_embd.weight");
    const auto* mappedProjection=loader.getTensor("blk.0.attn_q.weight");
    REQUIRE(mappedEmbedding && mappedProjection);
    REQUIRE(mappedEmbedding->mapped && mappedProjection->mapped);
    REQUIRE(mappedEmbedding->sizeBytes==embedding.size());
    REQUIRE(mappedProjection->sizeBytes==projection.size());
    REQUIRE(static_cast<std::uint32_t>(mappedProjection->type)==2u);

    // This exercises the actual mapped-GGUF -> block-compressed-store adapter.
    rawrxd::compression::CompressedWeightStore store(0, 64, 1u<<20);
    std::string failedTensor, error;
    const auto admitted=rawrxd::compression::StoreMappedGGUFModel(
        store, loader, &failedTensor, &error, true);
    REQUIRE(admitted==2);
    REQUIRE(failedTensor.empty());
    const auto admittedStats=store.stats();
    REQUIRE(admittedStats.tensors==2);
    REQUIRE(admittedStats.raw_bytes==embedding.size()+projection.size());
    REQUIRE(admittedStats.compressed_bytes<admittedStats.raw_bytes);
    REQUIRE(store.tensorType("blk.0.attn_q.weight")==2u);
    REQUIRE(store.tensorType("token_embd.weight")==2u);

    // Drop the GGUF mapping. The compressed store must remain independently
    // usable and must not rely on the original mapped pointer.
    loader.close();
    REQUIRE(!loader.loaded());

    std::vector<float> input(cols, 1.0f), compressedOutput(rows), referenceOutput(rows);
    rawrxd::compression::StoredTensorMatvec(
        store, "blk.0.attn_q.weight", rawrxd::compression::ResidentWeightType::Q4_0,
        input.data(), compressedOutput.data(), rows, cols, 7);
    DirectReader direct{projection};
    rawrxd::compression::ResidentMatvec(
        direct, rawrxd::compression::ResidentWeightType::Q4_0,
        input.data(), referenceOutput.data(), rows, cols, 7);
    REQUIRE(compressedOutput==referenceOutput);
    for (float value:compressedOutput) REQUIRE(value==16.0f);

    // Embedding lookup reads only the selected packed row, not the vocabulary
    // matrix. Its bytes must match the original GGUF payload exactly.
    constexpr std::size_t token=37;
    std::array<std::uint8_t,rowBytes> selectedRow{};
    REQUIRE(store.readRange("token_embd.weight", token*rowBytes,
                            selectedRow.data(), selectedRow.size(), &error));
    REQUIRE(std::equal(selectedRow.begin(), selectedRow.end(),
                       embedding.begin()+token*rowBytes));

    // With decoded cache budget zero, all successful reads are transient
    // block leases; no whole decoded tensor is retained in the store cache.
    const auto finalStats=store.stats();
    REQUIRE(finalStats.cache_misses>0);
    REQUIRE(finalStats.cached_decoded_bytes==0);
    REQUIRE(finalStats.compressed_bytes<finalStats.raw_bytes);

    // Corrupt/truncate the synthetic GGUF and require parser rejection.
    const auto badPath=path.string()+".truncated";
    {
        std::ifstream in(path, std::ios::binary);
        std::vector<char> bytes((std::istreambuf_iterator<char>(in)), {});
        REQUIRE(bytes.size()>64);
        bytes.resize(bytes.size()-17);
        std::ofstream out(badPath, std::ios::binary|std::ios::trunc);
        REQUIRE(static_cast<bool>(out));
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        REQUIRE(out.good());
    }
    Deep2::GGUFLoader badLoader;
    REQUIRE(!badLoader.load(badPath));
    REQUIRE(!badLoader.error().empty());

    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    std::filesystem::remove(badPath, ignored);
    std::cout << "SYNTHETIC_GGUF_E2E_PASS tensors=" << finalStats.tensors
              << " raw=" << finalStats.raw_bytes
              << " compressed=" << finalStats.compressed_bytes
              << " cache_misses=" << finalStats.cache_misses
              << " decoded_cache=" << finalStats.cached_decoded_bytes << "\n";
    return 0;
}
