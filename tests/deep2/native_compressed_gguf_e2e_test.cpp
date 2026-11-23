#include "../../src/TensorROM.hpp"
#include "../../src/deep2/NativeTensorResidencyCache.hpp"
#include "../../src/deep2/NativeTensorByteResidencyCache.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {
template<class T> void put(std::ostream& out, T value) {
    out.write(reinterpret_cast<const char*>(&value), sizeof(value));
}
void putString(std::ostream& out, const std::string& value) {
    put<uint64_t>(out, value.size());
    out.write(value.data(), static_cast<std::streamsize>(value.size()));
}
uint64_t alignUp(uint64_t n, uint64_t alignment) {
    return (n + alignment - 1) & ~(alignment - 1);
}
struct TensorSpec {
    std::string name;
    uint32_t type;
    std::vector<uint64_t> dims;
    uint64_t offset;
};
void putTensorInfo(std::ostream& out, const TensorSpec& tensor) {
    putString(out, tensor.name);
    put<uint32_t>(out, static_cast<uint32_t>(tensor.dims.size()));
    for (uint64_t dim : tensor.dims) put<uint64_t>(out, dim);
    put<uint32_t>(out, tensor.type);
    put<uint64_t>(out, tensor.offset);
}
bool writeSyntheticGGUF(const std::filesystem::path& path,
                        std::vector<float>& embeddings,
                        std::vector<float>& outputWeights,
                        std::vector<uint8_t>& q4Payload) {
    constexpr uint64_t kHidden = 1024;
    const uint64_t embeddingBytes = embeddings.size() * sizeof(float);
    const uint64_t outputOffset = alignUp(embeddingBytes, 32);
    const uint64_t outputBytes = outputWeights.size() * sizeof(float);
    const uint64_t q4Offset = alignUp(outputOffset + outputBytes, 32);

    const TensorSpec tensors[] = {
        {"token_embd.weight", 0, {kHidden, 4}, 0},
        {"output.weight", 0, {kHidden, 4}, outputOffset},
        {"synthetic.q4_k", 12, {256}, q4Offset}
    };

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    put<uint32_t>(out, 0x46554747u); // GGUF magic
    put<uint32_t>(out, 3);
    put<uint64_t>(out, 3); // tensor count
    put<uint64_t>(out, 0); // KV count
    for (const auto& tensor : tensors) putTensorInfo(out, tensor);

    const auto directoryEnd = static_cast<uint64_t>(out.tellp());
    const uint64_t dataStart = alignUp(directoryEnd, 32);
    while (static_cast<uint64_t>(out.tellp()) < dataStart) out.put('\0');

    out.write(reinterpret_cast<const char*>(embeddings.data()),
              static_cast<std::streamsize>(embeddingBytes));
    while (static_cast<uint64_t>(out.tellp()) < dataStart + outputOffset) out.put('\0');
    out.write(reinterpret_cast<const char*>(outputWeights.data()),
              static_cast<std::streamsize>(outputBytes));
    while (static_cast<uint64_t>(out.tellp()) < dataStart + q4Offset) out.put('\0');
    out.write(reinterpret_cast<const char*>(q4Payload.data()),
              static_cast<std::streamsize>(q4Payload.size()));
    return static_cast<bool>(out);
}
}

int main() {
    constexpr size_t kHidden = 1024;
    constexpr size_t kVocab = 4;
    const auto path = std::filesystem::temp_directory_path() /
        "rawrxd_native_compressed_synthetic_e2e.gguf";

    // Synthetic one-layer inference fixture: token 1 embeds to 0.5 in every
    // channel; output rows are 0.1, 0.2, 0.3, and 0.4 respectively.
    std::vector<float> embeddings(kHidden * kVocab);
    std::vector<float> outputWeights(kHidden * kVocab);
    for (size_t token = 0; token < kVocab; ++token)
        std::fill_n(embeddings.begin() + token * kHidden, kHidden,
                    token == 1 ? 0.5f : 0.0f);
    for (size_t row = 0; row < kVocab; ++row)
        std::fill_n(outputWeights.begin() + row * kHidden, kHidden,
                    0.1f * static_cast<float>(row + 1));
    std::vector<uint8_t> q4Payload(144, 0xA5); // Q4_K: 256 values -> 144 bytes

    if (!writeSyntheticGGUF(path, embeddings, outputWeights, q4Payload)) {
        std::cerr << "could not write synthetic GGUF fixture\n";
        return 1;
    }

    int result = 0;
    {
        deep2::TensorROM rom;
        if (!rom.addShard(path.string()) || !rom.finalizeIndex()) {
            std::cerr << "TensorROM failed to index synthetic GGUF\n";
            result = 2;
        } else {
            const auto* embedding = rom.findTensor("token_embd.weight");
            const auto* output = rom.findTensor("output.weight");
            const auto* q4 = rom.findTensor("synthetic.q4_k");
            if (!embedding || !output || !q4 ||
                embedding->byteSize() != embeddings.size() * sizeof(float) ||
                q4->byteSize() != q4Payload.size()) {
                std::cerr << "synthetic GGUF tensor metadata mismatch\n";
                result = 3;
            } else {
                Deep2::TensorResidencyCache f32Cache(64 * 1024);
                Deep2::TensorByteResidencyCache byteCache(4096);
                auto registerF32 = [&](const deep2::TensorEntry& entry,
                                       const std::vector<float>& reference) {
                    const std::string key = entry.name;
                    return f32Cache.RegisterF32FromReader(
                        key, reference.size(), 0.0f,
                        [&](size_t offset, size_t count, float* destination) {
                            return rom.readTensorRange(entry,
                                static_cast<uint64_t>(offset) * sizeof(float),
                                static_cast<uint64_t>(count) * sizeof(float),
                                reinterpret_cast<uint8_t*>(destination));
                        }, 256);
                };

                if (!registerF32(*embedding, embeddings) ||
                    !registerF32(*output, outputWeights)) {
                    std::cerr << "failed to admit synthetic F32 tensors\n";
                    result = 4;
                } else {
                    const std::string q4Key = q4->name;
                    if (!byteCache.RegisterFromReader(q4Key, q4Payload.size(),
                        [&](size_t offset, size_t count, uint8_t* destination) {
                            return rom.readTensorRange(*q4, offset, count, destination);
                        }, 32)) {
                        std::cerr << "failed to admit synthetic Q4_K bytes\n";
                        result = 5;
                    } else {
                        // Token embedding lookup: decode only token 1's row.
                        std::vector<float> hidden(kHidden);
                        if (!f32Cache.ReadRange("token_embd.weight", kHidden,
                                                kHidden, hidden.data())) {
                            std::cerr << "compressed embedding tile read failed\n";
                            result = 6;
                        } else {
                            // Output projection: read one compressed row at a
                            // time, exactly as a tiled matrix-vector kernel needs.
                            std::vector<float> row(kHidden);
                            std::vector<float> logits(kVocab, 0.0f);
                            for (size_t vocab = 0; vocab < kVocab && result == 0; ++vocab) {
                                if (!f32Cache.ReadRange("output.weight",
                                    vocab * kHidden, kHidden, row.data())) {
                                    result = 7;
                                    break;
                                }
                                double sum = 0.0;
                                for (size_t i = 0; i < kHidden; ++i)
                                    sum += static_cast<double>(hidden[i]) * row[i];
                                logits[vocab] = static_cast<float>(sum);
                            }
                            const auto best = static_cast<size_t>(
                                std::max_element(logits.begin(), logits.end()) - logits.begin());
                            if (result == 0 && best != 3) {
                                std::cerr << "synthetic inference selected wrong token: " << best << "\n";
                                result = 8;
                            }
                            if (result == 0) {
                                std::vector<uint8_t> q4Read(q4Payload.size());
                                std::vector<uint8_t> scratch;
                                if (!byteCache.ReadRange(q4Key, 0, q4Read.size(),
                                                         q4Read.data(), scratch) ||
                                    q4Read != q4Payload) {
                                    std::cerr << "Q4_K payload was not preserved losslessly\n";
                                    result = 9;
                                }
                            }
                            if (result == 0) {
                                const auto fstats = f32Cache.GetStats();
                                const auto bstats = byteCache.GetStats();
                                if (fstats.compressedBytes >= fstats.logicalBytes ||
                                    bstats.compressedBytes >= bstats.logicalBytes ||
                                    fstats.activeReaders || bstats.activeReaders) {
                                    std::cerr << "compressed residency accounting invariant failed\n";
                                    result = 10;
                                } else {
                                    std::cout << "SYNTHETIC_GGUF_E2E_PASS"
                                              << " f32_logical=" << fstats.logicalBytes
                                              << " f32_compressed=" << fstats.compressedBytes
                                              << " q4_logical=" << bstats.logicalBytes
                                              << " q4_compressed=" << bstats.compressedBytes
                                              << " logits=" << logits[0] << "," << logits[1]
                                              << "," << logits[2] << "," << logits[3]
                                              << " argmax=" << best << "\n";
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    return result;
}
