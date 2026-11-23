#include "../../src/Deep2Engine.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
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
void putU64KV(std::ostream& out, const std::string& key, uint64_t value) {
    putString(out, key);
    put<uint32_t>(out, 10); // GGUF UINT64
    put<uint64_t>(out, value);
}
uint64_t alignUp(uint64_t n, uint64_t alignment) {
    return (n + alignment - 1) & ~(alignment - 1);
}
struct Tensor {
    std::string name;
    std::vector<uint64_t> dims;
    std::vector<float> values;
    uint64_t offset = 0;
    uint32_t ggmlType = 0; // F32=0, F16=1
};
void putTensorInfo(std::ostream& out, const Tensor& tensor) {
    putString(out, tensor.name);
    put<uint32_t>(out, static_cast<uint32_t>(tensor.dims.size()));
    for (uint64_t d : tensor.dims) put<uint64_t>(out, d);
    put<uint32_t>(out, tensor.ggmlType);
    put<uint64_t>(out, tensor.offset);
}
bool writeFixture(const std::filesystem::path& path, std::vector<Tensor>& tensors) {
    constexpr uint64_t alignment = 32;
    uint64_t cursor = 0;
    for (auto& t : tensors) {
        cursor = alignUp(cursor, alignment);
        t.offset = cursor;
        cursor += t.values.size() * (t.ggmlType == 1 ? sizeof(uint16_t) : sizeof(float));
    }
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    put<uint32_t>(out, 0x46554747u);
    put<uint32_t>(out, 3);
    put<uint64_t>(out, tensors.size());
    put<uint64_t>(out, 7);
    putU64KV(out, "phi3.embedding_length", 16);
    putU64KV(out, "phi3.block_count", 1);
    putU64KV(out, "phi3.attention.head_count", 1);
    putU64KV(out, "phi3.attention.head_count_kv", 1);
    putU64KV(out, "phi3.feed_forward_length", 16);
    putU64KV(out, "phi3.context_length", 16);
    putU64KV(out, "general.alignment", alignment);
    for (const auto& t : tensors) putTensorInfo(out, t);
    const uint64_t dataStart = alignUp(static_cast<uint64_t>(out.tellp()), alignment);
    while (static_cast<uint64_t>(out.tellp()) < dataStart) out.put('\0');
    for (const auto& t : tensors) {
        while (static_cast<uint64_t>(out.tellp()) < dataStart + t.offset) out.put('\0');
        if (t.ggmlType == 1) {
            // Exact small positive F16 values used by this fixture.
            for (float value : t.values) {
                uint16_t half = 0;
                if (value == 1.0f) half = 0x3c00;
                else if (value == 2.0f) half = 0x4000;
                else if (value == 0.5f) half = 0x3800;
                else if (value != 0.0f) return false;
                put<uint16_t>(out, half);
            }
        } else {
            out.write(reinterpret_cast<const char*>(t.values.data()),
                      static_cast<std::streamsize>(t.values.size() * sizeof(float)));
        }
    }
    return static_cast<bool>(out);
}
Tensor makeTensor(std::string name, std::vector<uint64_t> dims,
                  std::vector<float> values) {
    return Tensor{std::move(name), std::move(dims), std::move(values), 0, 0};
}
}

int main() {
    constexpr size_t H = 16;
    std::vector<Tensor> tensors;

    // Token 1 -> [1, 2, 0, ...]. GGUF matrix dimensions are [columns, rows].
    std::vector<float> embedding(H * H, 0.0f);
    embedding[H + 0] = 1.0f;
    embedding[H + 1] = 2.0f;
    tensors.push_back(makeTensor("token_embd.weight", {H, H}, embedding));

    // One QKV projection: Q=0, K=0, V maps x0 -> [x0,x0] and
    // x1 -> [x1,x1], preserving a small deterministic active subspace.
    std::vector<float> qkv(3 * H * H, 0.0f);
    qkv[(2 * H + 0) * H + 0] = 1.0f;
    qkv[(2 * H + 1) * H + 0] = 1.0f;
    qkv[(2 * H + 2) * H + 1] = 1.0f;
    qkv[(2 * H + 3) * H + 1] = 1.0f;
    tensors.push_back(makeTensor("blk.0.attn_qkv.weight", {H, 3 * H}, qkv));

    // A zero FFN is intentional: it exercises the production up/GELU/down
    // projection path while leaving the known hidden state unchanged.
    tensors.push_back(makeTensor("blk.0.ffn_up.weight", {H, H},
                                 std::vector<float>(H * H, 0.0f)));
    tensors.push_back(makeTensor("blk.0.ffn_down.weight", {H, H},
                                 std::vector<float>(H * H, 0.0f)));

    // A 4096x16 F16 output projection spans two 64 KiB codec chunks.
    // Each GEMV tile requests only 16 rows, so inference must range-decode
    // compressed chunks rather than materializing the complete 128 KiB matrix.
    constexpr size_t outputRows = 4096;
    std::vector<float> output(H * outputRows, 0.0f);
    for (size_t i = 0; i < H - 1; ++i) output[i * H + i] = 1.0f;
    output[(outputRows - 1) * H + 0] = 2.0f;
    output[(outputRows - 1) * H + 1] = 2.0f;
    Tensor packedOutput = makeTensor("output.weight", {H, outputRows}, output);
    packedOutput.ggmlType = 1; // Exercise the native packed-F16 inference dispatch.
    tensors.push_back(std::move(packedOutput));

    const auto path = std::filesystem::temp_directory_path() /
        "rawrxd_deep2_compressed_model_e2e.gguf";
    if (!writeFixture(path, tensors)) {
        std::cerr << "fixture creation failed\n";
        return 1;
    }

    int rc = 0;
    {
        Deep2Engine engine;
        if (!engine.Initialize(path.string())) {
            std::cerr << "Deep2Engine failed to initialize synthetic GGUF\n";
            rc = 3;
        } else if (!engine.ConfigureTensorCompression(1024 * 1024, 1024 * 1024, 0.0f)) {
            std::cerr << "compression configuration rejected\n";
            rc = 2;
        } else {
            // Keep this numerical smoke deterministic on hosted runners: the
            // production CPU tiled GEMV still consumes compressed cache ranges.
            engine.vulkanReady = false;
            std::vector<float> logits, baseline;
            if (!engine.executePhi3ROMForwardPass({1}, logits, baseline)) {
                std::cerr << "Deep2Engine synthetic Phi-3 forward pass failed\n";
                rc = 4;
            } else if (logits.size() != outputRows || baseline.size() != outputRows) {
                std::cerr << "unexpected synthetic model logit shape\n";
                rc = 5;
            } else {
                const auto best = static_cast<size_t>(
                    std::max_element(logits.begin(), logits.end()) - logits.begin());
                const auto stats = engine.GetTensorResidencySnapshot();
                if (best != outputRows - 1 || logits != baseline ||
                    stats.f32TensorCount == 0 ||
                    stats.f32CompressedBytes >= stats.f32LogicalBytes ||
                    stats.encodedTensorCount == 0 ||
                    stats.encodedCompressedBytes >= stats.encodedLogicalBytes ||
                    stats.encodedCacheHits == 0 || stats.bytesDecoded == 0 ||
                    stats.f32ActiveReaders != 0 || stats.encodedActiveReaders != 0) {
                    std::cerr << "synthetic Deep2 inference/residency acceptance failed"
                              << " argmax=" << best
                              << " f32_tensors=" << stats.f32TensorCount
                              << " compressed=" << stats.f32CompressedBytes
                              << " logical=" << stats.f32LogicalBytes
                              << " active_readers=" << stats.f32ActiveReaders << "\n";
                    rc = 6;
                } else {
                    std::cout << "DEEP2_COMPRESSED_MODEL_E2E_PASS"
                              << " argmax=" << best
                              << " logits[0..1]=" << logits[0] << "," << logits[1]
                              << " final_logit=" << logits[outputRows - 1]
                              << " f32_compressed=" << stats.f32CompressedBytes
                              << " f32_logical=" << stats.f32LogicalBytes
                              << " encoded_compressed=" << stats.encodedCompressedBytes
                              << " encoded_logical=" << stats.encodedLogicalBytes
                              << " pager_resident=" << stats.sourcePagerResidentBytes << "\n";
                }
            }
        }
        engine.Shutdown();
    }
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    return rc;
}
