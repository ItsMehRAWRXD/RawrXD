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
};
void putTensorInfo(std::ostream& out, const Tensor& tensor) {
    putString(out, tensor.name);
    put<uint32_t>(out, static_cast<uint32_t>(tensor.dims.size()));
    for (uint64_t d : tensor.dims) put<uint64_t>(out, d);
    put<uint32_t>(out, 0); // GGML_TYPE_F32
    put<uint64_t>(out, tensor.offset);
}
bool writeFixture(const std::filesystem::path& path, std::vector<Tensor>& tensors) {
    constexpr uint64_t alignment = 32;
    uint64_t cursor = 0;
    for (auto& t : tensors) {
        cursor = alignUp(cursor, alignment);
        t.offset = cursor;
        cursor += t.values.size() * sizeof(float);
    }
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    put<uint32_t>(out, 0x46554747u);
    put<uint32_t>(out, 3);
    put<uint64_t>(out, tensors.size());
    put<uint64_t>(out, 7);
    putU64KV(out, "phi3.embedding_length", 4);
    putU64KV(out, "phi3.block_count", 1);
    putU64KV(out, "phi3.attention.head_count", 1);
    putU64KV(out, "phi3.attention.head_count_kv", 1);
    putU64KV(out, "phi3.feed_forward_length", 4);
    putU64KV(out, "phi3.context_length", 16);
    putU64KV(out, "general.alignment", alignment);
    for (const auto& t : tensors) putTensorInfo(out, t);
    const uint64_t dataStart = alignUp(static_cast<uint64_t>(out.tellp()), alignment);
    while (static_cast<uint64_t>(out.tellp()) < dataStart) out.put('\0');
    for (const auto& t : tensors) {
        while (static_cast<uint64_t>(out.tellp()) < dataStart + t.offset) out.put('\0');
        out.write(reinterpret_cast<const char*>(t.values.data()),
                  static_cast<std::streamsize>(t.values.size() * sizeof(float)));
    }
    return static_cast<bool>(out);
}
Tensor makeTensor(std::string name, std::vector<uint64_t> dims,
                  std::vector<float> values) {
    return Tensor{std::move(name), std::move(dims), std::move(values), 0};
}
}

int main() {
    constexpr size_t H = 4;
    std::vector<Tensor> tensors;

    // Token 1 -> [1, 2, 0, 0]. GGUF matrix dimensions are [columns, rows].
    std::vector<float> embedding(H * H, 0.0f);
    embedding[H + 0] = 1.0f;
    embedding[H + 1] = 2.0f;
    tensors.push_back(makeTensor("token_embd.weight", {H, H}, embedding));

    // One QKV projection: Q=0, K=0, V maps x0 -> [x0,x0] and
    // x1 -> [x1,x1], yielding [1,1,2,2] at the attention output.
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

    // Identity output projection with a stronger final row. Expected argmax=3.
    std::vector<float> output(H * H, 0.0f);
    output[0 * H + 0] = 1.0f;
    output[1 * H + 1] = 1.0f;
    output[2 * H + 2] = 1.0f;
    output[3 * H + 3] = 2.0f;
    tensors.push_back(makeTensor("output.weight", {H, H}, output));

    const auto path = std::filesystem::temp_directory_path() /
        "rawrxd_deep2_compressed_model_e2e.gguf";
    if (!writeFixture(path, tensors)) {
        std::cerr << "fixture creation failed\n";
        return 1;
    }

    int rc = 0;
    {
        Deep2Engine engine;
        if (!engine.ConfigureTensorCompression(1024 * 1024, 1024 * 1024, 0.0f)) {
            std::cerr << "compression configuration rejected\n";
            rc = 2;
        } else if (!engine.Initialize(path.string())) {
            std::cerr << "Deep2Engine failed to initialize synthetic GGUF\n";
            rc = 3;
        } else {
            std::vector<float> logits, baseline;
            if (!engine.executePhi3ROMForwardPass({1}, logits, baseline)) {
                std::cerr << "Deep2Engine synthetic Phi-3 forward pass failed\n";
                rc = 4;
            } else if (logits.size() != H || baseline.size() != H) {
                std::cerr << "unexpected synthetic model logit shape\n";
                rc = 5;
            } else {
                const auto best = static_cast<size_t>(
                    std::max_element(logits.begin(), logits.end()) - logits.begin());
                const auto stats = engine.GetTensorResidencySnapshot();
                if (best != 3 || logits != baseline ||
                    stats.f32TensorCount == 0 ||
                    stats.f32CompressedBytes >= stats.f32LogicalBytes ||
                    stats.f32ActiveReaders != 0) {
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
                              << " logits=" << logits[0] << "," << logits[1]
                              << "," << logits[2] << "," << logits[3]
                              << " f32_compressed=" << stats.f32CompressedBytes
                              << " f32_logical=" << stats.f32LogicalBytes
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
