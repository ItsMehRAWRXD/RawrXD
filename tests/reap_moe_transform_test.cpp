#include "deep2/GGUFLoader.hpp"
#include "deep2/ReapMoETransformer.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

void put(std::ofstream& out, const void* data, size_t bytes) {
    out.write(static_cast<const char*>(data), static_cast<std::streamsize>(bytes));
}

template <typename T>
void put(std::ofstream& out, T value) {
    put(out, &value, sizeof(value));
}

void stringValue(std::ofstream& out, const std::string& value) {
    put(out, static_cast<uint64_t>(value.size()));
    put(out, value.data(), value.size());
}

uint64_t alignUp(uint64_t value, uint64_t alignment) {
    const uint64_t rem = value % alignment;
    return rem ? value + alignment - rem : value;
}

std::vector<uint8_t> readAll(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
}

bool writeFixture(const fs::path& path) {
    struct Tensor {
        std::string name;
        std::vector<uint64_t> dims;
        uint64_t offset = 0;
        std::vector<uint8_t> bytes;
    };

    std::vector<Tensor> tensors = {
        {"blk.0.ffn_gate_exps.weight", {4, 2}},
        {"blk.0.ffn_up_exps.weight", {4, 2}},
        {"blk.0.ffn_down_exps.weight", {4, 2}},
        {"blk.0.ffn_gate_inp.weight", {4, 2}},
        {"blk.0.exp_probs_b.bias", {2}},
        {"token_embd.weight", {4, 4}},
        {"output_norm.weight", {4}},
    };
    uint8_t marker = 1;
    for (auto& tensor : tensors) {
        uint64_t elements = 1;
        for (uint64_t dim : tensor.dims) elements *= dim;
        tensor.bytes.resize(static_cast<size_t>(elements * sizeof(float)));
        for (auto& byte : tensor.bytes) byte = marker++;
    }

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    put(out, uint32_t{0x46554747}); // GGUF
    put(out, uint32_t{3});
    put(out, static_cast<uint64_t>(tensors.size()));
    put(out, uint64_t{2});

    stringValue(out, "general.alignment");
    put(out, uint32_t{4}); // UINT32
    put(out, uint32_t{32});
    stringValue(out, "general.architecture");
    put(out, uint32_t{8}); // STRING
    stringValue(out, "deepseek2");

    uint64_t cursor = 0;
    for (auto& tensor : tensors) {
        tensor.offset = alignUp(cursor, 32);
        cursor = tensor.offset + tensor.bytes.size();
        stringValue(out, tensor.name);
        put(out, static_cast<uint32_t>(tensor.dims.size()));
        for (uint64_t dim : tensor.dims) put(out, dim);
        put(out, uint32_t{0}); // GGML_TYPE_F32
        put(out, tensor.offset);
    }
    const uint64_t dataStart = alignUp(static_cast<uint64_t>(out.tellp()), 32);
    const uint64_t headerEnd = static_cast<uint64_t>(out.tellp());
    if (dataStart < headerEnd) return false;
    std::vector<uint8_t> zeros(static_cast<size_t>(dataStart - headerEnd), 0);
    put(out, zeros.data(), zeros.size());
    for (const auto& tensor : tensors) {
        const uint64_t current = static_cast<uint64_t>(out.tellp());
        const uint64_t expected = dataStart + tensor.offset;
        if (current > expected) return false;
        std::vector<uint8_t> padding(static_cast<size_t>(expected - current), 0);
        put(out, padding.data(), padding.size());
        put(out, tensor.bytes.data(), tensor.bytes.size());
    }
    out.flush();
    return out.good();
}

bool writeSelection(const fs::path& path) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out << R"({
  "schema": "RAWRXD_REAP_EXPERT_SELECTION_001",
  "status": "CANDIDATE",
  "model": "fixture",
  "active_experts": 1,
  "reference_parity_pass": true,
  "rewrite_authorized": true,
  "layers": [{"layer": 0, "selected": [{"expert": 1, "score": 1.0}]}]
}
)";
    return out.good();
}

bool equalSlice(const Deep2::GGUFTensor* source, const Deep2::GGUFTensor* output) {
    if (!source || !output || source->shape.back() != 2 || output->shape.back() != 1)
        return false;
    const size_t stride = source->sizeBytes / 2;
    return output->sizeBytes == stride &&
           std::equal(source->data + stride, source->data + stride * 2, output->data);
}

} // namespace

int main() {
    const fs::path root = fs::temp_directory_path() / "rawrxd_reap_moe_transform_test";
    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(root, ec);
    const fs::path source = root / "fixture.gguf";
    const fs::path selection = root / "selection.json";
    const fs::path output = root / "candidate";
    if (!writeFixture(source) || !writeSelection(selection)) {
        std::cerr << "FIXTURE_WRITE_FAIL\n";
        return 1;
    }
    const auto before = readAll(source);

    Deep2::ReapMoETransformRequest request;
    request.sourceFirstShard = source.string();
    request.outputDirectory = output.string();
    request.selectionManifest = selection.string();
    request.activeExperts = 1;
    request.targetSizeBytes = 4096;
    const auto result = Deep2::transformMoEGGUF(request);
    if (!result.success || result.outputFirstShard.empty() ||
        result.outputBytes > request.targetSizeBytes) {
        std::cerr << "TRANSFORM_FAIL " << result.error << "\n";
        return 2;
    }
    if (readAll(source) != before) {
        std::cerr << "SOURCE_MUTATED\n";
        return 3;
    }

    Deep2::GGUFLoader sourceLoader;
    Deep2::GGUFLoader outputLoader;
    if (!sourceLoader.load(source.string()) || !outputLoader.load(result.outputFirstShard)) {
        std::cerr << "RELOAD_FAIL\n";
        return 4;
    }
    if (!equalSlice(sourceLoader.getTensor("blk.0.ffn_gate_exps.weight"),
                    outputLoader.getTensor("blk.0.ffn_gate_exps.weight")) ||
        !equalSlice(sourceLoader.getTensor("blk.0.ffn_up_exps.weight"),
                    outputLoader.getTensor("blk.0.ffn_up_exps.weight")) ||
        !equalSlice(sourceLoader.getTensor("blk.0.ffn_down_exps.weight"),
                    outputLoader.getTensor("blk.0.ffn_down_exps.weight")) ||
        !equalSlice(sourceLoader.getTensor("blk.0.ffn_gate_inp.weight"),
                    outputLoader.getTensor("blk.0.ffn_gate_inp.weight")) ||
        !equalSlice(sourceLoader.getTensor("blk.0.exp_probs_b.bias"),
                    outputLoader.getTensor("blk.0.exp_probs_b.bias"))) {
        std::cerr << "SELECTED_SLICE_MISMATCH\n";
        return 5;
    }
    if (sourceLoader.tensorCount() != outputLoader.tensorCount() ||
        outputLoader.shardCount() != 1 ||
        outputLoader.getMetaInt("rawrxd.reap.active_experts", 0) != 1) {
        std::cerr << "OUTPUT_INVENTORY_MISMATCH\n";
        return 6;
    }
    const fs::path tooSmall = root / "candidate_too_small";
    Deep2::ReapMoETransformRequest rejected = request;
    rejected.outputDirectory = tooSmall.string();
    rejected.targetSizeBytes = 100;
    const auto rejectedResult = Deep2::transformMoEGGUF(rejected);
    if (rejectedResult.success ||
        rejectedResult.error.find("exceeds target size") == std::string::npos ||
        fs::exists(tooSmall)) {
        std::cerr << "TARGET_ENFORCEMENT_FAIL " << rejectedResult.error << "\n";
        return 7;
    }
    const fs::path existing = root / "candidate_existing";
    fs::create_directories(existing, ec);
    rejected.outputDirectory = existing.string();
    const auto existingResult = Deep2::transformMoEGGUF(rejected);
    if (existingResult.success ||
        existingResult.error.find("exceeds target size") == std::string::npos ||
        !fs::exists(existing) ||
        fs::directory_iterator(existing, ec) != fs::directory_iterator()) {
        std::cerr << "EXISTING_TARGET_ENFORCEMENT_FAIL " << existingResult.error << "\n";
        return 8;
    }
    std::cout << "REAP_MOE_TRANSFORM_PASS\n"
              << "SOURCE_BYTES=" << before.size() << "\n"
              << "OUTPUT_BYTES=" << result.outputBytes << "\n"
              << "TRANSFORMED_TENSORS=" << result.transformedTensors << "\n"
              << "SOURCE_UNCHANGED=1\n"
              << "RELOAD_PASS=1\n"
              << "TARGET_ENFORCEMENT_PASS=1\n"
              << "PARTIAL_OUTPUT_ROLLBACK_PASS=1\n";
    fs::remove_all(root, ec);
    return 0;
}
