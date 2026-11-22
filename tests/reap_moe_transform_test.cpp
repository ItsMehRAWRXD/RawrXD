#include "deep2/GGUFLoader.hpp"
#include "deep2/ReapMoETransformer.hpp"
#include "deep2/ReapQ4KToQ2K.hpp"

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

bool writeFixture(const fs::path& path, bool quantized=false) {
    struct Tensor {
        std::string name;
        std::vector<uint64_t> dims;
        uint64_t offset = 0;
        std::vector<uint8_t> bytes;
        uint32_t type=0;
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
        if (quantized && tensor.name.find("_exps.weight")!=std::string::npos) {
            tensor.dims={256,1,2};
            tensor.type=12;
            Deep2::ReapQuant::Q4Block block{};
            Deep2::ReapQuant::StoreHalf(block.data(),0x3c00);
            for (unsigned i=4;i<16;++i) block[i]=1;
            for (unsigned i=16;i<144;++i) block[i]=static_cast<uint8_t>(i);
            tensor.bytes.insert(tensor.bytes.end(),block.begin(),block.end());
            for (unsigned i=16;i<144;++i) block[i]^=0x5a;
            tensor.bytes.insert(tensor.bytes.end(),block.begin(),block.end());
            continue;
        }
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
    put(out, uint64_t{4});

    stringValue(out, "general.alignment");
    put(out, uint32_t{4}); // UINT32
    put(out, uint32_t{32});
    stringValue(out, "general.architecture");
    put(out, uint32_t{8}); // STRING
    stringValue(out, "deepseek2");
    stringValue(out, "deepseek2.expert_count");
    put(out,uint32_t{4}); put(out,uint32_t{2});
    stringValue(out, "deepseek2.expert_used_count");
    put(out,uint32_t{4}); put(out,uint32_t{1});

    uint64_t cursor = 0;
    for (auto& tensor : tensors) {
        tensor.offset = alignUp(cursor, 32);
        cursor = tensor.offset + tensor.bytes.size();
        stringValue(out, tensor.name);
        put(out, static_cast<uint32_t>(tensor.dims.size()));
        for (uint64_t dim : tensor.dims) put(out, dim);
        put(out, tensor.type);
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
    const auto inspection = Deep2::inspectMoEGGUFBudget(source.string(),4096);
    if (!inspection.success || inspection.originalExperts!=2 ||
        inspection.topK!=1 || inspection.groups!=1 || inspection.groupsUsed!=1 ||
        inspection.maxRetained!=2 || inspection.routedLayers!=std::vector<uint32_t>{0} ||
        fs::exists(output) || readAll(source)!=before) {
        std::cerr<<"READ_ONLY_INSPECTION_FAIL "<<inspection.error<<"\n";
        return 10;
    }

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
        outputLoader.getMetaInt("deepseek2.expert_count", 0) != 1 ||
        outputLoader.getMetaInt("deepseek2.expert_used_count", 0) != 1) {
        std::cerr << "OUTPUT_INVENTORY_MISMATCH\n";
        return 6;
    }
    // The complete physical writer must agree with preflight at the exact
    // serialized boundary, not just under an arbitrary generous budget.
    Deep2::ReapMoETransformRequest exact = request;
    exact.outputDirectory = (root / "candidate_exact").string();
    exact.targetSizeBytes = result.outputBytes;
    const auto exactResult = Deep2::transformMoEGGUF(exact);
    if (!exactResult.success || exactResult.outputBytes != result.outputBytes) {
        std::cerr << "EXACT_BUDGET_FAIL " << exactResult.error << "\n";
        return 9;
    }
    const auto boundary = Deep2::inspectMoEGGUFBudget(source.string(),result.outputBytes);
    const auto impossible = Deep2::inspectMoEGGUFBudget(source.string(),result.outputBytes-1);
    if (!boundary.success || boundary.minimumBytes!=result.outputBytes ||
        boundary.predictedBytes!=result.outputBytes || !boundary.maxRetained ||
        !impossible.success || impossible.maxRetained!=0 || impossible.predictedBytes!=0 ||
        impossible.minimumBytes!=result.outputBytes || readAll(source)!=before) {
        std::cerr<<"INSPECTION_WRITER_BOUNDARY_MISMATCH\n";
        return 11;
    }
    const fs::path tooSmall = root / "candidate_too_small";
    Deep2::ReapMoETransformRequest rejected = request;
    rejected.outputDirectory = tooSmall.string();
    rejected.targetSizeBytes = result.outputBytes - 1;
    const auto rejectedResult = Deep2::transformMoEGGUF(rejected);
    if (rejectedResult.success ||
        rejectedResult.error.find("max_uniform_retained_at_current_dtype=0") == std::string::npos ||
        fs::exists(tooSmall)) {
        std::cerr << "TARGET_ENFORCEMENT_FAIL " << rejectedResult.error << "\n";
        return 7;
    }
    const fs::path existing = root / "candidate_existing";
    fs::create_directories(existing, ec);
    rejected.outputDirectory = existing.string();
    const auto existingResult = Deep2::transformMoEGGUF(rejected);
    if (existingResult.success ||
        existingResult.error.find("max_uniform_retained_at_current_dtype=0") == std::string::npos ||
        !fs::exists(existing) ||
        fs::directory_iterator(existing, ec) != fs::directory_iterator()) {
        std::cerr << "EXISTING_TARGET_ENFORCEMENT_FAIL " << existingResult.error << "\n";
        return 8;
    }
    const fs::path quantSource=root/"quant_fixture.gguf";
    if (!writeFixture(quantSource,true)) return 12;
    const auto quantBefore=readAll(quantSource);
    const auto quantBudget=Deep2::inspectMoEGGUFBudget(quantSource.string(),4096,true);
    const auto originalBudget=Deep2::inspectMoEGGUFBudget(quantSource.string(),4096);
    if (!quantBudget.success || !originalBudget.success ||
        quantBudget.requantizableTensors!=3 ||
        quantBudget.minimumBytes>=originalBudget.minimumBytes) return 13;
    Deep2::ReapMoETransformRequest quantRequest=request;
    quantRequest.sourceFirstShard=quantSource.string();
    quantRequest.outputDirectory=(root/"candidate_q2").string();
    quantRequest.requantizeQ4KToQ2K=true;
    quantRequest.maxQuantRelativeRmse=1.0;
    quantRequest.targetSizeBytes=quantBudget.minimumBytes;
    const auto quantOutput=Deep2::transformMoEGGUF(quantRequest);
    if (!quantOutput.success || quantOutput.outputBytes!=quantBudget.minimumBytes ||
        quantOutput.requantizedBlocks!=3 || readAll(quantSource)!=quantBefore) {
        std::cerr<<"Q2_TRANSFORM_FAIL "<<quantOutput.error<<"\n";return 14;
    }
    Deep2::GGUFLoader q4Loader,q2Loader;
    if (!q4Loader.load(quantSource.string()) || !q2Loader.load(quantOutput.outputFirstShard)) return 15;
    const auto* q4=q4Loader.getTensor("blk.0.ffn_gate_exps.weight");
    const auto* q2=q2Loader.getTensor("blk.0.ffn_gate_exps.weight");
    if (!q4 || !q2 || q4->sizeBytes!=288 || q2->sizeBytes!=84 ||
        static_cast<uint32_t>(q2->type)!=10 || q2->shape.back()!=1) return 16;
    Deep2::ReapQuant::Q4Block selectedBlock{};
    std::copy_n(q4->data+144,144,selectedBlock.begin());
    Deep2::ReapQuant::Q2Block expectedBlock{};
    Deep2::ReapQuant::Error error;
    if (!Deep2::ReapQuant::Convert(selectedBlock,expectedBlock,error) ||
        !std::equal(expectedBlock.begin(),expectedBlock.end(),q2->data) ||
        !equalSlice(q4Loader.getTensor("blk.0.ffn_gate_inp.weight"),
                    q2Loader.getTensor("blk.0.ffn_gate_inp.weight"))) return 17;
    quantRequest.outputDirectory=(root/"candidate_q2_rejected").string();
    quantRequest.maxQuantRelativeRmse=0;
    const auto quantRejected=Deep2::transformMoEGGUF(quantRequest);
    if (quantRejected.success || fs::exists(quantRequest.outputDirectory) ||
        quantRejected.error.find("requantization error limit exceeded")==std::string::npos ||
        readAll(quantSource)!=quantBefore) return 18;
    std::cout << "NATIVE_Q2_TRANSFORM_PASS\n";
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
