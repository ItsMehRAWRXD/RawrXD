// REAP full tensor inventory — uses existing GGUFLoader to enumerate ALL tensors
// across all GGUF shards loaded from shard 1. Metadata-only: does not read tensor
// payloads or construct in-memory model.
//
// Output: JSON array of tensor entries with name, type, sizeBytes, dims,
// shardId, fileOffset (absolute), tensorOffset (relative), family classification.
#include "deep2/GGUFLoader.hpp"
#include "reap/ReapAutoFitIR.hpp"
#include "reap/ReapCanonicalIR.hpp"
#include "deep2/deep2_sha256.hpp"
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <iostream>
#include <map>
#include <set>
#include <algorithm>
#include <filesystem>
#include <array>
#include <sstream>
#include <iomanip>

struct TensorEntry {
    std::string name;
    uint32_t type = 0;
    uint64_t sizeBytes = 0;
    std::vector<uint64_t> dims;
    uint32_t shardId = 0;
    uint64_t fileOffset = 0;
    uint64_t tensorOffset = 0;
    std::string family;
    uint64_t expertCount = 0;
};

static std::string classifyFamily(const std::string& name, uint64_t modelExpertCount,
                                  uint64_t& expertCount) {
    expertCount = 0;
    std::string family = "other";
    if (name.find("ffn_gate_exps") != std::string::npos) { family = "expert_gate"; expertCount = modelExpertCount; }
    else if (name.find("ffn_up_exps") != std::string::npos) { family = "expert_up"; expertCount = modelExpertCount; }
    else if (name.find("ffn_down_exps") != std::string::npos) { family = "expert_down"; expertCount = modelExpertCount; }
    else if (name.find("exp_probs_b.bias") != std::string::npos) { family = "router_bias"; }
    else if (name.find("ffn_gate_inp.weight") != std::string::npos) { family = "router_input"; }
    else if (name.find("ffn_gate_shexp") != std::string::npos) { family = "shared_expert"; }
    else if (name.find("ffn_up_shexp") != std::string::npos) { family = "shared_expert"; }
    else if (name.find("ffn_down_shexp") != std::string::npos) { family = "shared_expert"; }
    else if (name.find("attn_q") != std::string::npos) { family = "attention_q"; }
    else if (name.find("attn_k") != std::string::npos) { family = "attention_k"; }
    else if (name.find("attn_v") != std::string::npos) { family = "attention_v"; }
    else if (name.find("attn_output") != std::string::npos) { family = "attention_output"; }
    else if (name.find("attn_norm") != std::string::npos) { family = "attention_norm"; }
    else if (name.find("ffn_norm") != std::string::npos) { family = "ffn_norm"; }
    else if (name.find("token_embd") != std::string::npos) { family = "embedding"; }
    else if (name.find("output.weight") != std::string::npos) { family = "output_head"; }
    else if (name.find("output_norm") != std::string::npos) { family = "output_norm"; }
    return family;
}

static std::string esc(const std::string& s) {
    std::string o;
    for (char c : s) {
        if (c == '"' || c == '\\') { o += '\\'; o += c; }
        else if (c == '\n') o += "\\n";
        else o += c;
    }
    return o;
}

static bool isExpertTensor(const std::string& name) {
    return name.find("ffn_gate_exps") != std::string::npos ||
           name.find("ffn_up_exps") != std::string::npos ||
           name.find("ffn_down_exps") != std::string::npos ||
           name.find(".experts.") != std::string::npos;
}

static uint64_t visitMultiplier(const reap::LoopSchedule& loop, const std::string& name) {
    const uint32_t layer = reap::ParseLayerIndex(name);
    return layer == UINT32_MAX ? 1 : reap::VisitMultiplicity(loop, layer);
}

static std::vector<std::filesystem::path> shardPaths(const std::filesystem::path& first) {
    const std::string name = first.filename().string();
    const size_t marker = name.find("-00001-of-");
    if (marker == std::string::npos) return {first};
    const size_t end = name.find(".gguf", marker);
    if (end == std::string::npos) return {};
    const std::string totalText = name.substr(marker + 10, end - marker - 10);
    uint32_t total = 0;
    try { total = static_cast<uint32_t>(std::stoul(totalText)); } catch (...) { return {}; }
    if (total == 0 || total > 4096) return {};
    std::vector<std::filesystem::path> out;
    const std::string prefix = name.substr(0, marker);
    for (uint32_t i = 1; i <= total; ++i) {
        std::ostringstream s;
        s << prefix << '-' << std::setw(5) << std::setfill('0') << i
          << "-of-" << std::setw(5) << std::setfill('0') << total << ".gguf";
        const auto path = first.parent_path() / s.str();
        if (!std::filesystem::is_regular_file(path)) return {};
        out.push_back(path);
    }
    return out;
}

int main(int argc, char** argv) {
    const char* path = argc > 1 ? argv[1] :
        "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M\\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf";

    const bool hashShards = argc > 2 && std::string(argv[2]) == "--hash-shards";
    Deep2::GGUFLoader loader;
    if (!loader.load(path)) {
        std::cerr << "LOAD_FAILED: " << loader.error() << "\n";
        return 2;
    }

    auto names = loader.listTensors();
    const std::string architecture = loader.getMetaString("general.architecture", "unknown");
    const auto archMeta = [&](const char* suffix, int64_t fallback = 0) -> int64_t {
        const std::string key = architecture + "." + suffix;
        const int64_t value = loader.getMetaInt(key, fallback);
        return value > 0 ? value : fallback;
    };
    const uint64_t modelExpertCount = static_cast<uint64_t>(archMeta("expert_count"));
    const uint64_t loopStart = static_cast<uint64_t>(archMeta("loop.start"));
    const uint64_t loopEnd = static_cast<uint64_t>(archMeta("loop.end"));
    const uint64_t loopCount = static_cast<uint64_t>(archMeta("loop.count"));
    const auto loop = reap::NormalizeLoop(architecture, static_cast<uint64_t>(archMeta("block_count")), loopCount, loopStart, loopEnd);
    std::cout << "{\n";
    std::cout << "  \"schema\": \"reap.full_inventory.v1\",\n";
    std::cout << "  \"model\": \"" << esc(path) << "\",\n";
    std::cout << "  \"architecture\": \"" << esc(architecture) << "\",\n";
    std::cout << "  \"architecture_metadata\": {\n";
    std::cout << "    \"embedding_length\": " << archMeta("embedding_length") << ",\n";
    std::cout << "    \"block_count\": " << archMeta("block_count") << ",\n";
    std::cout << "    \"context_length\": " << archMeta("context_length") << ",\n";
    std::cout << "    \"expert_count\": " << modelExpertCount << ",\n";
    std::cout << "    \"expert_used_count\": " << archMeta("expert_used_count") << ",\n";
    std::cout << "    \"attention_head_count\": " << archMeta("attention.head_count") << ",\n";
    std::cout << "    \"attention_head_count_kv\": " << archMeta("attention.head_count_kv") << ",\n";
    std::cout << "    \"loop_count\": " << archMeta("loop.count") << ",\n";
    std::cout << "    \"loop_start\": " << archMeta("loop.start") << ",\n";
    std::cout << "    \"loop_end\": " << archMeta("loop.end") << ",\n";
    std::cout << "    \"loop_gate_rank\": " << archMeta("loop.gate_rank") << "\n";
    std::cout << "  },\n";
    std::cout << "  \"shard_count\": " << loader.shardCount() << ",\n";
    std::cout << "  \"source_hash_scope\": \"" << (hashShards ? "all_shards_sha256" : "not_requested") << "\",\n";
    std::cout << "  \"source_shards\": [";
    const auto shards = shardPaths(std::filesystem::path(path));
    for (size_t i = 0; i < shards.size(); ++i) {
        if (i) std::cout << ',';
        std::array<uint8_t, 32> digest{};
        uint64_t bytes = 0;
        const bool ok = !hashShards || deep2::sha256_file(shards[i].string(), digest, &bytes);
        std::cout << "{\"path\":\"" << esc(shards[i].string()) << "\",\"bytes\":" << bytes
                  << ",\"sha256\":\"" << (hashShards && ok ? deep2::hex32(digest) : "") << "\"}";
    }
    std::cout << "],\n";
    std::cout << "  \"total_logical_tensors\": " << loader.tensorCount() << ",\n";
    std::cout << "  \"ir_contract\": \"rawrxd.reap.autofit.ir.v1\",\n";
    std::cout << "  \"ir_semantics\": {\"physical_layer_identity\":true,\"visit_multiplier\":true,\"recurrent\":true,\"prunable\":true,\"dtype_accounting\":true},\n";
    std::cout << "  \"tensors\": [\n";

    bool first = true;
    uint64_t totalBytes = 0;
    uint64_t packedExpertBytes = 0;
    uint64_t nonExpertBytes = 0;
    std::map<std::string, uint64_t> familyBytes;
    std::map<std::string, uint64_t> familyCount;
    std::set<std::string> seenNames;
    bool duplicateFound = false;

    for (const auto& name : names) {
        const auto* t = loader.getTensor(name);
        if (!t) continue;

        if (!seenNames.insert(name).second) {
            duplicateFound = true;
            std::cerr << "DUPLICATE TENSOR: " << name << "\n";
        }

        uint64_t tensorExpertCount = 0;
        std::string family = classifyFamily(name, modelExpertCount, tensorExpertCount);

        if (!first) std::cout << ",\n";
        first = false;

        const bool prunable = isExpertTensor(name);
        const uint64_t visits = visitMultiplier(loop, name);
        totalBytes += t->sizeBytes;
        familyBytes[family] += t->sizeBytes;
        familyCount[family] += 1;
        if (prunable) packedExpertBytes += t->sizeBytes;
        else nonExpertBytes += t->sizeBytes;

        std::cout << "    {\n";
        std::cout << "      \"name\": \"" << esc(name) << "\",\n";
        std::cout << "      \"type\": " << static_cast<uint32_t>(t->type) << ",\n";
        std::cout << "      \"size_bytes\": " << t->sizeBytes << ",\n";
        std::cout << "      \"dims\": [";
        for (size_t i = 0; i < t->shape.size(); ++i) {
            if (i) std::cout << ", ";
            std::cout << t->shape[i];
        }
        std::cout << "],\n";
        std::cout << "      \"shard_id\": " << t->shardId << ",\n";
        std::cout << "      \"file_offset\": " << t->fileOffset << ",\n";
        std::cout << "      \"tensor_offset\": " << t->tensorOffset << ",\n";
        std::cout << "      \"family\": \"" << family << "\",\n";
        std::cout << "      \"expert_count\": " << tensorExpertCount << ",\n";
        std::cout << "      \"physical_key\": \"" << esc(name) << "\",\n";
        std::cout << "      \"visit_multiplier\": " << visits << ",\n";
        std::cout << "      \"prunable\": " << (prunable ? "true" : "false") << ",\n";
        std::cout << "      \"recurrent\": " << (visits > 1 ? "true" : "false") << ",\n";
        std::cout << "      \"storage_dtype\": " << static_cast<uint32_t>(t->type) << ",\n";
        std::cout << "      \"scale_granularity\": \"UNKNOWN\"\n";
        std::cout << "    }";
    }

    std::cout << "\n  ],\n";

    // Family summary
    std::cout << "  \"family_summary\": {\n";
    bool famFirst = true;
    for (const auto& [fam, bytes] : familyBytes) {
        if (!famFirst) std::cout << ",\n";
        famFirst = false;
        std::cout << "    \"" << esc(fam) << "\": {\"bytes\": " << bytes
                  << ", \"count\": " << familyCount[fam] << "}";
    }
    std::cout << "\n  },\n";

    // Totals
    std::cout << "  \"totals\": {\n";
    std::cout << "    \"total_bytes\": " << totalBytes << ",\n";
    std::cout << "    \"packed_expert_bytes\": " << packedExpertBytes << ",\n";
    std::cout << "    \"nonexpert_bytes\": " << nonExpertBytes << ",\n";
    std::cout << "    \"duplicate_tensors\": " << (duplicateFound ? "true" : "false") << "\n";
    std::cout << "  }\n";

    std::cout << "}\n";
    return duplicateFound ? 2 : 0;
}
