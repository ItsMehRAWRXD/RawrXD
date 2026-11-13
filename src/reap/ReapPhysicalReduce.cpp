#include "reap/ReapPhysicalReduce.hpp"

#include "deep2/GGUFLoader.hpp"
#include "deep2/ReapPhysicalBank.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <sstream>
#include <vector>

namespace RawrXD::Reap {
namespace {

namespace fs = std::filesystem;

enum class TensorClass : uint8_t {
    RoutedExps,
    Keep
};

TensorClass classifyTensor(const std::string& name) {
    if (name.find("ffn_gate_exps") != std::string::npos ||
        name.find("ffn_up_exps") != std::string::npos ||
        name.find("ffn_down_exps") != std::string::npos)
        return TensorClass::RoutedExps;
    return TensorClass::Keep;
}

bool listShardPaths(const fs::path& first, std::vector<fs::path>& out,
                    std::string& error) {
    out.clear();
    std::error_code ec;
    if (!fs::is_regular_file(first, ec)) {
        error = "PHYSICAL_FIRST_SHARD_MISSING";
        return false;
    }
    const std::string name = first.filename().string();
    const auto marker = name.find("-00001-of-");
    if (marker == std::string::npos) {
        out.push_back(first);
        return true;
    }
    const std::string prefix = name.substr(0, marker);
    for (auto& ent : fs::directory_iterator(first.parent_path(), ec)) {
        if (ec || !ent.is_regular_file(ec)) continue;
        const std::string fn = ent.path().filename().string();
        if (fn.rfind(prefix, 0) == 0 && ent.path().extension() == ".gguf")
            out.push_back(ent.path());
    }
    std::sort(out.begin(), out.end());
    if (out.empty()) {
        error = "PHYSICAL_NO_SHARDS_FOUND";
        return false;
    }
    return true;
}

} // namespace

bool BuildPhysicalReducePlan(const RuntimePlan& runtime,
                             PhysicalReducePlan& out,
                             std::string& error) {
    out = {};
    error.clear();
    out.sourceImmutable = true;
    out.topK = runtime.requested.expertCount;
    out.originalExpertCount = runtime.actual.expertCount;

    if (runtime.actual.expertCount == 0) {
        out.mode = "RESIDENCY_ONLY";
        out.reason = "DENSE_OR_NO_MOE_TOPOLOGY";
        return true;
    }
    if (runtime.direction != "DOWNSIZE" && runtime.direction != "MIXED") {
        out.mode = "RESIDENCY_ONLY";
        out.reason = "NO_DOWNSIZE_PHYSICAL_REDUCE";
        return true;
    }

    std::vector<fs::path> shards;
    if (!listShardPaths(fs::path(runtime.actual.model), shards, error))
        return false;

    Deep2::GGUFLoadOptions options{};
    options.mmap = false;
    options.loadTensors = false;
    options.verbose = false;

    uint64_t disk = 0;
    uint64_t routed = 0;
    uint64_t keep = 0;
    uint64_t tensorCount = 0;
    uint32_t metaLayers = 0;
    uint32_t denseLead = 1;
    uint32_t expertCount = static_cast<uint32_t>(runtime.actual.expertCount);

    for (const auto& shard : shards) {
        std::error_code ec;
        disk += static_cast<uint64_t>(fs::file_size(shard, ec));
        Deep2::GGUFLoadResult result =
            Deep2::GGUFLoader::Load(shard.string().c_str(), options);
        if (!result.success) {
            error = std::string("PHYSICAL_SHARD_INVENTORY_FAILED:") +
                    shard.filename().string() + ":" + result.error;
            return false;
        }
        if (result.metadata.numLayers)
            metaLayers = result.metadata.numLayers;
        if (result.metadata.leadingDenseBlockCount)
            denseLead = result.metadata.leadingDenseBlockCount;
        if (result.metadata.numExperts)
            expertCount = result.metadata.numExperts;
        for (const auto& tensor : result.tensors) {
            const uint64_t bytes = static_cast<uint64_t>(tensor.size);
            ++tensorCount;
            if (classifyTensor(tensor.name) == TensorClass::RoutedExps)
                routed += bytes;
            else
                keep += bytes;
        }
    }

    out.originalModelBytes = disk ? disk : runtime.actual.tensorBytes;
    out.originalExpertCount = expertCount ? expertCount
                                          : runtime.actual.expertCount;
    out.expertBytes = routed;
    out.sharedBytes = keep;
    out.moeLayerCount = (metaLayers > denseLead)
        ? (metaLayers - denseLead)
        : (runtime.actual.layerCount > 1 ? runtime.actual.layerCount - 1 : 1);

    const uint64_t E = (std::max)(uint64_t{1}, out.originalExpertCount);
    const uint64_t bytesPerExpertAllLayers = routed / E;
    if (!bytesPerExpertAllLayers) {
        error = "PHYSICAL_ROUTED_EXPERT_BYTES_ZERO";
        return false;
    }

    const uint64_t budget = runtime.targetWorkingSetBytes
        ? runtime.targetWorkingSetBytes
        : runtime.requested.parameterCount;

    uint64_t retained = out.topK;
    if (budget > keep)
        retained = (budget - keep) / bytesPerExpertAllLayers;
    if (retained < out.topK) retained = out.topK;
    if (retained > E) retained = E;

    out.retainedExpertsPerLayer = retained;
    out.retainedExpertSlices = retained * out.moeLayerCount;
    /* Honest scope: keep tensors + retained routed expert slices only. */
    out.repackedModelBytes = keep + bytesPerExpertAllLayers * retained;
    out.prunedParameterEstimate =
        bytesPerExpertAllLayers * (E - retained);
    out.activeParametersPerToken =
        out.topK *
        (bytesPerExpertAllLayers / (std::max)(out.moeLayerCount, uint64_t{1}));

    out.enabled = true;
    out.physicalRepresentation = true;
    out.mode = "PHYSICAL_STREAM";
    out.selectionPolicy = "BUDGET_UNIFORM_UNCERTIFIED";
    out.reason = "ALL_SHARDS_ROUTED_EXPERT_INVENTORY_BUDGET_REDUCE";
    (void)tensorCount;
    return true;
}

void ApplyPhysicalReducePlan(const PhysicalReducePlan& plan) {
    Deep2::ReapPhysicalBankState st{};
    st.active = plan.enabled && plan.physicalRepresentation;
    st.retainedPerLayer =
        static_cast<uint32_t>(plan.retainedExpertsPerLayer);
    st.originalModelBytes = plan.originalModelBytes;
    st.originalExpertCount = plan.originalExpertCount;
    st.retainedSlices = plan.retainedExpertSlices;
    st.prunedParamEstimate = plan.prunedParameterEstimate;
    st.repackedModelBytes = plan.repackedModelBytes;
    st.topK = plan.topK;
    std::snprintf(st.mode, sizeof(st.mode), "%s", plan.mode.c_str());
    std::snprintf(st.selectionPolicy, sizeof(st.selectionPolicy), "%s",
                  plan.selectionPolicy.c_str());
    Deep2::ReapPhysicalBankInstall(st);
}

void ClearPhysicalReducePlan() { Deep2::ReapPhysicalBankClear(); }

std::string PhysicalReduceReceiptJson(const PhysicalReducePlan& plan) {
    std::ostringstream o;
    o << "{\"physical_reduce\":"
      << (plan.physicalRepresentation ? "true" : "false")
      << ",\"mode\":\"" << plan.mode << "\""
      << ",\"selection_policy\":\"" << plan.selectionPolicy << "\""
      << ",\"INVENTORY_METHOD\":\"ALL_SHARDS_GGUF_TENSOR_SIZE\""
      << ",\"REPACKED_SCOPE\":\"SHARED_KEEP_PLUS_RETAINED_ROUTED_EXPERTS\""
      << ",\"ACCOUNTING_COMPLETE\":1"
      << ",\"ORIGINAL_MODEL_BYTES\":" << plan.originalModelBytes
      << ",\"ORIGINAL_EXPERT_COUNT\":" << plan.originalExpertCount
      << ",\"ROUTED_EXPERT_BYTES\":" << plan.expertBytes
      << ",\"SHARED_KEEP_BYTES\":" << plan.sharedBytes
      << ",\"RETAINED_EXPERT_COUNT\":" << plan.retainedExpertsPerLayer
      << ",\"RETAINED_EXPERT_SLICES\":" << plan.retainedExpertSlices
      << ",\"PRUNED_ROUTED_EXPERT_BYTES\":" << plan.prunedParameterEstimate
      << ",\"REPACKED_MODEL_BYTES\":" << plan.repackedModelBytes
      << ",\"ACTIVE_PARAMETERS_PER_TOKEN\":"
      << plan.activeParametersPerToken
      << ",\"MOE_LAYER_COUNT\":" << plan.moeLayerCount
      << ",\"TOP_K\":" << plan.topK
      << ",\"source_immutable\":"
      << (plan.sourceImmutable ? "true" : "false")
      << ",\"writer_invoked\":"
      << (plan.writerInvoked ? "true" : "false")
      << ",\"reason\":\"" << plan.reason << "\""
      << ",\"PROMOTE\":0,\"CERTIFIED\":0"
      << ",\"NOTE\":\"REPACKED_MODEL_BYTES_IS_NOT_A_CERTIFIED_STANDALONE_GGUF\"}";
    return o.str();
}

} // namespace RawrXD::Reap
