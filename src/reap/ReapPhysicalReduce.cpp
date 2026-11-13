#include "reap/ReapPhysicalReduce.hpp"

#include "deep2/GGUFLoader.hpp"
#include "deep2/ReapPhysicalBank.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <sstream>

namespace RawrXD::Reap {
namespace {

bool isExpertTensor(const std::string& name) {
    return name.find("_exps.") != std::string::npos ||
           name.find("ffn_gate_inp") != std::string::npos ||
           name.find("exp_probs_b") != std::string::npos;
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
    out.originalModelBytes = runtime.actual.tensorBytes;
    /* Prefer on-disk shard sum for ORIGINAL_MODEL_BYTES (full Kimi ≈578GiB). */
    {
        namespace fs = std::filesystem;
        std::error_code ec;
        const fs::path first(runtime.actual.model);
        uint64_t disk = 0;
        if (fs::is_regular_file(first, ec)) {
            const std::string name = first.filename().string();
            const auto marker = name.find("-00001-of-");
            if (marker != std::string::npos) {
                const std::string prefix = name.substr(0, marker);
                for (auto& ent : fs::directory_iterator(first.parent_path(), ec)) {
                    if (ec || !ent.is_regular_file(ec)) continue;
                    const std::string fn = ent.path().filename().string();
                    if (fn.rfind(prefix, 0) == 0 &&
                        ent.path().extension() == ".gguf")
                        disk += static_cast<uint64_t>(ent.file_size(ec));
                }
            } else {
                disk = static_cast<uint64_t>(fs::file_size(first, ec));
            }
        }
        if (disk > out.originalModelBytes) out.originalModelBytes = disk;
    }

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

    Deep2::GGUFLoadOptions options{};
    options.mmap = false;
    options.loadTensors = false;
    options.verbose = false;
    Deep2::GGUFLoadResult result =
        Deep2::GGUFLoader::Load(runtime.actual.model.c_str(), options);
    if (!result.success) {
        error = std::string("PHYSICAL_INVENTORY_FAILED:") + result.error;
        return false;
    }

    uint64_t expertBytes = 0;
    uint64_t sharedBytes = 0;
    for (const auto& tensor : result.tensors) {
        const uint64_t bytes = static_cast<uint64_t>(tensor.size);
        if (isExpertTensor(tensor.name)) expertBytes += bytes;
        else sharedBytes += bytes;
    }
    /* Prefer metadata layer geometry over first-shard tensor sampling.
     * Split Kimi GGUFs expose only a subset of tensors in shard 0. */
    uint64_t moeLayers = 0;
    if (result.metadata.numLayers > 1) {
        const uint32_t denseLead =
            result.metadata.leadingDenseBlockCount
                ? result.metadata.leadingDenseBlockCount
                : 1u;
        moeLayers = result.metadata.numLayers > denseLead
            ? result.metadata.numLayers - denseLead
            : result.metadata.numLayers;
    } else if (runtime.actual.layerCount > 1) {
        moeLayers = runtime.actual.layerCount - 1;
    } else {
        moeLayers = 1;
    }

    out.expertBytes = expertBytes;
    out.sharedBytes = sharedBytes ? sharedBytes
                                  : runtime.actual.tensorBytes / 10;
    out.moeLayerCount = moeLayers;

    const uint64_t E = (std::max)(uint64_t{1}, runtime.actual.expertCount);
    const uint64_t bytesPerExpertAllLayers =
        expertBytes ? (expertBytes / E)
                    : (runtime.actual.tensorBytes / E);
    const uint64_t budget = runtime.targetWorkingSetBytes
        ? runtime.targetWorkingSetBytes
        : runtime.requested.parameterCount;

    uint64_t retained = out.topK;
    if (budget > out.sharedBytes && bytesPerExpertAllLayers > 0) {
        retained = (budget - out.sharedBytes) / bytesPerExpertAllLayers;
    }
    if (retained < out.topK) retained = out.topK;
    if (retained > E) retained = E;

    out.retainedExpertsPerLayer = retained;
    out.retainedExpertSlices = retained * moeLayers;
    out.repackedModelBytes =
        out.sharedBytes + bytesPerExpertAllLayers * retained;
    out.prunedParameterEstimate =
        (E > retained) ? bytesPerExpertAllLayers * (E - retained) : 0;
    out.activeParametersPerToken =
        out.topK *
        (bytesPerExpertAllLayers / (std::max)(moeLayers, uint64_t{1}));

    out.enabled = true;
    out.physicalRepresentation = true;
    out.mode = "PHYSICAL_STREAM";
    out.selectionPolicy = "BUDGET_UNIFORM_UNCERTIFIED";
    out.reason = "PHYSICAL_EXPERT_SET_DERIVED_FROM_WORKING_SET_BUDGET";
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
      << ",\"ORIGINAL_MODEL_BYTES\":" << plan.originalModelBytes
      << ",\"ORIGINAL_EXPERT_COUNT\":" << plan.originalExpertCount
      << ",\"RETAINED_EXPERT_COUNT\":" << plan.retainedExpertsPerLayer
      << ",\"RETAINED_EXPERT_SLICES\":" << plan.retainedExpertSlices
      << ",\"PRUNED_PARAMETER_COUNT\":" << plan.prunedParameterEstimate
      << ",\"REPACKED_MODEL_BYTES\":" << plan.repackedModelBytes
      << ",\"ACTIVE_PARAMETERS_PER_TOKEN\":"
      << plan.activeParametersPerToken
      << ",\"SHARED_BYTES\":" << plan.sharedBytes
      << ",\"EXPERT_BYTES\":" << plan.expertBytes
      << ",\"MOE_LAYER_COUNT\":" << plan.moeLayerCount
      << ",\"TOP_K\":" << plan.topK
      << ",\"source_immutable\":"
      << (plan.sourceImmutable ? "true" : "false")
      << ",\"writer_invoked\":"
      << (plan.writerInvoked ? "true" : "false")
      << ",\"reason\":\"" << plan.reason << "\""
      << ",\"PROMOTE\":0,\"CERTIFIED\":0}";
    return o.str();
}

} // namespace RawrXD::Reap
