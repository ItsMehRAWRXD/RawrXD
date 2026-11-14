#include "reap/ReapPhysicalReduce.hpp"

#include "reap/ReapPhysicalReduceCalib.hpp"
#include "reap/ReapPhysicalReduceExport.hpp"
#include "deep2/GGUFLoader.hpp"
#include "deep2/ReapPhysicalBank.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
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

    /* F-tree GGUFLoadOptions is global (::), not Deep2::. loadTensors=true
       with mmap=true enumerates TensorInfo.size without heap-copying payloads
       (F's loadTensors=false clears tensors and would zero the inventory). */
    ::GGUFLoadOptions options{};
    options.mmap = true;
    options.loadTensors = true;
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
    }
    /* F GGUFLoader::Load on -00001-of-N opens the full shard set once.
       Loading every shard path would triple-count tensor sizes. */
    {
        Deep2::GGUFLoadResult result =
            Deep2::GGUFLoader::Load(shards.front().string().c_str(), options);
        if (!result.success) {
            error = std::string("PHYSICAL_SHARD_INVENTORY_FAILED:") +
                    shards.front().filename().string() + ":" + result.error;
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

    /* Explicit Tip15-bind / experiment override (still source-immutable). */
    const char* forceRet = std::getenv("RAWRXD_REAP_RETAINED");
    bool forced = false;
    if (forceRet && forceRet[0]) {
        char* end = nullptr;
        unsigned long long v = std::strtoull(forceRet, &end, 10);
        if (end != forceRet && v >= out.topK && v <= E) {
            retained = static_cast<uint64_t>(v);
            forced = true;
        }
    }

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
    out.selectionPolicy = forced ? "FORCED_RETAINED_OVERRIDE_UNCERTIFIED"
                                 : "BUDGET_UNIFORM_UNCERTIFIED";
    out.reason = forced
        ? "RAWRXD_REAP_RETAINED_OVERRIDE_TIP15_BIND"
        : "ALL_SHARDS_ROUTED_EXPERT_INVENTORY_BUDGET_REDUCE";
    std::fprintf(stderr,
                 "[PHYSICAL_INVENTORY] shards=%zu tensors=%llu disk=%llu "
                 "routed=%llu keep=%llu E=%llu bpe=%llu budget=%llu "
                 "retained=%llu repacked=%llu policy=%s\n",
                 shards.size(),
                 (unsigned long long)tensorCount,
                 (unsigned long long)out.originalModelBytes,
                 (unsigned long long)routed,
                 (unsigned long long)keep,
                 (unsigned long long)E,
                 (unsigned long long)bytesPerExpertAllLayers,
                 (unsigned long long)budget,
                 (unsigned long long)retained,
                 (unsigned long long)out.repackedModelBytes,
                 out.selectionPolicy.c_str());
    std::fflush(stderr);

    PhysicalCalibResult calib{};
    const char* calibEnv = std::getenv("RAWR_REAP_CALIBRATION");
    TryLoadCalibrationRanks(calibEnv ? calibEnv : "", E, retained, calib);
    out.calibrationStatus = calib.status;

    PhysicalExportResult exp{};
    const char* exportDir = std::getenv("RAWR_REAP_EXPORT_DIR");
    if (exportDir && exportDir[0]) {
        if (TryExportReducedSidecar(runtime.actual.model, exportDir,
                                    static_cast<uint32_t>(retained),
                                    out.repackedModelBytes, exp)) {
            out.writerInvoked = true;
            out.exportStatus = exp.status;
            out.exportPath = exp.outputFirstShard;
            out.exportSha256 = exp.sha256;
        } else {
            out.exportStatus = exp.status;
        }
    }

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
      << ",\"calibration_status\":\"" << plan.calibrationStatus << "\""
      << ",\"export_status\":\"" << plan.exportStatus << "\""
      << ",\"INVENTORY_METHOD\":\"ALL_SHARDS_GGUF_TENSOR_SIZE\""
      << ",\"REPACKED_SCOPE\":\"SHARED_KEEP_PLUS_RETAINED_ROUTED_EXPERTS\""
      << ",\"ACCOUNTING_COMPLETE\":1"
      << ",\"REPACKED_MODEL_BYTES_KIND\":\"PROXY_PLAN_SCOPE\""
      << ",\"ORIGINAL_MODEL_BYTES\":" << plan.originalModelBytes
      << ",\"ORIGINAL_EXPERT_COUNT\":" << plan.originalExpertCount
      << ",\"ORIGINAL_EXPERT_TENSOR_BYTES\":" << plan.expertBytes
      << ",\"SHARED_NON_EXPERT_BYTES\":" << plan.sharedBytes
      << ",\"ROUTED_EXPERT_BYTES\":" << plan.expertBytes
      << ",\"SHARED_KEEP_BYTES\":" << plan.sharedBytes
      << ",\"RETAINED_EXPERT_COUNT\":" << plan.retainedExpertsPerLayer
      << ",\"RETAINED_EXPERT_SLICES\":" << plan.retainedExpertSlices
      << ",\"RETAINED_EXPERT_BYTES\":"
      << (plan.originalExpertCount
              ? (plan.expertBytes / plan.originalExpertCount) *
                    plan.retainedExpertsPerLayer
              : 0)
      << ",\"PRUNED_EXPERT_BYTES\":" << plan.prunedParameterEstimate
      << ",\"PRUNED_ROUTED_EXPERT_BYTES\":" << plan.prunedParameterEstimate
      << ",\"PRUNED_PARAMETER_COUNT\":" << plan.prunedParameterEstimate
      << ",\"PRUNED_PARAMETER_COUNT_UNIT\":\"BYTE_PROXY\""
      << ",\"REPACKED_MODEL_BYTES\":" << plan.repackedModelBytes
      << ",\"ACTIVE_PARAMETERS_PER_TOKEN\":"
      << plan.activeParametersPerToken
      << ",\"MOE_LAYER_COUNT\":" << plan.moeLayerCount
      << ",\"TOP_K\":" << plan.topK
      << ",\"REAP_MODEL_SHA256\":\"" << plan.exportSha256 << "\""
      << ",\"export_path\":\"" << plan.exportPath << "\""
      << ",\"source_immutable\":"
      << (plan.sourceImmutable ? "true" : "false")
      << ",\"writer_invoked\":"
      << (plan.writerInvoked ? "true" : "false")
      << ",\"reason\":\"" << plan.reason << "\""
      << ",\"PROMOTE\":0,\"CERTIFIED\":0"
      << ",\"NOTE\":\"REPACKED_MODEL_BYTES_IS_NOT_A_CERTIFIED_STANDALONE_GGUF;"
         "TIP15_19_4GB_SMOKE=PROXY_ONLY\"}";
    return o.str();
}

} // namespace RawrXD::Reap
