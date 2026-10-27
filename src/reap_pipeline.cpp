#include "reap_pipeline.hpp"

#include "reap_inventory.hpp"

#include "deep2/Deep2CLIBridge.hpp"
#include "deep2/GGUFLoader.hpp"
#include "deep2/ReapMoETransformer.hpp"
#include "deep2/execution_policy/ExecutionPolicy.hpp"

namespace RawrXD::Reap {
namespace {

std::string WithStage(std::string receipt, const char* stage) {
    if (receipt.size() >= 2 && receipt[receipt.size() - 2] == '}')
        receipt.insert(receipt.size() - 2, std::string(",\"pipeline_stage\":\"") + stage + "\"");
    return receipt;
}

PipelineResult Fail(const CliRequest& request, Admission admission,
                    const char* stage) {
    PipelineResult out;
    out.exitCode = 4;
    out.receipt = WithStage(BlockedReceipt(request, admission), stage);
    return out;
}

} // namespace

PipelineResult RunPipeline(const CliRequest& request, const std::string& prompt) {
    const auto policy = Deep2::Exec::MakeDefaultPolicy();
    const auto policyCheck = Deep2::Exec::Validate(policy);
    if (!policyCheck.ok) {
        Admission denied;
        denied.reason = "REAP_POLICY_INVALID";
        return Fail(request, denied, "policy");
    }

    Deep2::GGUFLoader loader;
    Inventory inventory;
    std::string error;
    if (!CollectInventory(request.model, loader, inventory, error)) {
        Admission denied;
        denied.reason = "REAP_INVENTORY_FAILED";
        (void)error;
        return Fail(request, denied, "inventory");
    }
    if (inventory.logicalExperts == 0 || inventory.moeLayers.empty()) {
        Admission denied;
        denied.reason = "REAP_MODEL_HAS_NO_VERIFIED_MOE_EXPERTS";
        return Fail(request, denied, "inventory");
    }
    if (request.activeExperts > inventory.maxExpertsPerLayer) {
        Admission denied;
        denied.reason = "REAP_ACTIVE_EXPERTS_EXCEEDS_MODEL";
        return Fail(request, denied, "selection");
    }

    const Admission admission = EvaluateAdmission(request);
    if (!admission.transformationEnabled)
        return Fail(request, admission, "admission");

    // Admission is checked before any writer call.  This ordering is a safety
    // boundary: a missing or stale receipt must not even create a candidate
    // directory.  The unified CLI also requires an explicit rewrite opt-in
    // and separate output paths so the original shard set remains immutable.
    if (!request.authorizeRewrite) {
        Admission held = admission;
        held.transformationEnabled = false;
        held.reason = "REAP_REWRITE_NOT_AUTHORIZED_BY_FLAG";
        return Fail(request, held, "rewrite_authorization");
    }
    if (request.selectionManifestPath.empty() || request.outputDirectory.empty()) {
        Admission held = admission;
        held.transformationEnabled = false;
        held.reason = "REAP_OUTPUT_CONFIGURATION_REQUIRED";
        return Fail(request, held, "rewrite_configuration");
    }

    Deep2::ReapMoETransformRequest writer;
    writer.sourceFirstShard = request.model;
    writer.outputDirectory = request.outputDirectory;
    writer.selectionManifest = request.selectionManifestPath;
    writer.activeExperts = request.activeExperts;
    writer.replaceExisting = false;
    const Deep2::ReapMoETransformResult published = Deep2::transformMoEGGUF(writer);
    const std::string candidate = published.success ? published.outputFirstShard : std::string();
    if (candidate.empty() || prompt.empty()) {
        Admission held = admission;
        held.transformationEnabled = false;
        held.reason = candidate.empty() ? "REAP_CANDIDATE_NOT_PUBLISHED"
                                        : "REAP_PROMPT_REQUIRED";
        return Fail(request, held, "writer");
    }

    Deep2EngineHandle* engine = deep2_load_model(candidate.c_str());
    if (!engine) {
        Admission held = admission;
        held.transformationEnabled = false;
        held.reason = "REAP_DEEP2_LOAD_FAILED";
        return Fail(request, held, "deep2_load");
    }
    std::string text;
    const bool generated = deep2_generate(engine, prompt.c_str(), 16, text);
    deep2_free(engine);
    if (!generated) {
        Admission held = admission;
        held.transformationEnabled = false;
        held.reason = "REAP_DEEP2_NO_TOKENS";
        return Fail(request, held, "deep2_generate");
    }
    Admission passed = admission;
    passed.reducedReloadPass = true;
    passed.reason = "REAP_E2E_PASS";
    PipelineResult out;
    out.exitCode = 0;
    out.receipt = WithStage(BlockedReceipt(request, passed), "deep2_generate");
    return out;
}

} // namespace RawrXD::Reap
