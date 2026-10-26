#include "reap_cli_contract.hpp"

#include <cassert>
#include <iostream>

using RawrXD::Reap::CliRequest;

int main() {
    CliRequest valid;
    valid.model = "example-moe.gguf";
    valid.targetSizeText = "30GB";
    valid.expertBudgetText = "20GB";
    valid.activeExpertsText = "64";
    valid.qualityFloorText = "0.95";
    auto parsed = RawrXD::Reap::Validate(valid);
    assert(parsed.ok);
    assert(RawrXD::Reap::ParseSizeBytes(valid.targetSizeText, valid.targetSizeBytes));
    assert(RawrXD::Reap::ParseSizeBytes(valid.expertBudgetText, valid.expertBudgetBytes));
    assert(RawrXD::Reap::ParseActiveExperts(valid.activeExpertsText, valid.activeExperts));
    assert(RawrXD::Reap::ParseQualityFloor(valid.qualityFloorText, valid.qualityFloor));
    const auto admission = RawrXD::Reap::EvaluateAdmission(valid);
    assert(!admission.transformationEnabled);
    const auto receipt = RawrXD::Reap::BlockedReceipt(valid, admission);
    assert(receipt.find("REAP_EVIDENCE_") != std::string::npos ||
           receipt.find("REAP_RUNTIME_UNAVAILABLE") != std::string::npos);
    assert(receipt.find("\"transformation_enabled\":false") != std::string::npos);

    RawrXD::Reap::AdmissionEvidence evidence;
    evidence.schema = "RAWRXD_REAP_ADMISSION_EVIDENCE_001";
    evidence.model = valid.model;
    evidence.modelHash = "model-sha256";
    evidence.tokenizerHash = "tokenizer-sha256";
    evidence.calibrationHash = "calibration-sha256";
    evidence.selectionMaskHash = "mask-sha256";
    evidence.generatedWindows = 256;
    evidence.requiredWindows = 256;
    evidence.observedLayers = 60;
    evidence.requiredLayers = 60;
    evidence.mlaCert001 = true;
    evidence.calibrationComplete = true;
    evidence.routeMetricsComplete = true;
    evidence.referenceParity = true;
    evidence.selectionComplete = true;
    evidence.qualityFloorPass = true;
    evidence.rewriterCertified = true;
    evidence.reducedReloadPass = true;
    const auto authorized = RawrXD::Reap::EvaluateAdmission(valid, evidence);
    assert(authorized.transformationEnabled);
    assert(authorized.reason == "REAP_ADMISSION_AUTHORIZED");

    const auto assertDenied = [&](auto mutate, const char* expected) {
        auto candidate = evidence;
        mutate(candidate);
        const auto denied = RawrXD::Reap::EvaluateAdmission(valid, candidate);
        assert(!denied.transformationEnabled);
        assert(denied.reason == expected);
    };
    assertDenied([](auto& e) { e.schema.clear(); }, "REAP_EVIDENCE_SCHEMA_INVALID");
    assertDenied([](auto& e) { e.model = "other-model"; }, "REAP_EVIDENCE_MODEL_MISMATCH");
    assertDenied([](auto& e) { e.selectionMaskHash.clear(); }, "REAP_EVIDENCE_HASH_INCOMPLETE");
    assertDenied([](auto& e) { e.generatedWindows = 255; }, "REAP_CALIBRATION_WINDOWS_INCOMPLETE");
    assertDenied([](auto& e) { e.observedLayers = 59; }, "REAP_ROUTING_TOPOLOGY_INCOMPLETE");
    assertDenied([](auto& e) { e.referenceParity = false; }, "REAP_REFERENCE_PARITY_REQUIRED");
    assertDenied([](auto& e) { e.reducedReloadPass = false; }, "REAP_REDUCED_RELOAD_REQUIRED");

    CliRequest missing = valid;
    missing.qualityFloorText.clear();
    assert(!RawrXD::Reap::Validate(missing).ok);

    CliRequest outOfRange = valid;
    outOfRange.qualityFloorText = "1.01";
    assert(!RawrXD::Reap::Validate(outOfRange).ok);

    CliRequest overBudget = valid;
    overBudget.expertBudgetText = "31GB";
    assert(!RawrXD::Reap::Validate(overBudget).ok);

    assert(!RawrXD::Reap::ParseActiveExperts("0", valid.activeExperts));
    assert(!RawrXD::Reap::ParseSizeBytes("30Gi", valid.targetSizeBytes));
    std::cout << "REAP_CLI_CONTRACT_PASS\n";
    return 0;
}
