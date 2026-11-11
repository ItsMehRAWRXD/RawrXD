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
    assert(receipt.find("REAP_RUNTIME_UNAVAILABLE") != std::string::npos);
    assert(receipt.find("\"transformation_enabled\":false") != std::string::npos);

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
