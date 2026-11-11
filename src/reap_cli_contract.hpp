#pragma once

#include <cstdint>
#include <map>
#include <string>

namespace RawrXD::Reap {

// The CLI contract is deliberately separate from the model transformer.  It
// owns syntax/semantic validation and admission reporting; it does not infer
// a calibration mask or silently run an unmodified model.
struct CliRequest {
    std::string model;
    std::string targetSizeText;
    std::string expertBudgetText;
    std::string qualityFloorText;
    std::string activeExpertsText;
    std::string workspace;

    uint64_t targetSizeBytes = 0;
    uint64_t expertBudgetBytes = 0;
    uint32_t activeExperts = 0;
    double qualityFloor = 0.0;
};

struct CliValidation {
    bool ok = false;
    std::string code;
    std::string message;
};

struct Admission {
    // All fields are explicit so a receipt cannot be mistaken for a successful
    // transformation merely because it contains a target size.
    bool mlaCert001 = false;
    bool calibrationComplete = false;
    bool selectionComplete = false;
    bool rewriterCertified = false;
    bool reducedReloadPass = false;
    bool qualityFloorPass = false;
    bool transformationEnabled = false;
    std::string reason = "REAP_RUNTIME_UNAVAILABLE";
};

// Evidence supplied by a model-specific calibration/rewrite campaign.  The
// evaluator consumes typed facts only; it never treats a path, environment
// variable, or command-line switch as proof of a certification gate.
struct AdmissionEvidence {
    std::string schema;
    std::string model;
    std::string modelHash;
    std::string tokenizerHash;
    std::string calibrationHash;
    std::string selectionMaskHash;
    uint64_t generatedWindows = 0;
    uint64_t requiredWindows = 256;
    uint64_t observedLayers = 0;
    uint64_t requiredLayers = 0;
    bool mlaCert001 = false;
    bool calibrationComplete = false;
    bool routeMetricsComplete = false;
    bool referenceParity = false;
    bool selectionComplete = false;
    bool rewriterCertified = false;
    bool reducedReloadPass = false;
    bool qualityFloorPass = false;
};

bool ParseSizeBytes(const std::string& text, uint64_t& bytes);
bool ParseActiveExperts(const std::string& text, uint32_t& activeExperts);
bool ParseQualityFloor(const std::string& text, double& qualityFloor);

CliValidation Validate(const CliRequest& request);

// The production transformer is not admitted by this contract until all four
// independent evidence gates are supplied by the real runtime.  No environment
// variable or command-line flag can manufacture those gates.
Admission EvaluateAdmission(const CliRequest& request);
Admission EvaluateAdmission(const CliRequest& request,
                            const AdmissionEvidence& evidence);

// Stable machine-readable receipt for logs and automation.  Values are escaped
// without depending on the CLI's larger JSON/runtime dependency graph.
std::string BlockedReceipt(const CliRequest& request, const Admission& admission);

} // namespace RawrXD::Reap
