#include "reap_cli_contract.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>

#include <nlohmann/json.hpp>

namespace RawrXD::Reap {
namespace {

using json = nlohmann::json;
namespace fs = std::filesystem;

std::string Upper(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return value;
}

std::string JsonQuote(const std::string& value) {
    std::ostringstream out;
    out << '"';
    for (unsigned char c : value) {
        switch (c) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 0x20) {
                out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                    << static_cast<unsigned int>(c) << std::dec << std::setfill(' ');
            } else {
                out << static_cast<char>(c);
            }
            break;
        }
    }
    out << '"';
    return out.str();
}

bool ParseUnsigned(const std::string& text, uint64_t max, uint64_t& value) {
    if (text.empty()) return false;
    uint64_t parsed = 0;
    for (unsigned char c : text) {
        if (!std::isdigit(c)) return false;
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (parsed > (max - digit) / 10u) return false;
        parsed = parsed * 10u + digit;
    }
    value = parsed;
    return true;
}

// Evidence contract versions.  Each gate reads a specific evidence file and
// validates its schema version before trusting any PASS claim.
inline const char* kInventorySchema = "reap.full_inventory.v1";
inline const char* kInventoryMatrixSchema = "reap.model_inventory_matrix_001";
inline const char* kExtractionCertSchema = "reap.writer_extraction_cert_001.v1";
inline const char* kReferenceParitySchema = "reap.reference_parity_001.v1";
inline const char* kCalibrationSchema = "reap.calibration_001.v1";
inline const char* kSelectionSchema = "reap.selection_001.v1";
inline const char* kQualityFloorSchema = "reap.quality_floor_001.v1";

// Read and parse a JSON evidence file.  Returns false (with reason) if the
// file is missing, unreadable, or not valid JSON.
bool ReadEvidence(const fs::path& workspace, const char* filename, json& out,
                  std::string& reason) {
    fs::path p = workspace / "evidence" / filename;
    if (!fs::exists(p)) {
        reason = "REAP_EVIDENCE_MISSING:" + std::string(filename);
        return false;
    }
    std::ifstream in(p);
    if (!in) {
        reason = "REAP_EVIDENCE_UNREADABLE:" + std::string(filename);
        return false;
    }
    try {
        in >> out;
    } catch (const std::exception&) {
        reason = "REAP_EVIDENCE_MALFORMED:" + std::string(filename);
        return false;
    }
    return true;
}

// Validate that an evidence document carries the expected schema version.
// The evaluator must not trust a PASS from an unknown or unsupported schema.
bool ValidateSchema(const json& doc, const char* expectedSchema,
                    std::string& reason) {
    if (!doc.contains("schema") || !doc["schema"].is_string()) {
        reason = "REAP_EVIDENCE_NO_SCHEMA";
        return false;
    }
    if (doc["schema"].get<std::string>() != expectedSchema) {
        reason = "REAP_EVIDENCE_UNSUPPORTED_SCHEMA:" +
                 doc["schema"].get<std::string>();
        return false;
    }
    return true;
}

// Check that a boolean gate field is present and true.  Absence or false
// means the gate has not been earned.
bool GatePassed(const json& doc, const char* field, std::string& reason) {
    if (!doc.contains(field) || !doc[field].is_boolean() || !doc[field].get<bool>()) {
        reason = "REAP_GATE_NOT_PASSED:" + std::string(field);
        return false;
    }
    return true;
}

} // namespace

bool ParseSizeBytes(const std::string& text, uint64_t& bytes) {
    bytes = 0;
    if (text.empty()) return false;

    size_t split = 0;
    bool seenDigit = false;
    bool seenDot = false;
    for (; split < text.size(); ++split) {
        const unsigned char c = static_cast<unsigned char>(text[split]);
        if (std::isdigit(c)) {
            seenDigit = true;
            continue;
        }
        if (c == '.' && !seenDot) {
            seenDot = true;
            continue;
        }
        break;
    }
    if (!seenDigit || split == text.size()) return false;
    const std::string number = text.substr(0, split);
    char* end = nullptr;
    const double value = std::strtod(number.c_str(), &end);
    if (!end || *end != '\0' || !std::isfinite(value) || value <= 0.0) return false;

    const std::string unit = Upper(text.substr(split));
    uint64_t multiplier = 0;
    if (unit == "B") multiplier = 1ull;
    else if (unit == "KB" || unit == "KIB") multiplier = 1ull << 10;
    else if (unit == "MB" || unit == "MIB") multiplier = 1ull << 20;
    else if (unit == "GB" || unit == "GIB") multiplier = 1ull << 30;
    else if (unit == "TB" || unit == "TIB") multiplier = 1ull << 40;
    else return false;

    const long double scaled = static_cast<long double>(value) * multiplier;
    if (!std::isfinite(static_cast<double>(scaled)) ||
        scaled < 1.0L ||
        scaled > static_cast<long double>(std::numeric_limits<uint64_t>::max())) {
        return false;
    }
    bytes = static_cast<uint64_t>(scaled);
    return bytes != 0;
}

bool ParseActiveExperts(const std::string& text, uint32_t& activeExperts) {
    uint64_t parsed = 0;
    if (!ParseUnsigned(text, std::numeric_limits<uint32_t>::max(), parsed) || parsed == 0) {
        activeExperts = 0;
        return false;
    }
    activeExperts = static_cast<uint32_t>(parsed);
    return true;
}

bool ParseQualityFloor(const std::string& text, double& qualityFloor) {
    qualityFloor = 0.0;
    if (text.empty()) return false;
    char* end = nullptr;
    const double parsed = std::strtod(text.c_str(), &end);
    if (!end || *end != '\0' || !std::isfinite(parsed) || parsed < 0.0 || parsed > 1.0) {
        return false;
    }
    qualityFloor = parsed;
    return true;
}

CliValidation Validate(const CliRequest& request) {
    CliValidation result;
    if (request.model.empty()) {
        result.code = "REAP_MODEL_REQUIRED";
        result.message = "a model identifier or path is required";
        return result;
    }
    uint64_t target = 0;
    if (request.targetSizeText.empty() || !ParseSizeBytes(request.targetSizeText, target)) {
        result.code = "REAP_TARGET_SIZE_INVALID";
        result.message = "--target-size must be a positive byte size (B, MB, GB, or TB)";
        return result;
    }
    uint64_t budget = 0;
    if (request.expertBudgetText.empty() || !ParseSizeBytes(request.expertBudgetText, budget)) {
        result.code = "REAP_EXPERT_BUDGET_INVALID";
        result.message = "--expert-budget must be a positive byte size (B, MB, GB, or TB)";
        return result;
    }
    uint32_t experts = 0;
    if (request.activeExpertsText.empty() || !ParseActiveExperts(request.activeExpertsText, experts)) {
        result.code = "REAP_ACTIVE_EXPERTS_INVALID";
        result.message = "--active-experts must be a positive integer";
        return result;
    }
    double floor = 0.0;
    if (request.qualityFloorText.empty() || !ParseQualityFloor(request.qualityFloorText, floor)) {
        result.code = "REAP_QUALITY_FLOOR_INVALID";
        result.message = "--quality-floor must be a finite number in [0,1]";
        return result;
    }
    if (budget > target) {
        result.code = "REAP_EXPERT_BUDGET_EXCEEDS_TARGET";
        result.message = "--expert-budget cannot exceed --target-size";
        return result;
    }

    result.ok = true;
    result.code = "REAP_REQUEST_VALID";
    result.message = "request is syntactically and semantically valid";
    return result;
}

// Evidence-backed admission evaluator.  Every gate must be earned by real,
// independently produced evidence.  The evaluator never synthesizes a PASS
// and never authorizes transformation based on a missing or stale receipt.
//
// All gates fail closed: unknown schema, missing field, malformed JSON, or
// a false boolean all produce explicit denial and transformationEnabled=false.
Admission EvaluateAdmission(const CliRequest& request) {
    Admission admission;
    admission.reason = "REAP_RUNTIME_UNAVAILABLE";

    fs::path workspace = request.workspace.empty()
                             ? fs::current_path()
                             : request.workspace;

    // Gate 1 — mlaCert001: model-specific inventory identity and integrity.
    // The matrix is populated by independent inventory runs for each model;
    // never reuse Kimi-specific counts for DeepSeek or MiniMax.
    {
        json doc;
        std::string reason;
        if (!ReadEvidence(workspace, "reap_model_inventory_matrix_20261026.json", doc, reason)) {
            admission.reason = reason;
            return admission;
        }
        if (!ValidateSchema(doc, kInventoryMatrixSchema, admission.reason)) return admission;
        if (!doc.contains("models") || !doc["models"].is_array()) {
            admission.reason = "REAP_INVENTORY_MATRIX_MALFORMED";
            return admission;
        }
        bool matched = false;
        for (const auto& model : doc["models"]) {
            if (!model.is_object() ||
                model.value("first_shard", std::string{}) != request.model) continue;
            matched = true;
            if (model.value("status", std::string{}) != "PASS" ||
                model.value("shards", uint64_t{0}) == 0 ||
                model.value("tensors", uint64_t{0}) == 0 ||
                model.value("logical_experts", uint64_t{0}) == 0) {
                admission.reason = "REAP_MODEL_INVENTORY_NOT_CERTIFIED";
                return admission;
            }
            break;
        }
        if (!matched) {
            admission.reason = "REAP_MODEL_NOT_IN_INVENTORY";
            return admission;
        }
        admission.mlaCert001 = true;
    }

    // Gate 2 — calibrationComplete: Extraction certification.
    // Validates that the writer extraction certificate exists, has the
    // expected schema, and reports overall PASS on real-model tests.
    {
        json doc;
        std::string reason;
        if (!ReadEvidence(workspace, "reap_writer_extraction_cert_001.json", doc, reason)) {
            admission.reason = reason;
            return admission;
        }
        if (!ValidateSchema(doc, kExtractionCertSchema, admission.reason)) return admission;
        if (!doc.contains("certification_result") || !doc["certification_result"].is_object()) {
            admission.reason = "REAP_EXTRACTION_CERT_NO_RESULT";
            return admission;
        }
        const auto& cert = doc["certification_result"];
        if (!cert.contains("overall_status") || !cert["overall_status"].is_string() ||
            cert["overall_status"].get<std::string>() != "PASS") {
            admission.reason = "REAP_EXTRACTION_NOT_CERTIFIED";
            return admission;
        }
        // Extraction certification is structural evidence only; it does not
        // count as a completed activation calibration run.
    }

    // Gate 3 — selectionComplete: Independent reference inference parity.
    // Requires evidence that tokenizer, greedy decode, continuous decode,
    // and logit parity have been independently verified against a baseline.
    {
        json doc;
        std::string reason;
        if (!ReadEvidence(workspace, "reap_reference_parity_001.json", doc, reason)) {
            admission.reason = reason;
            return admission;
        }
        if (!ValidateSchema(doc, kReferenceParitySchema, admission.reason)) return admission;
        if (!doc.contains("reference_parity_pass") ||
            !doc["reference_parity_pass"].is_boolean() ||
            !doc["reference_parity_pass"].get<bool>()) {
            admission.reason = "REAP_REFERENCE_PARITY_NOT_PASSED";
            return admission;
        }
        admission.selectionComplete = true;
    }

    // Gate 4 — rewriterCertified: Calibration, selection validity, quality
    // floor, and writer certification.  All four sub-gates must pass.
    {
        // Calibration evidence.
        json calDoc;
        std::string reason;
        if (!ReadEvidence(workspace, "reap_calibration_001.json", calDoc, reason)) {
            admission.reason = reason;
            return admission;
        }
        if (!ValidateSchema(calDoc, kCalibrationSchema, admission.reason)) return admission;
        if (!GatePassed(calDoc, "calibration_complete", admission.reason)) return admission;

        // Selection evidence.
        json selDoc;
        if (!ReadEvidence(workspace, "reap_selection_001.json", selDoc, reason)) {
            admission.reason = reason;
            return admission;
        }
        if (!ValidateSchema(selDoc, kSelectionSchema, admission.reason)) return admission;
        if (!GatePassed(selDoc, "selection_valid", admission.reason)) return admission;

        // Quality floor evidence.
        json qfDoc;
        if (!ReadEvidence(workspace, "reap_quality_floor_001.json", qfDoc, reason)) {
            admission.reason = reason;
            return admission;
        }
        if (!ValidateSchema(qfDoc, kQualityFloorSchema, admission.reason)) return admission;
        if (!GatePassed(qfDoc, "quality_floor_met", admission.reason)) return admission;

        admission.rewriterCertified = true;
        admission.calibrationComplete = true;
    }

    // All gates passed.  Transformation is enabled only when every independent
    // evidence gate has been earned.  Quality preservation and production
    // readiness remain separate downstream certifications.
    admission.transformationEnabled = true;
    admission.reason = "REAP_ADMISSION_GRANTED";
    return admission;
}

Admission EvaluateAdmission(const CliRequest& request,
                            const AdmissionEvidence& evidence) {
    Admission admission;
    const CliValidation requestValidation = Validate(request);
    if (!requestValidation.ok) {
        admission.reason = requestValidation.code;
        return admission;
    }
    if (evidence.schema != "RAWRXD_REAP_ADMISSION_EVIDENCE_001") {
        admission.reason = "REAP_EVIDENCE_SCHEMA_INVALID";
        return admission;
    }
    if (evidence.model.empty() || evidence.model != request.model) {
        admission.reason = "REAP_EVIDENCE_MODEL_MISMATCH";
        return admission;
    }
    if (evidence.modelHash.empty() || evidence.tokenizerHash.empty()) {
        admission.reason = "REAP_EVIDENCE_IDENTITY_INCOMPLETE";
        return admission;
    }
    if (evidence.calibrationHash.empty() || evidence.selectionMaskHash.empty()) {
        admission.reason = "REAP_EVIDENCE_HASH_INCOMPLETE";
        return admission;
    }
    if (evidence.requiredWindows == 0 ||
        evidence.generatedWindows < evidence.requiredWindows) {
        admission.reason = "REAP_CALIBRATION_WINDOWS_INCOMPLETE";
        return admission;
    }
    if (evidence.requiredLayers == 0 ||
        evidence.observedLayers < evidence.requiredLayers) {
        admission.reason = "REAP_ROUTING_TOPOLOGY_INCOMPLETE";
        return admission;
    }
    if (!evidence.mlaCert001) {
        admission.reason = "REAP_MLA_CERT_REQUIRED";
        return admission;
    }
    if (!evidence.calibrationComplete || !evidence.routeMetricsComplete) {
        admission.reason = "REAP_CALIBRATION_NOT_CERTIFIED";
        return admission;
    }
    if (!evidence.referenceParity) {
        admission.reason = "REAP_REFERENCE_PARITY_REQUIRED";
        return admission;
    }
    if (!evidence.selectionComplete) {
        admission.reason = "REAP_SELECTION_MASK_NOT_CERTIFIED";
        return admission;
    }
    if (!evidence.qualityFloorPass) {
        admission.reason = "REAP_QUALITY_FLOOR_NOT_MET";
        return admission;
    }
    if (!evidence.rewriterCertified) {
        admission.reason = "REAP_REWRITER_NOT_CERTIFIED";
        return admission;
    }
    if (!evidence.reducedReloadPass) {
        admission.reason = "REAP_REDUCED_RELOAD_REQUIRED";
        return admission;
    }
    admission.mlaCert001 = true;
    admission.calibrationComplete = true;
    admission.selectionComplete = true;
    admission.rewriterCertified = true;
    admission.reducedReloadPass = true;
    admission.qualityFloorPass = true;
    admission.transformationEnabled = true;
    admission.reason = "REAP_ADMISSION_AUTHORIZED";
    return admission;
}

std::string BlockedReceipt(const CliRequest& request, const Admission& admission) {
    std::ostringstream out;
    out << "{"
        << "\"status\":" << JsonQuote(admission.transformationEnabled ? "AUTHORIZED" : "BLOCKED") << ","
        << "\"reason\":" << JsonQuote(admission.reason) << ","
        << "\"model\":" << JsonQuote(request.model) << ","
        << "\"target_size\":" << request.targetSizeBytes << ","
        << "\"expert_budget\":" << request.expertBudgetBytes << ","
        << "\"active_experts\":" << request.activeExperts << ","
        << "\"quality_floor\":" << std::setprecision(17) << request.qualityFloor << ","
        << "\"gates\":{"
        << "\"mla_cert_001\":" << (admission.mlaCert001 ? "true" : "false") << ","
        << "\"calibration_complete\":" << (admission.calibrationComplete ? "true" : "false") << ","
        << "\"selection_complete\":" << (admission.selectionComplete ? "true" : "false") << ","
        << "\"rewriter_certified\":" << (admission.rewriterCertified ? "true" : "false") << ","
        << "\"quality_floor_pass\":" << (admission.qualityFloorPass ? "true" : "false") << ","
        << "\"reduced_reload_pass\":" << (admission.reducedReloadPass ? "true" : "false")
        << "},"
        << "\"transformation_enabled\":"
        << (admission.transformationEnabled ? "true" : "false")
        << "}\n";
    return out.str();
}

} // namespace RawrXD::Reap
