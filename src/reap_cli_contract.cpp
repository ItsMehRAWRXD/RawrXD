#include "reap_cli_contract.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <limits>
#include <sstream>

namespace RawrXD::Reap {
namespace {

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

Admission EvaluateAdmission(const CliRequest&) {
    // This is intentionally a hard-coded safe default, not an environment or
    // manifest switch.  The gates must be earned by the actual certified MLA
    // path, model-specific calibration, deterministic selection, and a parity-
    // validated writer before this function may return transformationEnabled.
    return Admission{};
}

std::string BlockedReceipt(const CliRequest& request, const Admission& admission) {
    std::ostringstream out;
    out << "{"
        << "\"status\":\"BLOCKED\","
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
        << "\"rewriter_certified\":" << (admission.rewriterCertified ? "true" : "false")
        << "},"
        << "\"transformation_enabled\":false"
        << "}\n";
    return out.str();
}

} // namespace RawrXD::Reap
