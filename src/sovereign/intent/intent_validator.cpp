#include "intent_abi.hpp"
#include "../../lora/json/json.h"
#include <regex>
#include <algorithm>

namespace RawrXD {
namespace Sovereign {
namespace Intent {

// =============================================================================
// IntentRequest Serialization
// =============================================================================

std::string IntentRequest::ToJson() const {
    Json::Value root;
    root["session_id"] = static_cast<Json::UInt64>(session_id);
    root["type"] = static_cast<int>(type);
    root["timestamp"] = static_cast<Json::UInt64>(timestamp);
    root["model_version"] = model_version;
    root["risk"] = static_cast<int>(risk);
    
    Json::Value target;
    target["file_path"] = target.file_path;
    target["symbol_name"] = target.symbol_name;
    target["line_start"] = target.line_start;
    target["line_end"] = target.line_end;
    target["ast_node_id"] = target.ast_node_id;
    root["target"] = target;
    
    Json::Value change;
    change["goal"] = change.goal;
    change["rationale"] = change.rationale;
    Json::Value constraints(Json::arrayValue);
    for (const auto& c : change.constraints) constraints.append(c);
    change["constraints"] = constraints;
    Json::Value assumptions(Json::arrayValue);
    for (const auto& a : change.assumptions) assumptions.append(a);
    change["assumptions"] = assumptions;
    if (change.reference_impl.has_value()) {
        change["reference_impl"] = *change.reference_impl;
    }
    root["change"] = change;
    
    Json::Value verify;
    verify["compile_check"] = verify.compile_check;
    verify["unit_tests"] = verify.unit_tests;
    verify["integration_tests"] = verify.integration_tests;
    verify["static_analysis"] = verify.static_analysis;
    verify["security_scan"] = verify.security_scan;
    verify["performance_regression"] = verify.performance_regression;
    Json::Value tests(Json::arrayValue);
    for (const auto& t : verify.specific_tests) tests.append(t);
    verify["specific_tests"] = tests;
    root["verify"] = verify;
    
    Json::StreamWriterBuilder builder;
    return Json::writeString(builder, root);
}

std::optional<IntentRequest> IntentRequest::FromJson(const std::string& json_str) {
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errors;
    
    std::istringstream json_stream(json_str);
    if (!Json::parseFromStream(builder, json_stream, &root, &errors)) {
        return std::nullopt;
    }
    
    IntentRequest req;
    req.session_id = root.get("session_id", 0).asUInt64();
    req.type = static_cast<IntentType>(root.get("type", 0).asInt());
    req.timestamp = root.get("timestamp", 0).asUInt64();
    req.model_version = root.get("model_version", "").asString();
    req.risk = static_cast<RiskLevel>(root.get("risk", 2).asInt());
    
    const auto& target = root["target"];
    req.target.file_path = target.get("file_path", "").asString();
    req.target.symbol_name = target.get("symbol_name", "").asString();
    req.target.line_start = target.get("line_start", 0).asUInt();
    req.target.line_end = target.get("line_end", 0).asUInt();
    req.target.ast_node_id = target.get("ast_node_id", "").asString();
    
    const auto& change = root["change"];
    req.change.goal = change.get("goal", "").asString();
    req.change.rationale = change.get("rationale", "").asString();
    for (const auto& c : change["constraints"]) {
        req.change.constraints.push_back(c.asString());
    }
    for (const auto& a : change["assumptions"]) {
        req.change.assumptions.push_back(a.asString());
    }
    if (change.isMember("reference_impl")) {
        req.change.reference_impl = change["reference_impl"].asString();
    }
    
    const auto& verify = root["verify"];
    req.verify.compile_check = verify.get("compile_check", true).asBool();
    req.verify.unit_tests = verify.get("unit_tests", true).asBool();
    req.verify.integration_tests = verify.get("integration_tests", false).asBool();
    req.verify.static_analysis = verify.get("static_analysis", true).asBool();
    req.verify.security_scan = verify.get("security_scan", true).asBool();
    req.verify.performance_regression = verify.get("performance_regression", false).asBool();
    for (const auto& t : verify["specific_tests"]) {
        req.verify.specific_tests.push_back(t.asString());
    }
    
    return req;
}

// =============================================================================
// CapabilityToken Implementation
// =============================================================================

bool CapabilityToken::Validate() const {
    // Check expiry
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    if (now > expiry_timestamp) return false;
    
    // Check signature (simplified - real impl would use HMAC)
    if (signature.empty()) return false;
    
    return true;
}

bool CapabilityToken::Allows(IntentType type, const std::string& path, RiskLevel r) const {
    if (!Validate()) return false;
    if (r > max_risk) return false;
    
    // Check type
    if (std::find(allowed_types.begin(), allowed_types.end(), type) == allowed_types.end()) {
        return false;
    }
    
    // Check path against globs
    bool path_allowed = false;
    for (const auto& pattern : allowed_paths) {
        std::regex glob(pattern);
        if (std::regex_match(path, glob)) {
            path_allowed = true;
            break;
        }
    }
    
    return path_allowed;
}

// =============================================================================
// Default Intent Validator
// =============================================================================

class DefaultIntentValidator : public IIntentValidator {
public:
    IntentResponse Validate(const IntentRequest& intent) override {
        IntentResponse response;
        response.transaction_id = GenerateTransactionId();
        
        // Check 1: Basic structure
        if (intent.type == IntentType::UNKNOWN) {
            response.status = IntentResponse::Status::INVALID;
            response.rejection_reason = "Unknown intent type";
            return response;
        }
        
        // Check 2: Path validation
        if (!IsPathAllowed(intent.target.file_path)) {
            response.status = IntentResponse::Status::REJECTED;
            response.rejection_reason = "Path not in allowed scope: " + intent.target.file_path;
            return response;
        }
        
        // Check 3: Risk assessment
        if (intent.risk == RiskLevel::CRITICAL) {
            response.status = IntentResponse::Status::NEEDS_APPROVAL;
            response.warnings.push_back("Critical risk operation requires human approval");
        }
        
        // Check 4: Protected symbols
        if (IsProtectedSymbol(intent.target.symbol_name)) {
            response.status = IntentResponse::Status::REJECTED;
            response.rejection_reason = "Cannot modify protected symbol: " + intent.target.symbol_name;
            return response;
        }
        
        // Check 5: Verification requirements
        if (!intent.verify.compile_check) {
            response.warnings.push_back("Compile check disabled - risky");
        }
        
        // All checks passed
        if (response.status != IntentResponse::Status::NEEDS_APPROVAL) {
            response.status = IntentResponse::Status::ACCEPTED;
        }
        
        response.estimated_duration_ms = EstimateDuration(intent);
        return response;
    }
    
    bool ValidateToken(const CapabilityToken& token) override {
        return token.Validate();
    }

private:
    std::string GenerateTransactionId() {
        static std::atomic<uint64_t> counter{0};
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        return "TXN-" + std::to_string(now) + "-" + std::to_string(counter++);
    }
    
    bool IsPathAllowed(const std::string& path) {
        // Block system paths
        static const std::vector<std::string> blocked = {
            "/boot", "/etc", "/sys", "/proc", "/dev",
            "C:\\Windows", "C:\\Program Files", "C:\\System32",
            ".git/", "node_modules/", ".env"
        };
        
        for (const auto& b : blocked) {
            if (path.find(b) != std::string::npos) return false;
        }
        return true;
    }
    
    bool IsProtectedSymbol(const std::string& symbol) {
        static const std::vector<std::string> protected_symbols = {
            "main", "_start", "AgenticSupervisor", "PuppeteerAPI",
            "VEH_Watchdog", "HotPatcher", "SymbolTableGenerator",
            "IntentValidator", "PatchTransaction"
        };
        
        for (const auto& p : protected_symbols) {
            if (symbol.find(p) != std::string::npos) return true;
        }
        return false;
    }
    
    uint64_t EstimateDuration(const IntentRequest& intent) {
        // Rough estimates in ms
        uint64_t base = 100;
        if (intent.verify.compile_check) base += 5000;
        if (intent.verify.unit_tests) base += 10000;
        if (intent.verify.integration_tests) base += 30000;
        if (intent.verify.static_analysis) base += 2000;
        if (intent.verify.security_scan) base += 5000;
        return base;
    }
};

// =============================================================================
// Global Validator Singleton
// =============================================================================

static IIntentValidator* g_validator = nullptr;

IIntentValidator* GetIntentValidator() {
    if (!g_validator) {
        static DefaultIntentValidator default_validator;
        g_validator = &default_validator;
    }
    return g_validator;
}

void SetIntentValidator(IIntentValidator* validator) {
    g_validator = validator;
}

} // namespace Intent
} // namespace Sovereign
} // namespace RawrXD
