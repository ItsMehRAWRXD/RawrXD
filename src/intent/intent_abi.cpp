#include "intent_abi.hpp"
#include <nlohmann/json.hpp>
#include <chrono>

namespace RawrXD {
namespace Intent {

// =============================================================================
// IntentRequest Serialization
// =============================================================================

std::string IntentRequest::ToJson() const {
    nlohmann::json j;
    
    j["session_id"] = session_id;
    j["intent_id"] = intent_id;
    j["type"] = static_cast<uint32_t>(type);
    j["risk"] = static_cast<uint32_t>(risk);
    
    // Target
    j["target"]["file_path"] = target.file_path;
    j["target"]["symbol_name"] = target.symbol_name;
    j["target"]["line_start"] = target.line_start;
    j["target"]["line_end"] = target.line_end;
    j["target"]["language"] = target.language;
    j["target"]["function_signature"] = target.function_signature;
    j["target"]["dependencies"] = target.dependencies;
    
    // Change
    if (change.has_value()) {
        j["change"]["operation"] = change->operation;
        j["change"]["target_fragment"] = change->target_fragment;
        j["change"]["replacement"] = change->replacement;
        j["change"]["reason"] = change->reason;
        j["change"]["constraints"] = change->constraints;
        j["change"]["expected_effect"] = change->expected_effect;
        j["change"]["expected_outputs"] = change->expected_outputs;
    }
    
    // Verification
    if (verification.has_value()) {
        j["verification"]["compile"] = verification->compile;
        j["verification"]["run_tests"] = verification->run_tests;
        j["verification"]["static_analysis"] = verification->static_analysis;
        j["verification"]["security_scan"] = verification->security_scan;
        j["verification"]["performance_check"] = verification->performance_check;
        j["verification"]["test_targets"] = verification->test_targets;
        j["verification"]["benchmark_targets"] = verification->benchmark_targets;
        j["verification"]["min_tests_passing"] = verification->min_tests_passing;
        j["verification"]["max_performance_regression"] = verification->max_performance_regression;
        j["verification"]["require_security_clean"] = verification->require_security_clean;
    }
    
    // Metadata
    j["model_source"] = model_source;
    j["reasoning"] = reasoning;
    j["confidence"] = confidence;
    j["timestamp_us"] = timestamp_us;
    j["timeout_ms"] = timeout_ms;
    
    // Overrides
    j["skip_validation"] = skip_validation;
    j["skip_tests"] = skip_tests;
    j["require_human_approval"] = require_human_approval;
    j["auto_rollback_on_failure"] = auto_rollback_on_failure;
    
    return j.dump();
}

std::optional<IntentRequest> IntentRequest::FromJson(const std::string& json) {
    try {
        auto j = nlohmann::json::parse(json);
        IntentRequest req;
        
        req.session_id = j.value("session_id", 0ULL);
        req.intent_id = j.value("intent_id", 0ULL);
        req.type = static_cast<IntentType>(j.value("type", 0));
        req.risk = static_cast<RiskLevel>(j.value("risk", 0));
        
        // Target
        if (j.contains("target")) {
            req.target.file_path = j["target"].value("file_path", "");
            req.target.symbol_name = j["target"].value("symbol_name", "");
            req.target.line_start = j["target"].value("line_start", 0);
            req.target.line_end = j["target"].value("line_end", 0);
            req.target.language = j["target"].value("language", "");
            req.target.function_signature = j["target"].value("function_signature", "");
            if (j["target"].contains("dependencies")) {
                req.target.dependencies = j["target"]["dependencies"].get<std::vector<std::string>>();
            }
        }
        
        // Change
        if (j.contains("change")) {
            ChangeDescription change;
            change.operation = j["change"].value("operation", "");
            change.target_fragment = j["change"].value("target_fragment", "");
            change.replacement = j["change"].value("replacement", "");
            change.reason = j["change"].value("reason", "");
            if (j["change"].contains("constraints")) {
                change.constraints = j["change"]["constraints"].get<std::vector<std::string>>();
            }
            change.expected_effect = j["change"].value("expected_effect", "");
            if (j["change"].contains("expected_outputs")) {
                change.expected_outputs = j["change"]["expected_outputs"].get<std::vector<std::string>>();
            }
            req.change = change;
        }
        
        // Verification
        if (j.contains("verification")) {
            VerificationPlan verify;
            verify.compile = j["verification"].value("compile", true);
            verify.run_tests = j["verification"].value("run_tests", true);
            verify.static_analysis = j["verification"].value("static_analysis", true);
            verify.security_scan = j["verification"].value("security_scan", false);
            verify.performance_check = j["verification"].value("performance_check", false);
            if (j["verification"].contains("test_targets")) {
                verify.test_targets = j["verification"]["test_targets"].get<std::vector<std::string>>();
            }
            if (j["verification"].contains("benchmark_targets")) {
                verify.benchmark_targets = j["verification"]["benchmark_targets"].get<std::vector<std::string>>();
            }
            verify.min_tests_passing = j["verification"].value("min_tests_passing", 0);
            verify.max_performance_regression = j["verification"].value("max_performance_regression", 0.05);
            verify.require_security_clean = j["verification"].value("require_security_clean", true);
            req.verification = verify;
        }
        
        req.model_source = j.value("model_source", "");
        req.reasoning = j.value("reasoning", "");
        req.confidence = j.value("confidence", 0.0f);
        req.timestamp_us = j.value("timestamp_us", 0ULL);
        req.timeout_ms = j.value("timeout_ms", 30000);
        
        req.skip_validation = j.value("skip_validation", false);
        req.skip_tests = j.value("skip_tests", false);
        req.require_human_approval = j.value("require_human_approval", false);
        req.auto_rollback_on_failure = j.value("auto_rollback_on_failure", true);
        
        return req;
    } catch (...) {
        return std::nullopt;
    }
}

// =============================================================================
// IntentResponse Serialization
// =============================================================================

std::string IntentResponse::ToJson() const {
    nlohmann::json j;
    
    j["intent_id"] = intent_id;
    j["status"] = static_cast<uint32_t>(status);
    j["message"] = message;
    j["warnings"] = warnings;
    j["errors"] = errors;
    j["compiled"] = compiled;
    j["tests_passed"] = tests_passed;
    j["tests_failed"] = tests_failed;
    j["performance_delta"] = performance_delta;
    j["security_clean"] = security_clean;
    j["rollback_id"] = rollback_id;
    j["can_rollback"] = can_rollback;
    
    return j.dump();
}

// =============================================================================
// IntentValidator
// =============================================================================

IntentValidator& IntentValidator::Instance() {
    static IntentValidator instance;
    return instance;
}

IntentValidator::ValidationResult IntentValidator::Validate(const IntentRequest& intent) {
    ValidationResult result;
    result.valid = true;
    
    // Check if validation is enabled
    if (!IntentRuntimeConfig::Instance().ValidationEnabled()) {
        result.assessed_risk = RiskLevel::NONE;
        return result;
    }
    
    // Check scope
    if (!CheckScope(intent)) {
        result.valid = false;
        result.errors.push_back("Intent scope validation failed");
    }
    
    // Check semantics
    if (!CheckSemantics(intent)) {
        result.valid = false;
        result.errors.push_back("Intent semantic validation failed");
    }
    
    // Check safety
    if (!CheckSafety(intent)) {
        result.valid = false;
        result.errors.push_back("Intent safety validation failed");
    }
    
    // Assess risk
    result.assessed_risk = AssessRisk(intent);
    
    // Issue capability token if valid
    if (result.valid) {
        // Token would be issued here
        result.token = CapabilityToken{};
    }
    
    return result;
}

bool IntentValidator::CheckScope(const IntentRequest& intent) {
    // Check if target file is within allowed paths
    // Implementation would check against policy
    return true;
}

bool IntentValidator::CheckSemantics(const IntentRequest& intent) {
    // Check if change description is valid
    if (intent.change.has_value()) {
        if (intent.change->operation.empty()) {
            return false;
        }
    }
    return true;
}

bool IntentValidator::CheckSafety(const IntentRequest& intent) {
    // Check for dangerous operations
    switch (intent.type) {
        case IntentType::DELETE_PROJECT:
        case IntentType::ACCESS_CREDENTIALS:
        case IntentType::SYSTEM_COMMAND:
            return false;  // Require explicit approval
        default:
            return true;
    }
}

RiskLevel IntentValidator::AssessRisk(const IntentRequest& intent) {
    // Base risk on intent type
    switch (intent.type) {
        case IntentType::READ_SOURCE:
        case IntentType::READ_AST:
        case IntentType::READ_SYMBOLS:
            return RiskLevel::NONE;
            
        case IntentType::ANALYZE_FUNCTION:
        case IntentType::ANALYZE_PERFORMANCE:
            return RiskLevel::LOW;
            
        case IntentType::MODIFY_FUNCTION:
        case IntentType::ADD_FUNCTION:
        case IntentType::REFACTOR:
            return RiskLevel::MEDIUM;
            
        case IntentType::MODIFY_BUILD_CONFIG:
        case IntentType::NETWORK_OPERATION:
            return RiskLevel::HIGH;
            
        case IntentType::DELETE_PROJECT:
        case IntentType::ACCESS_CREDENTIALS:
        case IntentType::SYSTEM_COMMAND:
            return RiskLevel::CRITICAL;
            
        default:
            return RiskLevel::LOW;
    }
}

void IntentValidator::SetPolicyFile(const std::string& path) {
    // Load policy from file
}

void IntentValidator::ReloadPolicy() {
    // Reload policy
}

// =============================================================================
// IntentRouter
// =============================================================================

IntentRouter& IntentRouter::Instance() {
    static IntentRouter instance;
    return instance;
}

IntentResponse IntentRouter::Route(const IntentRequest& intent) {
    if (!enabled_.load()) {
        IntentResponse response;
        response.intent_id = intent.intent_id;
        response.status = IntentResponse::Status::FAILED;
        response.message = "Routing disabled";
        return response;
    }
    
    auto it = handlers_.find(intent.type);
    if (it != handlers_.end() && it->second) {
        return it->second(intent);
    }
    
    IntentResponse response;
    response.intent_id = intent.intent_id;
    response.status = IntentResponse::Status::FAILED;
    response.message = "No handler for intent type";
    return response;
}

void IntentRouter::RegisterHandler(IntentType type, IntentHandler handler) {
    std::lock_guard<std::mutex> lock(handlers_mutex_);
    handlers_[type] = handler;
}

void IntentRouter::EnableRouting(bool enable) {
    enabled_.store(enable);
}

bool IntentRouter::IsRoutingEnabled() const {
    return enabled_.load();
}

} // namespace Intent
} // namespace RawrXD
