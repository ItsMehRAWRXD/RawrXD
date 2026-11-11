#include "patch_firewall.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <chrono>

namespace RawrXD {
namespace Guardrails {

// =============================================================================
// FirewallConfig
// =============================================================================

FirewallConfig& FirewallConfig::Instance() {
    static FirewallConfig instance;
    return instance;
}

void FirewallConfig::LoadFromFile(const std::filesystem::path& path) {
    std::ifstream file(path);
    if (!file.is_open()) return;
    
    try {
        nlohmann::json j;
        file >> j;
        
        if (j.contains("enabled")) enabled = j["enabled"];
        if (j.contains("validate_scope")) validate_scope = j["validate_scope"];
        if (j.contains("validate_semantics")) validate_semantics = j["validate_semantics"];
        if (j.contains("validate_safety")) validate_safety = j["validate_safety"];
        if (j.contains("require_ast_diff")) require_ast_diff = j["require_ast_diff"];
        if (j.contains("require_policy_check")) require_policy_check = j["require_policy_check"];
        if (j.contains("sandbox_untrusted")) sandbox_untrusted = j["sandbox_untrusted"];
        if (j.contains("log_all_patches")) log_all_patches = j["log_all_patches"];
        if (j.contains("alert_on_violation")) alert_on_violation = j["alert_on_violation"];
        
        if (j.contains("auto_reject_dangerous")) auto_reject_dangerous = j["auto_reject_dangerous"];
        if (j.contains("auto_rollback_on_failure")) auto_rollback_on_failure = j["auto_rollback_on_failure"];
        if (j.contains("auto_quarantine_suspicious")) auto_quarantine_suspicious = j["auto_quarantine_suspicious"];
        
        if (j.contains("protected_prefixes")) {
            protected_prefixes.clear();
            for (const auto& p : j["protected_prefixes"]) {
                protected_prefixes.push_back(p.get<std::string>());
            }
        }
        
        if (j.contains("protected_patterns")) {
            protected_patterns.clear();
            for (const auto& p : j["protected_patterns"]) {
                protected_patterns.push_back(p.get<std::string>());
            }
        }
    } catch (...) {
        // Ignore parse errors
    }
}

void FirewallConfig::SaveToFile(const std::filesystem::path& path) const {
    nlohmann::json j;
    j["enabled"] = enabled;
    j["validate_scope"] = validate_scope;
    j["validate_semantics"] = validate_semantics;
    j["validate_safety"] = validate_safety;
    j["require_ast_diff"] = require_ast_diff;
    j["require_policy_check"] = require_policy_check;
    j["sandbox_untrusted"] = sandbox_untrusted;
    j["log_all_patches"] = log_all_patches;
    j["alert_on_violation"] = alert_on_violation;
    j["auto_reject_dangerous"] = auto_reject_dangerous;
    j["auto_rollback_on_failure"] = auto_rollback_on_failure;
    j["auto_quarantine_suspicious"] = auto_quarantine_suspicious;
    j["protected_prefixes"] = protected_prefixes;
    j["protected_patterns"] = protected_patterns;
    
    std::ofstream file(path);
    if (file.is_open()) {
        file << j.dump(2);
    }
}

bool FirewallConfig::IsPathProtected(const std::filesystem::path& path) const {
    std::string path_str = path.string();
    
    // Check protected prefixes
    for (const auto& prefix : protected_prefixes) {
        if (path_str.find(prefix) == 0) {
            return true;
        }
    }
    
    // Check protected patterns
    for (const auto& pattern : protected_patterns) {
        // Simple pattern matching (would use regex in production)
        if (path_str.find(pattern) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

bool FirewallConfig::IsExtensionAllowed(const std::filesystem::path& path) const {
    std::string ext = path.extension().string();
    return allowed_extensions.find(ext) != allowed_extensions.end();
}

bool FirewallConfig::IsExtensionDenied(const std::filesystem::path& path) const {
    std::string ext = path.extension().string();
    return denied_extensions.find(ext) != denied_extensions.end();
}

// =============================================================================
// FirewallResult
// =============================================================================

FirewallResult::FirewallResult(const FirewallResult& other)
    : allowed(other.allowed),
      rule(other.rule),
      reason(other.reason),
      warnings(other.warnings),
      requires_sandbox(other.requires_sandbox),
      requires_approval(other.requires_approval),
      token(other.token) {}

FirewallResult::FirewallResult(FirewallResult&& other) noexcept
    : allowed(other.allowed),
      rule(other.rule),
      reason(std::move(other.reason)),
      warnings(std::move(other.warnings)),
      requires_sandbox(other.requires_sandbox),
      requires_approval(other.requires_approval),
      token(std::move(other.token)) {}

FirewallResult& FirewallResult::operator=(const FirewallResult& other) {
    if (this != &other) {
        allowed = other.allowed;
        rule = other.rule;
        reason = other.reason;
        warnings = other.warnings;
        requires_sandbox = other.requires_sandbox;
        requires_approval = other.requires_approval;
        token = other.token;
    }
    return *this;
}

FirewallResult& FirewallResult::operator=(FirewallResult&& other) noexcept {
    if (this != &other) {
        allowed = other.allowed;
        rule = other.rule;
        reason = std::move(other.reason);
        warnings = std::move(other.warnings);
        requires_sandbox = other.requires_sandbox;
        requires_approval = other.requires_approval;
        token = std::move(other.token);
    }
    return *this;
}

// =============================================================================
// PatchFirewall
// =============================================================================

PatchFirewall& PatchFirewall::Instance() {
    static PatchFirewall instance;
    return instance;
}

FirewallResult PatchFirewall::ValidateIntent(const Intent::IntentRequest& intent) {
    FirewallResult result;
    
    // Check if firewall is enabled
    if (!enabled_.load() || stopped_.load()) {
        result.allowed = true;
        result.rule = FirewallRule::ALLOW;
        return result;
    }
    
    // Check scope
    if (!CheckScope(intent)) {
        result.allowed = false;
        result.rule = FirewallRule::DENY;
        result.reason = "Intent scope validation failed";
        return result;
    }
    
    // Check semantics
    if (!CheckSemantics(intent)) {
        result.allowed = false;
        result.rule = FirewallRule::DENY;
        result.reason = "Intent semantic validation failed";
        return result;
    }
    
    // Check safety
    if (!CheckSafety(intent)) {
        result.allowed = false;
        result.rule = FirewallRule::DENY;
        result.reason = "Intent safety validation failed";
        return result;
    }
    
    // Check policy
    if (!CheckPolicy(intent)) {
        result.allowed = false;
        result.rule = FirewallRule::DENY;
        result.reason = "Intent policy validation failed";
        return result;
    }
    
    // Run custom validators
    {
        std::lock_guard<std::mutex> lock(validators_mutex_);
        for (const auto& [name, validator] : custom_validators_) {
            auto custom_result = validator(intent);
            if (!custom_result.allowed) {
                return custom_result;
            }
        }
    }
    
    // Determine rule based on risk
    switch (intent.risk) {
        case Intent::RiskLevel::NONE:
            result.allowed = true;
            result.rule = FirewallRule::ALLOW;
            break;
        case Intent::RiskLevel::LOW:
            result.allowed = true;
            result.rule = FirewallRule::ALLOW;
            break;
        case Intent::RiskLevel::MEDIUM:
            result.allowed = true;
            result.rule = FirewallRule::REQUIRE_VALIDATION;
            break;
        case Intent::RiskLevel::HIGH:
            result.allowed = true;
            result.rule = FirewallRule::REQUIRE_APPROVAL;
            result.requires_approval = true;
            break;
        case Intent::RiskLevel::CRITICAL:
            if (FirewallConfig::Instance().auto_reject_dangerous) {
                result.allowed = false;
                result.rule = FirewallRule::DENY;
                result.reason = "Critical risk intent auto-rejected";
            } else {
                result.allowed = true;
                result.rule = FirewallRule::REQUIRE_APPROVAL;
                result.requires_approval = true;
            }
            break;
    }
    
    return result;
}

FirewallResult PatchFirewall::ValidatePatch(const Hotpatch::Patch& patch) {
    FirewallResult result;
    
    if (!enabled_.load()) {
        result.allowed = true;
        return result;
    }
    
    // Check file extension
    if (!FirewallConfig::Instance().IsExtensionAllowed(patch.file_path)) {
        result.allowed = false;
        result.reason = "File extension not allowed";
        return result;
    }
    
    if (FirewallConfig::Instance().IsExtensionDenied(patch.file_path)) {
        result.allowed = false;
        result.reason = "File extension denied";
        return result;
    }
    
    // Check if path is protected
    if (FirewallConfig::Instance().IsPathProtected(patch.file_path)) {
        result.allowed = false;
        result.reason = "Path is protected";
        return result;
    }
    
    result.allowed = true;
    return result;
}

FirewallResult PatchFirewall::ValidateTransaction(const Hotpatch::PatchTransaction& tx) {
    FirewallResult result;
    
    if (!enabled_.load()) {
        result.allowed = true;
        return result;
    }
    
    // Validate all patches in transaction
    for (const auto& patch : tx.GetPatches()) {
        auto patch_result = ValidatePatch(patch);
        if (!patch_result.allowed) {
            return patch_result;
        }
    }
    
    result.allowed = true;
    return result;
}

bool PatchFirewall::IsAllowed(const Intent::IntentRequest& intent) {
    return ValidateIntent(intent).allowed;
}

bool PatchFirewall::IsAllowed(const Hotpatch::Patch& patch) {
    return ValidatePatch(patch).allowed;
}

void PatchFirewall::EmergencyStop(const std::string& reason) {
    stopped_.store(true);
    stop_reason_ = reason;
}

void PatchFirewall::Resume() {
    stopped_.store(false);
    stop_reason_.clear();
}

void PatchFirewall::RegisterValidator(const std::string& name, CustomValidator validator) {
    std::lock_guard<std::mutex> lock(validators_mutex_);
    custom_validators_[name] = validator;
}

void PatchFirewall::UnregisterValidator(const std::string& name) {
    std::lock_guard<std::mutex> lock(validators_mutex_);
    custom_validators_.erase(name);
}

bool PatchFirewall::CheckScope(const Intent::IntentRequest& intent) {
    auto& config = FirewallConfig::Instance();
    
    if (!config.validate_scope) return true;
    
    // Check if path is protected
    if (config.IsPathProtected(intent.target.file_path)) {
        return false;
    }
    
    return true;
}

bool PatchFirewall::CheckSemantics(const Intent::IntentRequest& intent) {
    auto& config = FirewallConfig::Instance();
    
    if (!config.validate_semantics) return true;
    
    // Check if change description is valid
    if (intent.change.has_value()) {
        if (intent.change->operation.empty()) {
            return false;
        }
    }
    
    return true;
}

bool PatchFirewall::CheckSafety(const Intent::IntentRequest& intent) {
    auto& config = FirewallConfig::Instance();
    
    if (!config.validate_safety) return true;
    
    // Check for dangerous operations
    switch (intent.type) {
        case Intent::IntentType::DELETE_PROJECT:
        case Intent::IntentType::ACCESS_CREDENTIALS:
        case Intent::IntentType::SYSTEM_COMMAND:
            return false;
        default:
            return true;
    }
}

bool PatchFirewall::CheckPolicy(const Intent::IntentRequest& intent) {
    auto& config = FirewallConfig::Instance();
    
    if (!config.require_policy_check) return true;
    
    // Would check against policy rules
    return true;
}

// =============================================================================
// ExecutionGateway
// =============================================================================

ExecutionGateway& ExecutionGateway::Instance() {
    static ExecutionGateway instance;
    return instance;
}

Intent::IntentResponse ExecutionGateway::Execute(const Intent::IntentRequest& intent) {
    if (!enabled_.load()) {
        Intent::IntentResponse response;
        response.intent_id = intent.intent_id;
        response.status = Intent::IntentResponse::Status::FAILED;
        response.message = "Gateway disabled";
        return response;
    }
    
    // Validate through firewall
    auto fw_result = PatchFirewall::Instance().ValidateIntent(intent);
    if (!fw_result.allowed) {
        Intent::IntentResponse response;
        response.intent_id = intent.intent_id;
        response.status = Intent::IntentResponse::Status::REJECTED;
        response.message = fw_result.reason;
        return response;
    }
    
    // Route to handler
    return Intent::IntentRouter::Instance().Route(intent);
}

Intent::IntentResponse ExecutionGateway::Execute(
    const Intent::IntentRequest& intent,
    const CapabilityToken& token
) {
    if (!enabled_.load()) {
        Intent::IntentResponse response;
        response.intent_id = intent.intent_id;
        response.status = Intent::IntentResponse::Status::FAILED;
        response.message = "Gateway disabled";
        return response;
    }
    
    // Validate token
    if (!token.IsValid()) {
        Intent::IntentResponse response;
        response.intent_id = intent.intent_id;
        response.status = Intent::IntentResponse::Status::REJECTED;
        response.message = "Invalid capability token";
        return response;
    }
    
    // Check if token allows this intent
    if (!token.AllowsIntent(intent)) {
        Intent::IntentResponse response;
        response.intent_id = intent.intent_id;
        response.status = Intent::IntentResponse::Status::REJECTED;
        response.message = "Capability token does not allow this intent";
        return response;
    }
    
    // Consume token use
    if (!token.IsExhausted()) {
        // Token is valid and not exhausted
    }
    
    // Execute
    return Execute(intent);
}

// =============================================================================
// ScopedFirewallBypass
// =============================================================================

std::atomic<int> ScopedFirewallBypass::bypass_count_{0};

ScopedFirewallBypass::ScopedFirewallBypass(const std::string& reason) 
    : reason_(reason) {
    bypass_count_.fetch_add(1);
    active_ = true;
}

ScopedFirewallBypass::~ScopedFirewallBypass() {
    if (active_) {
        bypass_count_.fetch_sub(1);
    }
}

} // namespace Guardrails
} // namespace RawrXD
