#include "capability_policy.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <chrono>

namespace RawrXD {
namespace Guardrails {

// =============================================================================
// PolicyConfig
// =============================================================================

PolicyConfig& PolicyConfig::Instance() {
    static PolicyConfig instance;
    return instance;
}

void PolicyConfig::LoadFromFile(const std::filesystem::path& path) {
    std::ifstream file(path);
    if (!file.is_open()) return;
    
    try {
        nlohmann::json j;
        file >> j;
        
        if (j.contains("enabled")) enabled = j["enabled"].get<bool>();
        if (j.contains("enforce_capabilities")) enforce_capabilities = j["enforce_capabilities"].get<bool>();
        if (j.contains("enforce_scope_limits")) enforce_scope_limits = j["enforce_scope_limits"].get<bool>();
        if (j.contains("enforce_rate_limits")) enforce_rate_limits = j["enforce_rate_limits"].get<bool>();
        if (j.contains("require_token_for_execution")) require_token_for_execution = j["require_token_for_execution"].get<bool>();
        if (j.contains("auto_revoke_on_violation")) auto_revoke_on_violation = j["auto_revoke_on_violation"].get<bool>();
        if (j.contains("log_all_capability_checks")) log_all_capability_checks = j["log_all_capability_checks"].get<bool>();
        
        if (j.contains("max_modifications_per_minute")) max_modifications_per_minute = j["max_modifications_per_minute"].get<uint32_t>();
        if (j.contains("max_executions_per_minute")) max_executions_per_minute = j["max_executions_per_minute"].get<uint32_t>();
        if (j.contains("max_high_risk_per_hour")) max_high_risk_per_hour = j["max_high_risk_per_hour"].get<uint32_t>();
        
        if (j.contains("protected_files")) {
            protected_files.clear();
            for (const auto& f : j["protected_files"]) {
                protected_files.insert(f);
            }
        }
    } catch (...) {
        // Ignore parse errors
    }
}

void PolicyConfig::SaveToFile(const std::filesystem::path& path) const {
    nlohmann::json j;
    j["enabled"] = enabled;
    j["enforce_capabilities"] = enforce_capabilities;
    j["enforce_scope_limits"] = enforce_scope_limits;
    j["enforce_rate_limits"] = enforce_rate_limits;
    j["require_token_for_execution"] = require_token_for_execution;
    j["auto_revoke_on_violation"] = auto_revoke_on_violation;
    j["log_all_capability_checks"] = log_all_capability_checks;
    j["max_modifications_per_minute"] = static_cast<uint64_t>(max_modifications_per_minute);
    j["max_executions_per_minute"] = static_cast<uint64_t>(max_executions_per_minute);
    j["max_high_risk_per_hour"] = static_cast<uint64_t>(max_high_risk_per_hour);
    
    std::ofstream file(path);
    if (file.is_open()) {
        file << j.dump(2);
    }
}

bool PolicyConfig::IsPathAllowed(const std::filesystem::path& path) const {
    for (const auto& pattern : allowed_paths) {
        if (std::regex_match(path.string(), pattern)) {
            return true;
        }
    }
    return allowed_paths.empty();  // If no patterns, allow all
}

bool PolicyConfig::IsPathDenied(const std::filesystem::path& path) const {
    for (const auto& pattern : denied_paths) {
        if (std::regex_match(path.string(), pattern)) {
            return true;
        }
    }
    return false;
}

bool PolicyConfig::IsFileProtected(const std::filesystem::path& path) const {
    return protected_files.find(path.string()) != protected_files.end();
}

// =============================================================================
// CapabilityToken
// =============================================================================

CapabilityToken::CapabilityToken(uint64_t token_id, uint64_t intent_id, Capability caps)
    : token_id_(token_id), intent_id_(intent_id), capabilities_(caps) {}

bool CapabilityToken::Allows(Capability cap) const {
    return HasCapability(capabilities_, cap);
}

bool CapabilityToken::AllowsIntent(const Intent::IntentRequest& intent) const {
    // Check if token allows this intent type
    switch (intent.type) {
        case Intent::IntentType::READ_SOURCE:
            return Allows(Capability::READ_SOURCE);
        case Intent::IntentType::MODIFY_FUNCTION:
            return Allows(Capability::MODIFY_FUNCTION);
        case Intent::IntentType::COMPILE:
            return Allows(Capability::COMPILE);
        case Intent::IntentType::RUN_TEST:
            return Allows(Capability::RUN_TEST);
        case Intent::IntentType::DELETE_PROJECT:
            return Allows(Capability::DELETE_PROJECT);
        default:
            return false;
    }
}

bool CapabilityToken::AllowsPath(const std::filesystem::path& path) const {
    // Check path against allowed/denied patterns
    for (const auto& pattern : denied_paths_) {
        if (std::regex_match(path.string(), pattern)) {
            return false;
        }
    }
    
    if (allowed_paths_.empty()) return true;
    
    for (const auto& pattern : allowed_paths_) {
        if (std::regex_match(path.string(), pattern)) {
            return true;
        }
    }
    
    return false;
}

bool CapabilityToken::IsExpired() const {
    if (expiry_timestamp_ == 0) return false;
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    return static_cast<uint64_t>(now) > expiry_timestamp_;
}

bool CapabilityToken::IsExhausted() const {
    return uses_remaining_.load() == 0;
}

bool CapabilityToken::IsRevoked() const {
    return revoked_.load();
}

bool CapabilityToken::IsValid() const {
    return !IsExpired() && !IsExhausted() && !IsRevoked();
}

bool CapabilityToken::Consume() {
    uint32_t expected = uses_remaining_.load();
    while (expected > 0) {
        if (uses_remaining_.compare_exchange_weak(expected, expected - 1)) {
            return true;
        }
    }
    return false;
}

void CapabilityToken::Revoke(const std::string& reason) {
    revoked_.store(true);
    revoke_reason_ = reason;
}

std::string CapabilityToken::ToJson() const {
    nlohmann::json j;
    j["token_id"] = token_id_;
    j["intent_id"] = intent_id_;
    j["capabilities"] = static_cast<uint64_t>(capabilities_);
    j["expiry_timestamp"] = expiry_timestamp_;
    j["max_uses"] = static_cast<uint64_t>(max_uses_);
    j["uses_remaining"] = static_cast<uint64_t>(uses_remaining_.load());
    j["revoked"] = revoked_.load();
    j["revoke_reason"] = revoke_reason_;
    return j.dump();
}

std::optional<CapabilityToken> CapabilityToken::FromJson(const std::string& json) {
    try {
        auto j = nlohmann::json::parse(json);
        CapabilityToken token;
        token.token_id_ = j.value("token_id", 0ULL);
        token.intent_id_ = j.value("intent_id", 0ULL);
        token.capabilities_ = static_cast<Capability>(j.value("capabilities", 0ULL));
        token.expiry_timestamp_ = j.value("expiry_timestamp", 0ULL);
        token.max_uses_ = j.value("max_uses", 1);
        token.uses_remaining_.store(j.value("uses_remaining", 0));
        token.revoked_.store(j.value("revoked", false));
        token.revoke_reason_ = j.value("revoke_reason", "");
        return token;
    } catch (...) {
        return std::nullopt;
    }
}

// Copy/move constructors (required due to atomic members)
CapabilityToken::CapabilityToken(const CapabilityToken& other)
    : token_id_(other.token_id_),
      intent_id_(other.intent_id_),
      capabilities_(other.capabilities_),
      allowed_paths_(other.allowed_paths_),
      denied_paths_(other.denied_paths_),
      expiry_timestamp_(other.expiry_timestamp_),
      max_uses_(other.max_uses_),
      uses_remaining_(other.uses_remaining_.load()),
      revoked_(other.revoked_.load()),
      revoke_reason_(other.revoke_reason_) {}

CapabilityToken::CapabilityToken(CapabilityToken&& other) noexcept
    : token_id_(other.token_id_),
      intent_id_(other.intent_id_),
      capabilities_(other.capabilities_),
      allowed_paths_(std::move(other.allowed_paths_)),
      denied_paths_(std::move(other.denied_paths_)),
      expiry_timestamp_(other.expiry_timestamp_),
      max_uses_(other.max_uses_),
      uses_remaining_(other.uses_remaining_.load()),
      revoked_(other.revoked_.load()),
      revoke_reason_(std::move(other.revoke_reason_)) {}

CapabilityToken& CapabilityToken::operator=(const CapabilityToken& other) {
    if (this != &other) {
        token_id_ = other.token_id_;
        intent_id_ = other.intent_id_;
        capabilities_ = other.capabilities_;
        allowed_paths_ = other.allowed_paths_;
        denied_paths_ = other.denied_paths_;
        expiry_timestamp_ = other.expiry_timestamp_;
        max_uses_ = other.max_uses_;
        uses_remaining_.store(other.uses_remaining_.load());
        revoked_.store(other.revoked_.load());
        revoke_reason_ = other.revoke_reason_;
    }
    return *this;
}

CapabilityToken& CapabilityToken::operator=(CapabilityToken&& other) noexcept {
    if (this != &other) {
        token_id_ = other.token_id_;
        intent_id_ = other.intent_id_;
        capabilities_ = other.capabilities_;
        allowed_paths_ = std::move(other.allowed_paths_);
        denied_paths_ = std::move(other.denied_paths_);
        expiry_timestamp_ = other.expiry_timestamp_;
        max_uses_ = other.max_uses_;
        uses_remaining_.store(other.uses_remaining_.load());
        revoked_.store(other.revoked_.load());
        revoke_reason_ = std::move(other.revoke_reason_);
    }
    return *this;
}

// =============================================================================
// CapabilityManager
// =============================================================================

CapabilityManager& CapabilityManager::Instance() {
    static CapabilityManager instance;
    return instance;
}

std::optional<CapabilityToken> CapabilityManager::IssueToken(
    uint64_t intent_id,
    Capability capabilities,
    uint32_t max_uses,
    uint32_t expiry_seconds
) {
    if (!enabled_.load()) {
        // Return unrestricted token when disabled
        CapabilityToken token(0, intent_id, Capability::ALL);
        return token;
    }
    
    uint64_t token_id = next_token_id_.fetch_add(1);
    
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    CapabilityToken token(token_id, intent_id, capabilities);
    token.expiry_timestamp_ = static_cast<uint64_t>(now) + expiry_seconds;
    token.max_uses_ = max_uses;
    token.uses_remaining_.store(max_uses);
    
    {
        std::lock_guard<std::mutex> lock(tokens_mutex_);
        tokens_[token_id] = token;
    }
    
    return token;
}

bool CapabilityManager::ValidateToken(const CapabilityToken& token) {
    if (!enabled_.load()) return true;
    
    std::lock_guard<std::mutex> lock(tokens_mutex_);
    auto it = tokens_.find(token.GetTokenId());
    if (it == tokens_.end()) return false;
    
    return it->second.IsValid();
}

void CapabilityManager::RevokeToken(uint64_t token_id, const std::string& reason) {
    std::lock_guard<std::mutex> lock(tokens_mutex_);
    auto it = tokens_.find(token_id);
    if (it != tokens_.end()) {
        it->second.Revoke(reason);
    }
}

bool CapabilityManager::CheckCapability(Capability required) {
    if (!enabled_.load()) return true;
    // Would check current context's capabilities
    return true;
}

bool CapabilityManager::CheckCapability(const CapabilityToken& token, Capability required) {
    if (!enabled_.load()) return true;
    return token.Allows(required);
}

bool CapabilityManager::CheckCapability(const CapabilityToken& token, const Intent::IntentRequest& intent) {
    if (!enabled_.load()) return true;
    return token.AllowsIntent(intent) && token.AllowsPath(intent.target.file_path);
}

Capability CapabilityManager::GetDefaultCapabilities(const std::string& agent_type) {
    auto& config = PolicyConfig::Instance();
    
    if (agent_type == "planner") {
        return config.default_planner_capabilities;
    } else if (agent_type == "coder") {
        return config.default_coder_capabilities;
    } else if (agent_type == "reviewer") {
        return config.default_reviewer_capabilities;
    }
    
    return Capability::READ_SOURCE;
}

void CapabilityManager::EmergencyRevokeAll(const std::string& reason) {
    std::lock_guard<std::mutex> lock(tokens_mutex_);
    for (auto& [id, token] : tokens_) {
        token.Revoke(reason);
    }
}

} // namespace Guardrails
} // namespace RawrXD
