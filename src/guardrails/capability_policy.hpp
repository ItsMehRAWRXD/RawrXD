#pragma once
#include <stdint.h>
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <filesystem>
#include <regex>
#include "../intent/intent_config.hpp"
#include "../intent/intent_abi.hpp"

// =============================================================================
// Capability Policy System - Permission tokens instead of unrestricted access
// Toggleable at compile-time and runtime
// =============================================================================

namespace RawrXD {
namespace Guardrails {

// Capability flags - what an agent is allowed to do
enum class Capability : uint64_t {
    NONE = 0,
    
    // Read capabilities
    READ_SOURCE = 1ULL << 0,
    READ_AST = 1ULL << 1,
    READ_SYMBOLS = 1ULL << 2,
    READ_TELEMETRY = 1ULL << 3,
    READ_DEPENDENCIES = 1ULL << 4,
    
    // Analysis capabilities
    ANALYZE_CODE = 1ULL << 10,
    ANALYZE_PERFORMANCE = 1ULL << 11,
    ANALYZE_SECURITY = 1ULL << 12,
    
    // Modification capabilities
    MODIFY_FUNCTION = 1ULL << 20,
    MODIFY_FILE = 1ULL << 21,
    ADD_FUNCTION = 1ULL << 22,
    REMOVE_FUNCTION = 1ULL << 23,
    REFACTOR = 1ULL << 24,
    OPTIMIZE = 1ULL << 25,
    
    // Execution capabilities
    COMPILE = 1ULL << 30,
    RUN_TEST = 1ULL << 31,
    DEBUG = 1ULL << 32,
    RUN_BENCHMARK = 1ULL << 33,
    
    // High-risk capabilities (require explicit grant)
    DELETE_PROJECT = 1ULL << 40,
    MODIFY_BUILD_CONFIG = 1ULL << 41,
    ACCESS_CREDENTIALS = 1ULL << 42,
    NETWORK_OPERATION = 1ULL << 43,
    SYSTEM_COMMAND = 1ULL << 44,
    
    // All capabilities (for testing only)
    ALL = ~0ULL,
};

inline Capability operator|(Capability a, Capability b) {
    return static_cast<Capability>(static_cast<uint64_t>(a) | static_cast<uint64_t>(b));
}

inline Capability operator&(Capability a, Capability b) {
    return static_cast<Capability>(static_cast<uint64_t>(a) & static_cast<uint64_t>(b));
}

inline bool HasCapability(Capability granted, Capability required) {
    return (static_cast<uint64_t>(granted) & static_cast<uint64_t>(required)) != 0;
}

// Policy configuration (toggleable)
struct PolicyConfig {
    // Master toggle
    bool enabled = true;
    
    // Feature toggles
    bool enforce_capabilities = true;
    bool enforce_scope_limits = true;
    bool enforce_rate_limits = true;
    bool require_token_for_execution = true;
    bool auto_revoke_on_violation = true;
    bool log_all_capability_checks = false;
    
    // Default capabilities for different agent types
    Capability default_planner_capabilities = 
        Capability::READ_SOURCE | Capability::READ_AST | Capability::READ_SYMBOLS |
        Capability::ANALYZE_CODE | Capability::ANALYZE_PERFORMANCE;
    
    Capability default_coder_capabilities = 
        Capability::READ_SOURCE | Capability::READ_AST | Capability::READ_SYMBOLS |
        Capability::MODIFY_FUNCTION | Capability::ADD_FUNCTION | Capability::REMOVE_FUNCTION |
        Capability::REFACTOR | Capability::OPTIMIZE |
        Capability::COMPILE | Capability::RUN_TEST | Capability::DEBUG;
    
    Capability default_reviewer_capabilities = 
        Capability::READ_SOURCE | Capability::READ_AST | Capability::READ_SYMBOLS |
        Capability::ANALYZE_CODE | Capability::ANALYZE_SECURITY |
        Capability::RUN_TEST;
    
    // Scope limits
    std::vector<std::regex> allowed_paths;
    std::vector<std::regex> denied_paths;
    std::unordered_set<std::string> protected_files;
    
    // Rate limits
    uint32_t max_modifications_per_minute = 60;
    uint32_t max_executions_per_minute = 30;
    uint32_t max_high_risk_per_hour = 10;
    
    // Singleton
    static PolicyConfig& Instance();
    
    // Load from policy file
    void LoadFromFile(const std::filesystem::path& path);
    void SaveToFile(const std::filesystem::path& path) const;
    
    // Check if path is allowed
    bool IsPathAllowed(const std::filesystem::path& path) const;
    bool IsPathDenied(const std::filesystem::path& path) const;
    bool IsFileProtected(const std::filesystem::path& path) const;
};

// Capability token with scope and expiry
class CapabilityToken {
public:
    CapabilityToken() = default;
    CapabilityToken(uint64_t token_id, uint64_t intent_id, Capability caps);
    
    // Check if token allows an operation
    bool Allows(Capability cap) const;
    bool AllowsIntent(const Intent::IntentRequest& intent) const;
    bool AllowsPath(const std::filesystem::path& path) const;
    
    // Token state
    bool IsExpired() const;
    bool IsExhausted() const;
    bool IsRevoked() const;
    bool IsValid() const;
    
    // Consume one use
    bool Consume();
    
    // Revoke token
    void Revoke(const std::string& reason);
    
    // Getters
    uint64_t GetTokenId() const { return token_id_; }
    uint64_t GetIntentId() const { return intent_id_; }
    Capability GetCapabilities() const { return capabilities_; }
    std::string GetRevokeReason() const { return revoke_reason_; }
    
    // Serialize
    std::string ToJson() const;
    static std::optional<CapabilityToken> FromJson(const std::string& json);
    
    // Copy/move constructors (required due to atomic members)
    CapabilityToken() = default;
    CapabilityToken(const CapabilityToken& other);
    CapabilityToken(CapabilityToken&& other) noexcept;
    CapabilityToken& operator=(const CapabilityToken& other);
    CapabilityToken& operator=(CapabilityToken&& other) noexcept;
    
private:
    uint64_t token_id_ = 0;
    uint64_t intent_id_ = 0;
    Capability capabilities_ = Capability::NONE;
    
    std::vector<std::regex> allowed_paths_;
    std::vector<std::regex> denied_paths_;
    
    uint64_t expiry_timestamp_ = 0;
    uint32_t max_uses_ = 1;
    std::atomic<uint32_t> uses_remaining_{0};
    
    std::atomic<bool> revoked_{false};
    std::string revoke_reason_;
    
    friend class CapabilityManager;
};

// Capability manager
class CapabilityManager {
public:
    static CapabilityManager& Instance();
    
    // Issue a new token
    std::optional<CapabilityToken> IssueToken(
        uint64_t intent_id,
        Capability capabilities,
        uint32_t max_uses = 1,
        uint32_t expiry_seconds = 300
    );
    
    // Validate token
    bool ValidateToken(const CapabilityToken& token);
    
    // Revoke token
    void RevokeToken(uint64_t token_id, const std::string& reason);
    
    // Check capability (with or without token)
    bool CheckCapability(Capability required);
    bool CheckCapability(const CapabilityToken& token, Capability required);
    bool CheckCapability(const CapabilityToken& token, const Intent::IntentRequest& intent);
    
    // Get default capabilities for agent type
    Capability GetDefaultCapabilities(const std::string& agent_type);
    
    // Toggle
    void EnableCapabilities(bool enable) { enabled_ = enable; }
    bool AreCapabilitiesEnabled() const { return enabled_.load(); }
    
    // Emergency revoke all
    void EmergencyRevokeAll(const std::string& reason);
    
private:
    CapabilityManager() = default;
    
    std::unordered_map<uint64_t, CapabilityToken> tokens_;
    std::mutex tokens_mutex_;
    std::atomic<bool> enabled_{true};
    std::atomic<uint64_t> next_token_id_{1};
};

// Scoped capability guard
class ScopedCapability {
public:
    ScopedCapability(CapabilityToken& token, Capability required) 
        : token_(token), required_(required), granted_(false) {
        if (token_.Allows(required_)) {
            granted_ = token_.Consume();
        }
    }
    
    ~ScopedCapability() {
        // Token use is consumed, no rollback needed
    }
    
    bool IsGranted() const { return granted_; }
    
private:
    CapabilityToken& token_;
    Capability required_;
    bool granted_;
};

// Macros for conditional capability checks
#define RAWR_CAPABILITY_CHECK(token, cap) \
    (RawrXD::Guardrails::CapabilityManager::Instance().AreCapabilitiesEnabled() ? \
     RawrXD::Guardrails::CapabilityManager::Instance().CheckCapability(token, cap) : true)

#define RAWR_CAPABILITY_GUARD(token, cap, on_denied) \
    do { \
        if (RawrXD::Guardrails::CapabilityManager::Instance().AreCapabilitiesEnabled() && \
            !RAWR_CAPABILITY_CHECK(token, cap)) { \
            on_denied; \
            break; \
        } \
    } while(0)

// Compile-time conditional macros
#if RAWR_CAPABILITY_TOKENS_ENABLED
    #define RAWR_CT_CAPABILITY(code) code
#else
    #define RAWR_CT_CAPABILITY(code)
#endif

} // namespace Guardrails
} // namespace RawrXD
