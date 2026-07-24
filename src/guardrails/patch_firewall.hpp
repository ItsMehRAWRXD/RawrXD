#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <filesystem>
#include "../intent/intent_config.hpp"
#include "../intent/intent_abi.hpp"
#include "../hotpatch/patch_transaction.hpp"
#include "capability_policy.hpp"

// =============================================================================
// Patch Firewall - Validates all modifications before execution
// Toggleable at compile-time and runtime
// =============================================================================

namespace RawrXD {
namespace Guardrails {

// Firewall rules
enum class FirewallRule : uint32_t {
    ALLOW = 0,
    DENY = 1,
    REQUIRE_VALIDATION = 2,
    REQUIRE_APPROVAL = 3,
    SANDBOX_ONLY = 4,
};

// Firewall configuration (toggleable)
struct FirewallConfig {
    // Master toggle
    bool enabled = true;
    
    // Feature toggles
    bool validate_scope = true;
    bool validate_semantics = true;
    bool validate_safety = true;
    bool require_ast_diff = true;
    bool require_policy_check = true;
    bool sandbox_untrusted = true;
    bool log_all_patches = true;
    bool alert_on_violation = true;
    
    // Auto-actions
    bool auto_reject_dangerous = true;
    bool auto_rollback_on_failure = true;
    bool auto_quarantine_suspicious = false;
    
    // Scope rules
    std::vector<std::string> protected_prefixes = {
        "/boot/",
        "/etc/",
        "/sys/",
        "/proc/",
        "/dev/",
        "C:\\Windows\\",
        "C:\\Program Files\\",
    };
    
    std::vector<std::string> protected_patterns = {
        "*.key",
        "*.pem",
        "*.p12",
        "*password*",
        "*credential*",
        "*secret*",
        ".env",
        ".git/config",
    };
    
    // File type rules
    std::unordered_set<std::string> allowed_extensions = {
        ".cpp", ".hpp", ".c", ".h",
        ".py", ".js", ".ts", ".java",
        ".rs", ".go", ".rb",
        ".md", ".txt", ".json", ".yaml", ".yml",
    };
    
    std::unordered_set<std::string> denied_extensions = {
        ".exe", ".dll", ".so", ".dylib",
        ".bin", ".dat", ".db",
    };
    
    // Singleton
    static FirewallConfig& Instance();
    
    // Load from config
    void LoadFromFile(const std::filesystem::path& path);
    void SaveToFile(const std::filesystem::path& path) const;
    
    // Check rules
    bool IsPathProtected(const std::filesystem::path& path) const;
    bool IsExtensionAllowed(const std::filesystem::path& path) const;
    bool IsExtensionDenied(const std::filesystem::path& path) const;
};

// Firewall validation result
struct FirewallResult {
    bool allowed = false;
    FirewallRule rule = FirewallRule::DENY;
    std::string reason;
    std::vector<std::string> warnings;
    bool requires_sandbox = false;
    bool requires_approval = false;
    std::optional<CapabilityToken> token;
    
    // Default constructor
    FirewallResult() = default;
    
    // Copy/move constructors (required due to CapabilityToken having atomic members)
    FirewallResult(const FirewallResult& other);
    FirewallResult(FirewallResult&& other) noexcept;
    FirewallResult& operator=(const FirewallResult& other);
    FirewallResult& operator=(FirewallResult&& other) noexcept;
};

// Patch Firewall - validates all patches
class PatchFirewall {
public:
    static PatchFirewall& Instance();
    
    // Validate an intent before execution
    FirewallResult ValidateIntent(const Intent::IntentRequest& intent);
    
    // Validate a patch before application
    FirewallResult ValidatePatch(const Hotpatch::Patch& patch);
    
    // Validate a transaction
    FirewallResult ValidateTransaction(const Hotpatch::PatchTransaction& tx);
    
    // Check if operation is allowed
    bool IsAllowed(const Intent::IntentRequest& intent);
    bool IsAllowed(const Hotpatch::Patch& patch);
    
    // Emergency stop
    void EmergencyStop(const std::string& reason);
    void Resume();
    bool IsStopped() const { return stopped_.load(); }
    
    // Toggle
    void EnableFirewall(bool enable) { enabled_ = enable; }
    bool IsEnabled() const { return enabled_.load(); }
    
    // Register custom validator
    using CustomValidator = std::function<FirewallResult(const Intent::IntentRequest&)>;
    void RegisterValidator(const std::string& name, CustomValidator validator);
    void UnregisterValidator(const std::string& name);
    
private:
    PatchFirewall() = default;
    
    bool CheckScope(const Intent::IntentRequest& intent);
    bool CheckSemantics(const Intent::IntentRequest& intent);
    bool CheckSafety(const Intent::IntentRequest& intent);
    bool CheckPolicy(const Intent::IntentRequest& intent);
    
    std::atomic<bool> enabled_{true};
    std::atomic<bool> stopped_{false};
    std::string stop_reason_;
    
    std::unordered_map<std::string, CustomValidator> custom_validators_;
    std::mutex validators_mutex_;
};

// Execution Gateway - controlled execution of validated intents
class ExecutionGateway {
public:
    static ExecutionGateway& Instance();
    
    // Execute intent through firewall
    Intent::IntentResponse Execute(const Intent::IntentRequest& intent);
    
    // Execute with explicit token
    Intent::IntentResponse Execute(
        const Intent::IntentRequest& intent,
        const CapabilityToken& token
    );
    
    // Toggle
    void EnableGateway(bool enable) { enabled_ = enable; }
    bool IsEnabled() const { return enabled_.load(); }
    
private:
    ExecutionGateway() = default;
    
    std::atomic<bool> enabled_{true};
};

// Scoped firewall bypass (for emergency use only)
class ScopedFirewallBypass {
public:
    explicit ScopedFirewallBypass(const std::string& reason);
    ~ScopedFirewallBypass();
    
    bool IsActive() const { return active_; }
    
private:
    bool active_ = false;
    std::string reason_;
    static std::atomic<int> bypass_count_;
};

// Macros for conditional firewall
#define RAWR_FIREWALL_CHECK(intent) \
    (RawrXD::Guardrails::PatchFirewall::Instance().IsEnabled() ? \
     RawrXD::Guardrails::PatchFirewall::Instance().ValidateIntent(intent).allowed : true)

#define RAWR_FIREWALL_GUARD(intent, on_denied) \
    do { \
        if (RawrXD::Guardrails::PatchFirewall::Instance().IsEnabled() && \
            !RAWR_FIREWALL_CHECK(intent)) { \
            on_denied; \
            break; \
        } \
    } while(0)

#define RAWR_GATEWAY_EXECUTE(intent) \
    RawrXD::Guardrails::ExecutionGateway::Instance().Execute(intent)

// Compile-time conditional macros
#if RAWR_PATCH_FIREWALL_ENABLED
    #define RAWR_CT_FIREWALL(code) code
#else
    #define RAWR_CT_FIREWALL(code)
#endif

} // namespace Guardrails
} // namespace RawrXD
