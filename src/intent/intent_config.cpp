#include "intent_config.hpp"
#include <cstdlib>
#include <fstream>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Intent {

IntentRuntimeConfig& IntentRuntimeConfig::Instance() {
    static IntentRuntimeConfig instance;
    return instance;
}

void IntentRuntimeConfig::LoadFromEnvironment() {
    // Master switches
    if (const char* val = std::getenv("RAWR_INTENT_GUARD_ENABLED")) {
        enableGuardrails.store(std::strcmp(val, "0") != 0);
    }
    if (const char* val = std::getenv("RAWR_INTENT_VALIDATION_ENABLED")) {
        enableValidation.store(std::strcmp(val, "0") != 0);
    }
    if (const char* val = std::getenv("RAWR_PATCH_TRANSACTION_ENABLED")) {
        enableTransactions.store(std::strcmp(val, "0") != 0);
    }
    if (const char* val = std::getenv("RAWR_CAPABILITY_TOKENS_ENABLED")) {
        enableCapabilityTokens.store(std::strcmp(val, "0") != 0);
    }
    if (const char* val = std::getenv("RAWR_HOTPATCH_JOURNAL_ENABLED")) {
        enableJournal.store(std::strcmp(val, "0") != 0);
    }
    if (const char* val = std::getenv("RAWR_PATCH_FIREWALL_ENABLED")) {
        enableFirewall.store(std::strcmp(val, "0") != 0);
    }
    if (const char* val = std::getenv("RAWR_REFLECTOR_AGENT_ENABLED")) {
        enableReflector.store(std::strcmp(val, "0") != 0);
    }
    if (const char* val = std::getenv("RAWR_ATOMIC_ACTIVATION_ENABLED")) {
        enableAtomicActivation.store(std::strcmp(val, "0") != 0);
    }
    if (const char* val = std::getenv("RAWR_ROLLBACK_FIRST_CLASS_ENABLED")) {
        enableRollback.store(std::strcmp(val, "0") != 0);
    }
    if (const char* val = std::getenv("RAWR_MODEL_ADAPTER_ENABLED")) {
        enableModelAdapter.store(std::strcmp(val, "0") != 0);
    }
    
    // Emergency bypass
    if (const char* val = std::getenv("RAWR_INTENT_EMERGENCY_BYPASS")) {
        emergencyBypass.store(std::strcmp(val, "1") == 0);
    }
    
    // Granular controls
    if (const char* val = std::getenv("RAWR_INTENT_REQUIRE_AST")) {
        requireASTValidation.store(std::strcmp(val, "1") == 0);
    }
    if (const char* val = std::getenv("RAWR_INTENT_REQUIRE_POLICY")) {
        requirePolicyCheck.store(std::strcmp(val, "1") == 0);
    }
    if (const char* val = std::getenv("RAWR_INTENT_REQUIRE_SANDBOX")) {
        requireSandboxBuild.store(std::strcmp(val, "1") == 0);
    }
    if (const char* val = std::getenv("RAWR_INTENT_REQUIRE_VERIFICATION")) {
        requireRuntimeVerification.store(std::strcmp(val, "1") == 0);
    }
    if (const char* val = std::getenv("RAWR_INTENT_REQUIRE_HUMAN")) {
        requireHumanApprovalForHighRisk.store(std::strcmp(val, "1") == 0);
    }
    if (const char* val = std::getenv("RAWR_INTENT_AUTO_COMMIT")) {
        autoCommitOnSuccess.store(std::strcmp(val, "1") == 0);
    }
    if (const char* val = std::getenv("RAWR_INTENT_AUTO_ROLLBACK")) {
        autoRollbackOnFailure.store(std::strcmp(val, "1") == 0);
    }
}

void IntentRuntimeConfig::LoadFromFile(const char* path) {
    std::ifstream file(path);
    if (!file.is_open()) return;
    
    try {
        nlohmann::json j;
        file >> j;
        
        // Master switches
        if (j.contains("enableGuardrails")) enableGuardrails.store(j["enableGuardrails"].get<bool>());
        if (j.contains("enableValidation")) enableValidation.store(j["enableValidation"].get<bool>());
        if (j.contains("enableTransactions")) enableTransactions.store(j["enableTransactions"].get<bool>());
        if (j.contains("enableCapabilityTokens")) enableCapabilityTokens.store(j["enableCapabilityTokens"].get<bool>());
        if (j.contains("enableJournal")) enableJournal.store(j["enableJournal"].get<bool>());
        if (j.contains("enableFirewall")) enableFirewall.store(j["enableFirewall"].get<bool>());
        if (j.contains("enableReflector")) enableReflector.store(j["enableReflector"].get<bool>());
        if (j.contains("enableAtomicActivation")) enableAtomicActivation.store(j["enableAtomicActivation"].get<bool>());
        if (j.contains("enableRollback")) enableRollback.store(j["enableRollback"].get<bool>());
        if (j.contains("enableModelAdapter")) enableModelAdapter.store(j["enableModelAdapter"].get<bool>());
        
        // Emergency bypass
        if (j.contains("emergencyBypass")) emergencyBypass.store(j["emergencyBypass"].get<bool>());
        
        // Granular controls
        if (j.contains("requireASTValidation")) requireASTValidation.store(j["requireASTValidation"].get<bool>());
        if (j.contains("requirePolicyCheck")) requirePolicyCheck.store(j["requirePolicyCheck"].get<bool>());
        if (j.contains("requireSandboxBuild")) requireSandboxBuild.store(j["requireSandboxBuild"].get<bool>());
        if (j.contains("requireRuntimeVerification")) requireRuntimeVerification.store(j["requireRuntimeVerification"].get<bool>());
        if (j.contains("requireHumanApprovalForHighRisk")) requireHumanApprovalForHighRisk.store(j["requireHumanApprovalForHighRisk"].get<bool>());
        if (j.contains("autoCommitOnSuccess")) autoCommitOnSuccess.store(j["autoCommitOnSuccess"].get<bool>());
        if (j.contains("autoRollbackOnFailure")) autoRollbackOnFailure.store(j["autoRollbackOnFailure"].get<bool>());
        
        // Performance settings
        if (j.contains("fastPathForTrustedModels")) fastPathForTrustedModels.store(j["fastPathForTrustedModels"].get<bool>());
        if (j.contains("maxValidationTimeMs")) maxValidationTimeMs.store(j["maxValidationTimeMs"].get<unsigned int>());
        if (j.contains("maxSandboxBuildTimeMs")) maxSandboxBuildTimeMs.store(j["maxSandboxBuildTimeMs"].get<unsigned int>());
        if (j.contains("maxRollbackTimeMs")) maxRollbackTimeMs.store(j["maxRollbackTimeMs"].get<unsigned int>());
    } catch (...) {
        // Ignore parse errors
    }
}

void IntentRuntimeConfig::SaveToFile(const char* path) const {
    nlohmann::json j;
    
    j["enableGuardrails"] = enableGuardrails.load();
    j["enableValidation"] = enableValidation.load();
    j["enableTransactions"] = enableTransactions.load();
    j["enableCapabilityTokens"] = enableCapabilityTokens.load();
    j["enableJournal"] = enableJournal.load();
    j["enableFirewall"] = enableFirewall.load();
    j["enableReflector"] = enableReflector.load();
    j["enableAtomicActivation"] = enableAtomicActivation.load();
    j["enableRollback"] = enableRollback.load();
    j["enableModelAdapter"] = enableModelAdapter.load();
    
    j["emergencyBypass"] = emergencyBypass.load();
    
    j["requireASTValidation"] = requireASTValidation.load();
    j["requirePolicyCheck"] = requirePolicyCheck.load();
    j["requireSandboxBuild"] = requireSandboxBuild.load();
    j["requireRuntimeVerification"] = requireRuntimeVerification.load();
    j["requireHumanApprovalForHighRisk"] = requireHumanApprovalForHighRisk.load();
    j["autoCommitOnSuccess"] = autoCommitOnSuccess.load();
    j["autoRollbackOnFailure"] = autoRollbackOnFailure.load();
    
    j["fastPathForTrustedModels"] = fastPathForTrustedModels.load();
    j["maxValidationTimeMs"] = maxValidationTimeMs.load();
    j["maxSandboxBuildTimeMs"] = maxSandboxBuildTimeMs.load();
    j["maxRollbackTimeMs"] = maxRollbackTimeMs.load();
    
    std::ofstream file(path);
    if (file.is_open()) {
        file << j.dump(2);
    }
}

} // namespace Intent
} // namespace RawrXD
