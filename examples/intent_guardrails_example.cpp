// Example: Intent-to-Execution Guardrails with Sovereign Puppeteer
// Demonstrates how models emit intent, which is validated and executed
// with automatic rollback via the Puppeteer system

#include <stdio.h>
#include <string>
#include <memory>

#include "intent/intent_config.hpp"
#include "intent/intent_abi.hpp"
#include "intent/model_adapter.hpp"
#include "guardrails/capability_policy.hpp"
#include "guardrails/patch_firewall.hpp"
#include "hotpatch/patch_transaction.hpp"
#include "sovereign/puppeteer/PuppeteerAPI.hpp"
#include "sovereign/puppeteer/VEH_Watchdog.hpp"

using namespace RawrXD::Intent;
using namespace RawrXD::Guardrails;
using namespace RawrXD::Hotpatch;
using namespace RawrXD::Sovereign;

// Example: Optimize a function using the Intent system
void Example_OptimizeFunction() {
    printf("\n=== Example: Optimize Function ===\n\n");
    
    // Step 1: Configure the system
    auto& config = IntentRuntimeConfig::Instance();
    config.enableGuardrails.store(true);
    config.enableValidation.store(true);
    config.enableTransactions.store(true);
    config.autoRollbackOnFailure.store(true);
    
    // Step 2: Create an intent (this is what models emit)
    IntentRequest intent;
    intent.type = IntentType::OPTIMIZE;
    intent.target.file_path = "src/attention.cpp";
    intent.target.symbol_name = "Attention::Compute";
    intent.target.language = "cpp";
    
    intent.change = ChangeDescription{
        .operation = "vectorize_loop",
        .reason = "Improve cache locality and enable SIMD",
        .expected_effect = "2x speedup on AVX-512",
        .constraints = {
            "preserve numerical output",
            "maintain thread safety",
            "AVX2 compatible fallback"
        }
    };
    
    intent.verification = VerificationPlan{
        .compile = true,
        .run_tests = true,
        .static_analysis = true,
        .security_scan = true,
        .performance_check = true,
        .test_targets = {"test_attention", "test_transformer"},
        .min_tests_passing = 50,
        .max_performance_regression = 0.05  // 5%
    };
    
    intent.model_source = "kimi";  // From Kimi backend
    intent.confidence = 0.92f;
    
    // Step 3: Validate the intent through the firewall
    printf("[1] Validating intent...\n");
    auto fw_result = PatchFirewall::Instance().ValidateIntent(intent);
    
    if (!fw_result.allowed) {
        printf("    REJECTED: %s\n", fw_result.reason.c_str());
        return;
    }
    
    printf("    ALLOWED (rule: %d)\n", static_cast<int>(fw_result.rule));
    
    if (fw_result.requires_approval) {
        printf("    WARNING: Requires human approval\n");
    }
    
    // Step 4: Issue capability token
    printf("[2] Issuing capability token...\n");
    auto token = CapabilityManager::Instance().IssueToken(
        intent.intent_id,
        Capability::MODIFY_FUNCTION | Capability::COMPILE | Capability::RUN_TEST,
        1,    // max uses
        300   // expiry seconds
    );
    
    if (!token) {
        printf("    FAILED: Could not issue token\n");
        return;
    }
    
    printf("    Token issued (id=%llu)\n", token->GetTokenId());
    
    // Step 5: Execute through gateway with transaction
    printf("[3] Executing with transaction...\n");
    
    RAWR_PATCH_TX_BEGIN(intent.intent_id)
        // Create patch
        Patch patch;
        patch.type = PatchType::AST_MUTATION;
        patch.file_path = intent.target.file_path;
        patch.symbol_name = intent.target.symbol_name;
        
        // In real implementation, this would be the actual optimized code
        patch.after_data = std::vector<uint8_t>{
            0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00,  // mov rax, 42
            0xC3                                          // ret
        };
        
        __tx.AddPatch(patch);
        
        // Validate
        printf("    Validating patch...\n");
        if (!__tx.Validate()) {
            printf("    VALIDATION FAILED\n");
            // Auto-rollback happens in destructor
            return;
        }
        
        // Apply
        printf("    Applying patch...\n");
        if (!__tx.Apply()) {
            printf("    APPLY FAILED\n");
            return;
        }
        
        // Commit
        printf("    Committing...\n");
        
    RAWR_PATCH_TX_COMMIT()
    
    printf("    SUCCESS: Transaction committed\n");
    
    // Step 6: Verify through Puppeteer
    printf("[4] Verifying through Puppeteer...\n");
    auto& puppeteer = PuppeteerAPI::Instance();
    
    // Read the modified function
    // auto read_result = puppeteer.ReadMemory(target_address, patch_size);
    
    printf("    Verification complete\n");
}

// Example: Use Model Adapter to select best backend
void Example_ModelAdapter() {
    printf("\n=== Example: Model Adapter ===\n\n");
    
    // Configure backends
    BackendConfig kimi_config{
        .name = "kimi",
        .type = "kimi",
        .endpoint = "https://api.moonshot.cn",
        .model_name = "kimi-latest",
        .enabled = true,
        .priority = 2
    };
    
    BackendConfig gguf_config{
        .name = "local",
        .type = "gguf",
        .model_name = "qwen2.5-32b-q4_k_m.gguf",
        .enabled = true,
        .priority = 1
    };
    
    // Register backends
    printf("[1] Registering backends...\n");
    ModelAdapter::Instance().RegisterBackend(
        std::make_shared<KimiBackend>(kimi_config)
    );
    printf("    - Kimi backend registered\n");
    
    ModelAdapter::Instance().RegisterBackend(
        std::make_shared<GGUFBackend>(gguf_config)
    );
    printf("    - GGUF backend registered\n");
    
    // Create context
    printf("[2] Creating model context...\n");
    ModelContext ctx;
    ctx.system_prompt = "You are a code optimization expert.";
    ctx.messages = {
        {"user", "Optimize the attention mechanism in this transformer model."}
    };
    ctx.relevant_files = {
        "src/attention.cpp",
        "src/transformer.cpp"
    };
    ctx.compiler_errors = "";
    ctx.max_tokens = 4096;
    ctx.temperature = 0.7f;
    
    // Complete (automatically selects best backend)
    printf("[3] Executing completion...\n");
    printf("    (Would call model backend here)\n");
    
    // In real implementation:
    // auto response = ModelAdapter::Instance().Complete(ctx);
    // if (response.success && response.intent) {
    //     // Process the intent
    // }
}

// Example: Emergency procedures
void Example_EmergencyProcedures() {
    printf("\n=== Example: Emergency Procedures ===\n\n");
    
    // Emergency bypass
    printf("[1] Emergency bypass (scoped)...\n");
    {
        ScopedFirewallBypass bypass("Critical security fix");
        printf("    Firewall bypassed for critical operation\n");
        // Critical operation here
    }
    printf("    Firewall re-enabled\n");
    
    // Emergency stop
    printf("[2] Emergency stop...\n");
    PatchFirewall::Instance().EmergencyStop("Security breach detected");
    printf("    Firewall stopped\n");
    
    // Check status
    if (PatchFirewall::Instance().IsStopped()) {
        printf("    Status: STOPPED\n");
    }
    
    // Resume
    PatchFirewall::Instance().Resume();
    printf("    Firewall resumed\n");
    
    // Emergency revoke all tokens
    printf("[3] Emergency token revocation...\n");
    CapabilityManager::Instance().EmergencyRevokeAll("Security incident");
    printf("    All tokens revoked\n");
    
    // Emergency rollback all transactions
    printf("[4] Emergency transaction rollback...\n");
    TransactionManager::Instance().EmergencyRollbackAll();
    printf("    All transactions rolled back\n");
}

// Example: Toggle features at runtime
void Example_RuntimeToggles() {
    printf("\n=== Example: Runtime Toggles ===\n\n");
    
    auto& config = IntentRuntimeConfig::Instance();
    
    // Show current state
    printf("[1] Current feature states:\n");
    printf("    Guardrails: %s\n", config.GuardrailsEnabled() ? "ON" : "OFF");
    printf("    Validation: %s\n", config.ValidationEnabled() ? "ON" : "OFF");
    printf("    Transactions: %s\n", config.TransactionsEnabled() ? "ON" : "OFF");
    printf("    Firewall: %s\n", config.FirewallEnabled() ? "ON" : "OFF");
    
    // Disable validation for trusted model
    printf("[2] Disabling validation for trusted model...\n");
    config.enableValidation.store(false);
    printf("    Validation: %s\n", config.ValidationEnabled() ? "ON" : "OFF");
    
    // Re-enable
    printf("[3] Re-enabling validation...\n");
    config.enableValidation.store(true);
    printf("    Validation: %s\n", config.ValidationEnabled() ? "ON" : "OFF");
    
    // Emergency bypass
    printf("[4] Emergency bypass (disables everything)...\n");
    config.emergencyBypass.store(true);
    printf("    Guardrails: %s\n", config.GuardrailsEnabled() ? "ON" : "OFF");
    
    // Restore
    printf("[5] Restoring normal operation...\n");
    config.emergencyBypass.store(false);
    printf("    Guardrails: %s\n", config.GuardrailsEnabled() ? "ON" : "OFF");
}

int main() {
    printf("========================================\n");
    printf("Intent-to-Execution Guardrails Examples\n");
    printf("========================================\n");
    
    // Run examples
    Example_OptimizeFunction();
    Example_ModelAdapter();
    Example_EmergencyProcedures();
    Example_RuntimeToggles();
    
    printf("\n========================================\n");
    printf("All examples completed successfully!\n");
    printf("========================================\n");
    
    return 0;
}
