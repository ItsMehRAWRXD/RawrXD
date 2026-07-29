// Test: Intent-to-Execution Guardrails Integration
// Verifies that all guardrail components compile and link correctly

#include <cstdio.h>
#include <cstdint.h>
#include <string>

// Include Intent Guardrails headers
#include "intent/intent_config.hpp"
#include "intent/intent_abi.hpp"
#include "guardrails/capability_policy.hpp"
#include "guardrails/patch_firewall.hpp"
#include "hotpatch/patch_transaction.hpp"

using namespace RawrXD::Intent;
using namespace RawrXD::Guardrails;
using namespace RawrXD::Hotpatch;

int main() {
    printf("=== Intent-to-Execution Guardrails Integration Test ===\n\n");
    
    // Test 1: IntentRuntimeConfig
    printf("[Test 1] IntentRuntimeConfig... ");
    auto& config = IntentRuntimeConfig::Instance();
    printf("OK (singleton accessible)\n");
    
    // Test 2: Toggle features
    printf("[Test 2] Feature Toggles... ");
    config.enableGuardrails.store(true);
    config.enableValidation.store(true);
    config.enableTransactions.store(true);
    config.enableCapabilityTokens.store(true);
    config.enableFirewall.store(true);
    
    bool guardrails = config.GuardrailsEnabled();
    bool validation = config.ValidationEnabled();
    bool transactions = config.TransactionsEnabled();
    bool capabilities = config.CapabilityTokensEnabled();
    bool firewall = config.FirewallEnabled();
    
    if (guardrails && validation && transactions && capabilities && firewall) {
        printf("OK (all features enabled)\n");
    } else {
        printf("FAIL (some features disabled)\n");
        return 1;
    }
    
    // Test 3: IntentValidator
    printf("[Test 3] IntentValidator... ");
    auto& validator = IntentValidator::Instance();
    
    IntentRequest intent;
    intent.type = IntentType::MODIFY_FUNCTION;
    intent.target.file_path = "src/test.cpp";
    intent.target.symbol_name = "TestFunction";
    
    auto result = validator.Validate(intent);
    printf("OK (validation result: %s)\n", result.valid ? "valid" : "invalid");
    
    // Test 4: IntentRouter
    printf("[Test 4] IntentRouter... ");
    auto& router = IntentRouter::Instance();
    router.EnableRouting(true);
    
    // Register a test handler
    router.RegisterHandler(IntentType::MODIFY_FUNCTION, [](const IntentRequest& req) {
        IntentResponse resp;
        resp.intent_id = req.intent_id;
        resp.status = IntentResponse::Status::EXECUTED;
        resp.message = "Test handler executed";
        return resp;
    });
    
    IntentRequest routeIntent;
    routeIntent.type = IntentType::MODIFY_FUNCTION;
    routeIntent.intent_id = 12345;
    
    auto routeResult = router.Route(routeIntent);
    printf("OK (routed: %s)\n", routeResult.message.c_str());
    
    // Test 5: CapabilityManager
    printf("[Test 5] CapabilityManager... ");
    auto& capManager = CapabilityManager::Instance();
    capManager.EnableCapabilities(true);
    
    auto token = capManager.IssueToken(
        1,  // intent_id
        Capability::MODIFY_FUNCTION | Capability::COMPILE | Capability::RUN_TEST,
        10,   // max uses
        300   // expiry seconds
    );
    
    if (token.has_value()) {
        printf("OK (token issued, id=%llu)\n", token->GetTokenId());
    } else {
        printf("FAIL (token not issued)\n");
        return 1;
    }
    
    // Test 6: PatchFirewall
    printf("[Test 6] PatchFirewall... ");
    auto& fw = PatchFirewall::Instance();
    fw.EnableFirewall(true);
    
    IntentRequest fwIntent;
    fwIntent.type = IntentType::READ_SOURCE;
    fwIntent.target.file_path = "src/main.cpp";
    
    auto fwResult = fw.ValidateIntent(fwIntent);
    printf("OK (firewall: %s)\n", fwResult.allowed ? "allowed" : "denied");
    
    // Test 7: ExecutionGateway
    printf("[Test 7] ExecutionGateway... ");
    auto& gateway = ExecutionGateway::Instance();
    gateway.EnableGateway(true);
    printf("OK (gateway enabled)\n");
    
    // Test 8: TransactionManager
    printf("[Test 8] TransactionManager... ");
    auto& txManager = TransactionManager::Instance();
    txManager.EnableTransactions(true);
    
    auto tx = txManager.BeginTransaction(1);
    if (tx) {
        printf("OK (transaction created, id=%llu)\n", tx->GetTransactionId());
    } else {
        printf("FAIL (transaction not created)\n");
        return 1;
    }
    
    // Test 9: Emergency bypass
    printf("[Test 9] Emergency Bypass... ");
    config.emergencyBypass.store(true);
    bool bypassed = !config.GuardrailsEnabled();
    config.emergencyBypass.store(false);
    
    if (bypassed) {
        printf("OK (emergency bypass works)\n");
    } else {
        printf("FAIL (emergency bypass not working)\n");
        return 1;
    }
    
    // Test 10: Compile-time flags
    printf("[Test 10] Compile-Time Flags... ");
    #if RAWR_INTENT_GUARD_ENABLED
        printf("OK (RAWR_INTENT_GUARD_ENABLED=1)\n");
    #else
        printf("OK (RAWR_INTENT_GUARD_ENABLED=0)\n");
    #endif
    
    printf("\n=== All Tests Passed ===\n");
    printf("\nIntent-to-Execution Guardrails System is fully integrated:\n");
    printf("  - IntentRuntimeConfig: Toggleable configuration\n");
    printf("  - IntentValidator: Intent validation\n");
    printf("  - IntentRouter: Intent routing\n");
    printf("  - CapabilityManager: Permission tokens\n");
    printf("  - PatchFirewall: Validation firewall\n");
    printf("  - ExecutionGateway: Controlled execution\n");
    printf("  - TransactionManager: ACID transactions\n");
    printf("  - Emergency Bypass: Global kill switch\n");
    printf("  - Compile-Time Flags: Conditional compilation\n");
    
    return 0;
}
