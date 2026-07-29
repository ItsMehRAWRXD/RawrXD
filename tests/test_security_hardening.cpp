// Security Hardening - Integration Tests
// Tests production-grade security controls

#include <iostream>
#include <cassert>
#include <thread>
#include <chrono>

#include "../src/security/SecurityHardening.hpp"

using namespace RawrXD;
using namespace RawrXD::Security;

// ============================================================================
// Test Utilities
// ============================================================================

static int testsPassed = 0;
static int testsFailed = 0;

#define TEST(name) void test_##name()
#define RUN_TEST(name) \
    std::cout << "  " #name "... "; \
    try { \
        test_##name(); \
        std::cout << "PASSED\n"; \
        testsPassed++; \
    } catch (const std::exception& e) { \
        std::cout << "FAILED: " << e.what() << "\n"; \
        testsFailed++; \
    }

#define ASSERT_TRUE(expr) \
    if (!(expr)) { \
        throw std::runtime_error("Assertion failed: " #expr); \
    }

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))
#define ASSERT_EQ(a, b) ASSERT_TRUE((a) == (b))

// ============================================================================
// Tests
// ============================================================================

TEST(audit_log_initialization) {
    ASSERT_TRUE(AuditLog::Instance().Initialize("test_audit.log"));
    ASSERT_TRUE(AuditLog::Instance().IsInitialized());
    
    auto stats = AuditLog::Instance().GetStats();
    ASSERT_TRUE(stats.totalEvents >= 1);  // Startup event
    
    AuditLog::Instance().Shutdown();
    ASSERT_FALSE(AuditLog::Instance().IsInitialized());
}

TEST(audit_log_event_logging) {
    AuditLog::Instance().Initialize("test_audit.log");
    
    // Log an intent
    AuditLog::Instance().LogIntentReceived(1, 1, "MODIFY_FUNCTION");
    
    auto stats = AuditLog::Instance().GetStats();
    ASSERT_EQ(stats.totalEvents, 2);  // Startup + intent
    
    // Query by agent
    auto events = AuditLog::Instance().QueryEventsByAgent(1, 10);
    ASSERT_TRUE(events.size() >= 1);
    
    AuditLog::Instance().Shutdown();
}

TEST(audit_log_chain_integrity) {
    AuditLog::Instance().Initialize("test_audit.log");
    
    // Log multiple events
    for (int i = 0; i < 10; i++) {
        AuditLog::Instance().LogIntentReceived(i, 1, "TEST");
    }
    
    // Verify chain
    ASSERT_TRUE(AuditLog::Instance().VerifyChain());
    
    AuditLog::Instance().Shutdown();
}

TEST(rate_limiter_initialization) {
    RateLimiter::Limits limits;
    limits.intentsPerSecond = 5;
    limits.intentsPerMinute = 30;
    limits.intentsPerHour = 100;
    limits.patchesPerSecond = 2;
    limits.resourcesPerSecond = 10;
    limits.failedAttemptsBeforeLockout = 3;
    limits.lockoutDurationSeconds = 60;
    
    ASSERT_TRUE(RateLimiter::Instance().Initialize(limits));
    RateLimiter::Instance().Shutdown();
}

TEST(rate_limiter_enforcement) {
    RateLimiter::Limits limits;
    limits.intentsPerSecond = 2;
    limits.intentsPerMinute = 10;
    limits.intentsPerHour = 100;
    limits.patchesPerSecond = 5;
    limits.resourcesPerSecond = 10;
    limits.failedAttemptsBeforeLockout = 5;
    limits.lockoutDurationSeconds = 60;
    
    RateLimiter::Instance().Initialize(limits);
    
    // Should allow first 2 intents
    ASSERT_TRUE(RateLimiter::Instance().CanExecuteIntent(1));
    RateLimiter::Instance().RecordIntent(1);
    
    ASSERT_TRUE(RateLimiter::Instance().CanExecuteIntent(1));
    RateLimiter::Instance().RecordIntent(1);
    
    // Third intent should be rate limited
    ASSERT_FALSE(RateLimiter::Instance().CanExecuteIntent(1));
    
    RateLimiter::Instance().Shutdown();
}

TEST(rate_limiter_lockout) {
    RateLimiter::Limits limits;
    limits.intentsPerSecond = 100;
    limits.intentsPerMinute = 1000;
    limits.intentsPerHour = 10000;
    limits.patchesPerSecond = 5;
    limits.resourcesPerSecond = 10;
    limits.failedAttemptsBeforeLockout = 3;
    limits.lockoutDurationSeconds = 1;  // Short for testing
    
    RateLimiter::Instance().Initialize(limits);
    
    // Record failures
    RateLimiter::Instance().RecordFailure(1);
    RateLimiter::Instance().RecordFailure(1);
    ASSERT_FALSE(RateLimiter::Instance().IsLockedOut(1));
    
    RateLimiter::Instance().RecordFailure(1);
    ASSERT_TRUE(RateLimiter::Instance().IsLockedOut(1));
    
    // Wait for lockout to expire
    std::this_thread::sleep_for(std::chrono::seconds(2));
    ASSERT_FALSE(RateLimiter::Instance().IsLockedOut(1));
    
    RateLimiter::Instance().Shutdown();
}

TEST(input_validator_symbol_name) {
    InputValidator::ValidationRules rules;
    rules.maxSymbolNameLength = 50;
    rules.requireAsciiOnly = true;
    rules.blockDangerousPatterns = true;
    
    InputValidator::Instance().Initialize(rules);
    
    std::string error;
    
    // Valid symbol name
    ASSERT_TRUE(InputValidator::Instance().ValidateSymbolName(
        "MyClass::myMethod", error));
    
    // Too long
    ASSERT_FALSE(InputValidator::Instance().ValidateSymbolName(
        std::string(100, 'a'), error));
    
    // Non-ASCII
    ASSERT_FALSE(InputValidator::Instance().ValidateSymbolName(
        "Tëst", error));
    
    // Dangerous pattern
    ASSERT_FALSE(InputValidator::Instance().ValidateSymbolName(
        "system(\"rm -rf\")", error));
}

TEST(input_validator_file_path) {
    InputValidator::ValidationRules rules;
    rules.maxFilePathLength = 100;
    
    InputValidator::Instance().Initialize(rules);
    
    std::string error;
    
    // Valid path
    ASSERT_TRUE(InputValidator::Instance().ValidateFilePath(
        "src/main.cpp", error));
    
    // Path traversal
    ASSERT_FALSE(InputValidator::Instance().ValidateFilePath(
        "../../../etc/passwd", error));
    
    // Too long
    ASSERT_FALSE(InputValidator::Instance().ValidateFilePath(
        std::string(200, 'a'), error));
}

TEST(input_validator_dangerous_patterns) {
    InputValidator::ValidationRules rules;
    rules.blockDangerousPatterns = true;
    
    InputValidator::Instance().Initialize(rules);
    
    ASSERT_TRUE(InputValidator::Instance().ContainsDangerousPattern("system("));
    ASSERT_TRUE(InputValidator::Instance().ContainsDangerousPattern("exec("));
    ASSERT_TRUE(InputValidator::Instance().ContainsShellInjection("; rm -rf"));
    ASSERT_TRUE(InputValidator::Instance().ContainsPathTraversal("../"));
    
    ASSERT_FALSE(InputValidator::Instance().ContainsDangerousPattern("safeFunction"));
}

TEST(security_manager_initialization) {
    ASSERT_TRUE(SecurityManager::Instance().Initialize(SecurityLevel::STANDARD));
    ASSERT_TRUE(SecurityManager::Instance().IsInitialized());
    ASSERT_EQ(static_cast<int>(SecurityManager::Instance().GetSecurityLevel()), 
              static_cast<int>(SecurityLevel::STANDARD));
    
    SecurityManager::Instance().Shutdown();
}

TEST(security_manager_pre_execution_checks) {
    SecurityManager::Instance().Initialize(SecurityLevel::STANDARD);
    
    std::string error;
    ASSERT_TRUE(SecurityManager::Instance().ValidatePreExecution(1, 1, error));
    
    SecurityManager::Instance().Shutdown();
}

TEST(security_manager_lockdown) {
    SecurityManager::Instance().Initialize(SecurityLevel::STANDARD);
    
    ASSERT_FALSE(SecurityManager::Instance().IsInLockdown());
    
    SecurityManager::Instance().EmergencyLockdown("Test lockdown");
    ASSERT_TRUE(SecurityManager::Instance().IsInLockdown());
    
    std::string error;
    ASSERT_FALSE(SecurityManager::Instance().ValidatePreExecution(1, 1, error));
    ASSERT_EQ(error, "System is in lockdown");
    
    SecurityManager::Instance().LiftLockdown();
    ASSERT_FALSE(SecurityManager::Instance().IsInLockdown());
    
    SecurityManager::Instance().Shutdown();
}

TEST(security_manager_audit) {
    SecurityManager::Instance().Initialize(SecurityLevel::STANDARD);
    
    // Run security audit
    ASSERT_TRUE(SecurityManager::Instance().RunSecurityAudit());
    
    // Get stats
    auto stats = SecurityManager::Instance().GetStats();
    ASSERT_TRUE(stats.totalEventsLogged >= 1);
    
    SecurityManager::Instance().Shutdown();
}

TEST(security_level_transitions) {
    SecurityManager::Instance().Initialize(SecurityLevel::MINIMAL);
    ASSERT_EQ(static_cast<int>(SecurityManager::Instance().GetSecurityLevel()), 
              static_cast<int>(SecurityLevel::MINIMAL));
    
    SecurityManager::Instance().SetSecurityLevel(SecurityLevel::HIGH);
    ASSERT_EQ(static_cast<int>(SecurityManager::Instance().GetSecurityLevel()), 
              static_cast<int>(SecurityLevel::HIGH));
    
    SecurityManager::Instance().SetSecurityLevel(SecurityLevel::MAXIMUM);
    ASSERT_EQ(static_cast<int>(SecurityManager::Instance().GetSecurityLevel()), 
              static_cast<int>(SecurityLevel::MAXIMUM));
    
    SecurityManager::Instance().Shutdown();
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     SECURITY HARDENING - INTEGRATION TESTS                      ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
    
    // Audit Log Tests
    std::cout << "┌─ Audit Log Tests ───────────────────────────────────────────────┐\n";
    RUN_TEST(audit_log_initialization);
    RUN_TEST(audit_log_event_logging);
    RUN_TEST(audit_log_chain_integrity);
    std::cout << "└───────────────────────────────────────────────────────────────────┘\n\n";
    
    // Rate Limiter Tests
    std::cout << "┌─ Rate Limiter Tests ────────────────────────────────────────────┐\n";
    RUN_TEST(rate_limiter_initialization);
    RUN_TEST(rate_limiter_enforcement);
    RUN_TEST(rate_limiter_lockout);
    std::cout << "└───────────────────────────────────────────────────────────────────┘\n\n";
    
    // Input Validator Tests
    std::cout << "┌─ Input Validator Tests ─────────────────────────────────────────┐\n";
    RUN_TEST(input_validator_symbol_name);
    RUN_TEST(input_validator_file_path);
    RUN_TEST(input_validator_dangerous_patterns);
    std::cout << "└───────────────────────────────────────────────────────────────────┘\n\n";
    
    // Security Manager Tests
    std::cout << "┌─ Security Manager Tests ────────────────────────────────────────┐\n";
    RUN_TEST(security_manager_initialization);
    RUN_TEST(security_manager_pre_execution_checks);
    RUN_TEST(security_manager_lockdown);
    RUN_TEST(security_manager_audit);
    RUN_TEST(security_level_transitions);
    std::cout << "└───────────────────────────────────────────────────────────────────┘\n\n";
    
    // Summary
    std::cout << "╔═══════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  TEST RESULTS: " << testsPassed << " passed, " << testsFailed << " failed";
    std::cout << std::string(35 - std::to_string(testsPassed).length() - std::to_string(testsFailed).length(), ' ') << "║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
    
    return testsFailed > 0 ? 1 : 0;
}
