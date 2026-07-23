// Model Adapter - Unit Tests
// Tests the IReasoningBackend abstraction

#include <iostream>
#include <cassert>
#include <chrono>

#include "../src/intent/model_adapter.hpp"

using namespace RawrXD;
using namespace RawrXD::Intent;

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
#define ASSERT_NE(a, b) ASSERT_TRUE((a) != (b))

// ============================================================================
// Tests
// ============================================================================

TEST(model_adapter_singleton) {
    auto& adapter1 = ModelAdapter::Instance();
    auto& adapter2 = ModelAdapter::Instance();
    ASSERT_EQ(&adapter1, &adapter2);
}

TEST(model_adapter_toggle) {
    ASSERT_TRUE(ModelAdapter::Instance().IsEnabled());
    
    ModelAdapter::Instance().EnableAdapter(false);
    ASSERT_FALSE(ModelAdapter::Instance().IsEnabled());
    
    ModelAdapter::Instance().EnableAdapter(true);
    ASSERT_TRUE(ModelAdapter::Instance().IsEnabled());
}

TEST(backend_registration) {
    // Create test backends
    BackendConfig kimiConfig;
    kimiConfig.name = "kimi-test";
    kimiConfig.type = "kimi";
    kimiConfig.enabled = true;
    
    BackendConfig moonshotConfig;
    moonshotConfig.name = "moonshot-test";
    moonshotConfig.type = "moonshot";
    moonshotConfig.enabled = true;
    
    auto kimiBackend = std::make_shared<KimiBackend>(kimiConfig);
    auto moonshotBackend = std::make_shared<MoonshotBackend>(moonshotConfig);
    
    // Register backends
    ModelAdapter::Instance().RegisterBackend(kimiBackend);
    ModelAdapter::Instance().RegisterBackend(moonshotBackend);
    
    // Check registered
    auto names = ModelAdapter::Instance().GetBackendNames();
    ASSERT_TRUE(names.size() >= 2);
    
    // Unregister
    ModelAdapter::Instance().UnregisterBackend("kimi-test");
    ModelAdapter::Instance().UnregisterBackend("moonshot-test");
}

TEST(backend_selection) {
    // Create and register backends
    BackendConfig kimiConfig;
    kimiConfig.name = "kimi";
    kimiConfig.type = "kimi";
    kimiConfig.enabled = true;
    
    BackendConfig moonshotConfig;
    moonshotConfig.name = "moonshot";
    moonshotConfig.type = "moonshot";
    moonshotConfig.enabled = true;
    
    auto kimiBackend = std::make_shared<KimiBackend>(kimiConfig);
    auto moonshotBackend = std::make_shared<MoonshotBackend>(moonshotConfig);
    
    ModelAdapter::Instance().RegisterBackend(kimiBackend);
    ModelAdapter::Instance().RegisterBackend(moonshotBackend);
    
    // Select by capability
    auto selected = ModelAdapter::Instance().SelectBackend(ModelCapability::COMPLETION);
    ASSERT_NE(selected, nullptr);
    ASSERT_TRUE(selected->IsEnabled());
    ASSERT_TRUE(selected->Supports(ModelCapability::COMPLETION));
    
    // Select preferred
    auto preferred = ModelAdapter::Instance().SelectBackend(
        ModelCapability::COMPLETION, "kimi");
    ASSERT_NE(preferred, nullptr);
    ASSERT_EQ(preferred->GetName(), "Kimi");
    
    // Cleanup
    ModelAdapter::Instance().UnregisterBackend("kimi");
    ModelAdapter::Instance().UnregisterBackend("moonshot");
}

TEST(kimi_backend_capabilities) {
    BackendConfig config;
    config.name = "kimi";
    config.enabled = true;
    
    KimiBackend backend(config);
    
    ASSERT_TRUE(backend.Supports(ModelCapability::COMPLETION));
    ASSERT_TRUE(backend.Supports(ModelCapability::CHAT));
    ASSERT_TRUE(backend.Supports(ModelCapability::STREAMING));
    ASSERT_TRUE(backend.Supports(ModelCapability::FUNCTION_CALLING));
    ASSERT_TRUE(backend.Supports(ModelCapability::REASONING));
    ASSERT_TRUE(backend.Supports(ModelCapability::CODE_GENERATION));
    ASSERT_TRUE(backend.Supports(ModelCapability::CODE_ANALYSIS));
    ASSERT_TRUE(backend.Supports(ModelCapability::LONG_CONTEXT));
    ASSERT_TRUE(backend.Supports(ModelCapability::TOOL_USE));
    
    ASSERT_EQ(backend.GetName(), "Kimi");
    ASSERT_EQ(backend.GetMaxContextLength(), 200000u);
}

TEST(moonshot_backend_capabilities) {
    BackendConfig config;
    config.name = "moonshot";
    config.enabled = true;
    
    MoonshotBackend backend(config);
    
    ASSERT_TRUE(backend.Supports(ModelCapability::COMPLETION));
    ASSERT_TRUE(backend.Supports(ModelCapability::CHAT));
    ASSERT_TRUE(backend.Supports(ModelCapability::STREAMING));
    ASSERT_TRUE(backend.Supports(ModelCapability::FUNCTION_CALLING));
    ASSERT_TRUE(backend.Supports(ModelCapability::REASONING));
    ASSERT_TRUE(backend.Supports(ModelCapability::CODE_GENERATION));
    ASSERT_TRUE(backend.Supports(ModelCapability::CODE_ANALYSIS));
    ASSERT_TRUE(backend.Supports(ModelCapability::TOOL_USE));
    
    // Moonshot doesn't support LONG_CONTEXT like Kimi
    ASSERT_FALSE(backend.Supports(ModelCapability::LONG_CONTEXT));
    
    ASSERT_EQ(backend.GetName(), "Moonshot");
    ASSERT_EQ(backend.GetMaxContextLength(), 128000u);
}

TEST(gguf_backend_capabilities) {
    BackendConfig config;
    config.name = "gguf";
    config.enabled = true;
    
    GGUFBackend backend(config);
    
    ASSERT_TRUE(backend.Supports(ModelCapability::COMPLETION));
    ASSERT_TRUE(backend.Supports(ModelCapability::CHAT));
    ASSERT_TRUE(backend.Supports(ModelCapability::CODE_GENERATION));
    ASSERT_TRUE(backend.Supports(ModelCapability::CODE_ANALYSIS));
    
    // GGUF doesn't support all capabilities
    ASSERT_FALSE(backend.Supports(ModelCapability::FUNCTION_CALLING));
    ASSERT_FALSE(backend.Supports(ModelCapability::TOOL_USE));
    ASSERT_FALSE(backend.Supports(ModelCapability::LONG_CONTEXT));
    
    ASSERT_EQ(backend.GetName(), "GGUF");
    ASSERT_EQ(backend.GetMaxContextLength(), 32768u);
}

TEST(backend_completion) {
    BackendConfig config;
    config.name = "kimi";
    config.enabled = true;
    
    KimiBackend backend(config);
    
    ModelContext ctx;
    ctx.system_prompt = "You are a helpful coding assistant.";
    ctx.messages = {{"user", "Optimize this function"}};
    ctx.max_tokens = 1000;
    ctx.temperature = 0.7f;
    
    auto response = backend.Complete(ctx);
    ASSERT_TRUE(response.success);
    ASSERT_TRUE(response.confidence > 0);
    ASSERT_TRUE(response.tokens_used > 0);
    ASSERT_TRUE(response.latency_ms > 0);
}

TEST(backend_disabled) {
    BackendConfig config;
    config.name = "kimi";
    config.enabled = false;  // Disabled
    
    KimiBackend backend(config);
    
    ModelContext ctx;
    ctx.messages = {{"user", "Hello"}};
    
    auto response = backend.Complete(ctx);
    ASSERT_FALSE(response.success);
    ASSERT_TRUE(response.warnings.size() > 0);
}

TEST(backend_streaming) {
    BackendConfig config;
    config.name = "kimi";
    config.enabled = true;
    
    KimiBackend backend(config);
    
    ModelContext ctx;
    ctx.messages = {{"user", "Stream this"}};
    
    std::string accumulated;
    backend.CompleteStreaming(ctx, [&accumulated](const std::string& chunk) {
        accumulated += chunk;
    });
    
    ASSERT_FALSE(accumulated.empty());
}

TEST(model_context_building) {
    ModelContext ctx;
    ctx.system_prompt = "System prompt";
    ctx.messages = {
        {"user", "Hello"},
        {"assistant", "Hi there"},
        {"user", "Optimize this code"}
    };
    ctx.relevant_files = {"src/main.cpp", "src/utils.cpp"};
    ctx.relevant_symbols = {"main", "utils::helper"};
    ctx.compiler_errors = "";
    ctx.test_results = "All tests passed";
    ctx.telemetry = "Performance: 100ms";
    ctx.max_tokens = 4096;
    ctx.temperature = 0.7f;
    ctx.response_format = "json";
    
    ASSERT_EQ(ctx.messages.size(), 3);
    ASSERT_EQ(ctx.relevant_files.size(), 2);
    ASSERT_EQ(ctx.relevant_symbols.size(), 2);
}

TEST(model_response_conversion) {
    ModelResponse response;
    response.success = true;
    response.content = "{\"action\": \"modify\"}";
    response.confidence = 0.95f;
    response.tokens_used = 150;
    
    IntentRequest intent;
    intent.type = IntentType::MODIFY_FUNCTION;
    intent.target.file_path = "test.cpp";
    intent.confidence = 0.95f;
    response.intent = intent;
    
    auto converted = ModelAdapter::Instance().ConvertToIntent(response);
    ASSERT_EQ(converted.status, IntentStatus::PENDING_VALIDATION);
    ASSERT_EQ(converted.request.type, IntentType::MODIFY_FUNCTION);
}

TEST(backend_config_persistence) {
    BackendConfig config;
    config.name = "test-backend";
    config.type = "kimi";
    config.endpoint = "https://api.example.com";
    config.api_key = "test-key";
    config.model_name = "test-model";
    config.timeout_ms = 30000;
    config.max_retries = 3;
    config.enabled = true;
    config.priority = 5;
    
    // Save to temp file
    std::string tempPath = "test_config.json";
    config.SaveToFile(tempPath);
    
    // Load back
    BackendConfig loaded;
    loaded.LoadFromFile(tempPath);
    
    ASSERT_EQ(loaded.name, config.name);
    ASSERT_EQ(loaded.type, config.type);
    ASSERT_EQ(loaded.endpoint, config.endpoint);
    ASSERT_EQ(loaded.model_name, config.model_name);
    ASSERT_EQ(loaded.timeout_ms, config.timeout_ms);
    ASSERT_EQ(loaded.max_retries, config.max_retries);
    ASSERT_EQ(loaded.enabled, config.enabled);
    ASSERT_EQ(loaded.priority, config.priority);
    
    // Cleanup
    std::remove(tempPath.c_str());
}

TEST(backend_health_check) {
    BackendConfig config;
    config.name = "kimi";
    config.enabled = true;
    
    KimiBackend backend(config);
    ASSERT_TRUE(backend.IsHealthy());
    
    backend.SetEnabled(false);
    ASSERT_FALSE(backend.IsHealthy());
}

TEST(model_capability_flags) {
    // Test bitwise operations
    auto caps = ModelCapability::COMPLETION | ModelCapability::CHAT;
    
    ASSERT_TRUE(static_cast<uint32_t>(caps) & 
                static_cast<uint32_t>(ModelCapability::COMPLETION));
    ASSERT_TRUE(static_cast<uint32_t>(caps) & 
                static_cast<uint32_t>(ModelCapability::CHAT));
    ASSERT_FALSE(static_cast<uint32_t>(caps) & 
                 static_cast<uint32_t>(ModelCapability::STREAMING));
}

TEST(adapter_with_disabled_backend) {
    // Create disabled backend
    BackendConfig config;
    config.name = "disabled";
    config.enabled = false;
    
    auto backend = std::make_shared<KimiBackend>(config);
    ModelAdapter::Instance().RegisterBackend(backend);
    
    // Should not select disabled backend
    auto selected = ModelAdapter::Instance().SelectBackend(ModelCapability::COMPLETION);
    if (selected) {
        ASSERT_NE(selected->GetName(), "Kimi");  // Should not be the disabled one
    }
    
    ModelAdapter::Instance().UnregisterBackend("disabled");
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     MODEL ADAPTER - UNIT TESTS                                    ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
    
    // Core Tests
    std::cout << "┌─ Core Adapter Tests ──────────────────────────────────────────────┐\n";
    RUN_TEST(model_adapter_singleton);
    RUN_TEST(model_adapter_toggle);
    RUN_TEST(backend_registration);
    RUN_TEST(backend_selection);
    std::cout << "└───────────────────────────────────────────────────────────────────┘\n\n";
    
    // Backend Capability Tests
    std::cout << "┌─ Backend Capability Tests ────────────────────────────────────────┐\n";
    RUN_TEST(kimi_backend_capabilities);
    RUN_TEST(moonshot_backend_capabilities);
    RUN_TEST(gguf_backend_capabilities);
    std::cout << "└───────────────────────────────────────────────────────────────────┘\n\n";
    
    // Functionality Tests
    std::cout << "┌─ Functionality Tests ─────────────────────────────────────────────┐\n";
    RUN_TEST(backend_completion);
    RUN_TEST(backend_disabled);
    RUN_TEST(backend_streaming);
    RUN_TEST(model_context_building);
    RUN_TEST(model_response_conversion);
    std::cout << "└───────────────────────────────────────────────────────────────────┘\n\n";
    
    // Configuration Tests
    std::cout << "┌─ Configuration Tests ─────────────────────────────────────────────┐\n";
    RUN_TEST(backend_config_persistence);
    RUN_TEST(backend_health_check);
    RUN_TEST(model_capability_flags);
    RUN_TEST(adapter_with_disabled_backend);
    std::cout << "└───────────────────────────────────────────────────────────────────┘\n\n";
    
    // Summary
    std::cout << "╔═══════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  TEST RESULTS: " << testsPassed << " passed, " << testsFailed << " failed";
    std::cout << std::string(35 - std::to_string(testsPassed).length() - std::to_string(testsFailed).length(), ' ') << "║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
    
    return testsFailed > 0 ? 1 : 0;
}
