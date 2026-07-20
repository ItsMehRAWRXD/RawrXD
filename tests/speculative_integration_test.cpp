//============================================================================
// speculative_integration_test.cpp
//
// VAL-032: Integration Test Suite
//
// Validates:
//   - Kernel dispatch (AVX-512 vs Scalar)
//   - Speculative execution pipeline
//   - B008 residency fabric integration
//   - Telemetry collection
//============================================================================

#include "../src/inference/speculative_execution_integration.hpp"
#include "../src/kernels/tree_attention_dispatch.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
#include <memory>

using namespace RawrXD;
using namespace RawrXD::Inference;
using namespace RawrXD::Kernels;

//============================================================================
// Mock Draft Model (N-gram style)
//============================================================================
class MockDraftModel : public IDraftModel {
public:
    uint32_t Predict(const std::vector<uint32_t>& context) override {
        // Simple: predict next token as last token + 1
        if (context.empty()) return 1;
        return context.back() + 1;
    }
    
    float GetProbability(uint32_t token) override {
        return 0.7f;  // Fixed confidence
    }
    
    std::vector<uint32_t> PredictBatch(
        const std::vector<uint32_t>& context,
        uint32_t count
    ) override {
        std::vector<uint32_t> result;
        uint32_t last = context.empty() ? 0 : context.back();
        for (uint32_t i = 0; i < count; i++) {
            result.push_back(last + i + 1);
        }
        return result;
    }
    
    std::vector<std::string> GetWeightIds() const override {
        return {"draft_embedding", "draft_head"};
    }
    
    bool IsReady() const override { return true; }
};

//============================================================================
// Mock Target Model
//============================================================================
class MockTargetModel : public ITargetModel {
public:
    bool VerifyBatch(
        const std::vector<uint32_t>& draft_tokens,
        std::vector<float>& out_logits
    ) override {
        // Accept first 2, reject rest
        out_logits.resize(draft_tokens.size());
        for (size_t i = 0; i < draft_tokens.size(); i++) {
            out_logits[i] = (i < 2) ? 0.9f : 0.3f;
        }
        return true;
    }
    
    uint32_t Generate(const std::vector<uint32_t>& context) override {
        return context.empty() ? 1 : context.back() + 1;
    }
    
    bool IsReady() const override { return true; }
};

//============================================================================
// Test Results
//============================================================================
struct TestResult {
    const char* name;
    bool passed;
    const char* error_msg;
};

//============================================================================
// Test 1: Kernel Dispatch
//============================================================================
TestResult Test_KernelDispatch() {
    TestResult result = {"KernelDispatch", false, nullptr};
    
    auto kernel = TreeAttentionDispatcher::SelectKernel();
    
    if (kernel.verify == nullptr) {
        result.error_msg = "Verify function is null";
        return result;
    }
    
    if (kernel.invalidate_kv == nullptr) {
        result.error_msg = "Invalidate function is null";
        return result;
    }
    
    if (kernel.name == nullptr || strlen(kernel.name) == 0) {
        result.error_msg = "Kernel name is empty";
        return result;
    }
    
    printf("  Selected kernel: %s (v%d)\n", kernel.name, kernel.version);
    result.passed = true;
    return result;
}

//============================================================================
// Test 2: Execution Engine Creation
//============================================================================
TestResult Test_ExecutionEngine() {
    TestResult result = {"ExecutionEngine", false, nullptr};
    
    TreeAttentionConfig config;
    config.max_candidates = 16;
    config.embedding_dim = 64;
    
    auto engine = std::make_unique<SpeculativeExecutionEngine>(config);
    
    if (!engine) {
        result.error_msg = "Failed to create execution engine";
        return result;
    }
    
    const auto& telemetry = engine->GetTelemetry();
    if (telemetry.candidates_verified != 0) {
        result.error_msg = "Telemetry not initialized";
        return result;
    }
    
    result.passed = true;
    return result;
}

//============================================================================
// Test 3: Pipeline Initialization
//============================================================================
TestResult Test_PipelineInitialization() {
    TestResult result = {"PipelineInitialization", false, nullptr};
    
    auto draft = std::make_unique<MockDraftModel>();
    auto target = std::make_unique<MockTargetModel>();
    
    SpeculativeConfig config;
    config.draft_tokens = 4;
    config.acceptance_threshold = 0.6f;
    
    auto pipeline = std::make_unique<SpeculativeExecutionPipeline>(
        std::move(draft),
        std::move(target),
        config
    );
    
    if (!pipeline->Initialize()) {
        result.error_msg = "Pipeline initialization failed";
        return result;
    }
    
    if (!pipeline->IsReady()) {
        result.error_msg = "Pipeline not ready after init";
        return result;
    }
    
    printf("  Kernel: %s\n", pipeline->GetKernelName());
    result.passed = true;
    return result;
}

//============================================================================
// Test 4: Token Generation
//============================================================================
TestResult Test_TokenGeneration() {
    TestResult result = {"TokenGeneration", false, nullptr};
    
    auto draft = std::make_unique<MockDraftModel>();
    auto target = std::make_unique<MockTargetModel>();
    
    SpeculativeConfig config;
    config.draft_tokens = 4;
    config.enable_tree_attention = true;
    
    auto pipeline = std::make_unique<SpeculativeExecutionPipeline>(
        std::move(draft),
        std::move(target),
        config
    );
    
    if (!pipeline->Initialize()) {
        result.error_msg = "Init failed";
        return result;
    }
    
    std::vector<uint32_t> prompt = {1, 2, 3};
    auto gen_result = pipeline->Generate(prompt, 5);
    
    if (gen_result.accepted_tokens.empty()) {
        result.error_msg = "No tokens generated";
        return result;
    }
    
    printf("  Generated %zu tokens\n", gen_result.accepted_tokens.size());
    printf("  Acceptance rate: %.2f%%\n", gen_result.acceptance_rate * 100);
    
    result.passed = true;
    return result;
}

//============================================================================
// Test 5: Telemetry Collection
//============================================================================
TestResult Test_Telemetry() {
    TestResult result = {"Telemetry", false, nullptr};
    
    auto draft = std::make_unique<MockDraftModel>();
    auto target = std::make_unique<MockTargetModel>();
    
    SpeculativeConfig config;
    config.enable_kernel_telemetry = true;
    
    auto pipeline = std::make_unique<SpeculativeExecutionPipeline>(
        std::move(draft),
        std::move(target),
        config
    );
    
    if (!pipeline->Initialize()) {
        result.error_msg = "Init failed";
        return result;
    }
    
    // Generate some tokens
    std::vector<uint32_t> prompt = {1, 2, 3};
    pipeline->Generate(prompt, 3);
    
    const auto& telemetry = pipeline->GetTelemetry();
    
    if (telemetry.candidates_verified == 0) {
        result.error_msg = "No candidates verified";
        return result;
    }
    
    // Export and print
    auto json = ExportTelemetryToJSON(telemetry);
    printf("  Telemetry JSON:\n%s\n", json.c_str());
    
    PrintTelemetrySummary(telemetry);
    
    result.passed = true;
    return result;
}

//============================================================================
// Test 6: Residency Integration (without actual planner)
//============================================================================
TestResult Test_ResidencyIntegration() {
    TestResult result = {"ResidencyIntegration", false, nullptr};
    
    auto draft = std::make_unique<MockDraftModel>();
    auto target = std::make_unique<MockTargetModel>();
    
    SpeculativeConfig config;
    config.enable_residency_hooks = true;
    
    auto pipeline = std::make_unique<SpeculativeExecutionPipeline>(
        std::move(draft),
        std::move(target),
        config
    );
    
    if (!pipeline->Initialize()) {
        result.error_msg = "Init failed";
        return result;
    }
    
    // Test with null planner (should not crash)
    pipeline->SetResidencyPlanner(nullptr);
    
    std::vector<uint32_t> prompt = {1, 2, 3};
    pipeline->Generate(prompt, 2);
    
    // Verify it handles null gracefully
    if (pipeline->GetResidencyPlanner() != nullptr) {
        result.error_msg = "Residency planner should be null";
        return result;
    }
    
    result.passed = true;
    return result;
}

//============================================================================
// Main
//============================================================================
int main() {
    printf("VAL-032 Integration Test Suite\n");
    printf("===============================\n\n");
    
    TestResult tests[] = {
        Test_KernelDispatch(),
        Test_ExecutionEngine(),
        Test_PipelineInitialization(),
        Test_TokenGeneration(),
        Test_Telemetry(),
        Test_ResidencyIntegration()
    };
    
    int passed = 0;
    int failed = 0;
    
    printf("\nTest Results:\n");
    printf("-------------\n");
    
    for (const auto& test : tests) {
        printf("%-25s: %s", test.name, test.passed ? "PASS" : "FAIL");
        if (!test.passed && test.error_msg) {
            printf(" - %s", test.error_msg);
        }
        printf("\n");
        
        if (test.passed) passed++;
        else failed++;
    }
    
    printf("\n");
    printf("Total: %d passed, %d failed\n", passed, failed);
    
    return failed > 0 ? 1 : 0;
}
