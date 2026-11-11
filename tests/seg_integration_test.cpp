// ============================================================================
// SEG Integration Test - End-to-End Sovereign Pipeline Validation
// ============================================================================
// Tests the full pipeline:
//   Text → Tokenizer → SEG → Q4K Decoder → Logits → Sampling → Tokens → Text
//
// With telemetry validation at each step.
// ============================================================================

#include <iostream>
#include <cassert>
#include <chrono>
#include <vector>
#include <string>
#include <cmath>

// Include SEG components
#include "../src/gateway/seg_gateway.hpp"
#include "../src/runtime/tokenizer_runtime.h"
#include "../src/model/model_context.h"

using namespace rawrxd::gateway;
using namespace rawrxd::runtime;
using namespace rawrxd::model;

// ============================================================================
// Test Configuration
// ============================================================================
struct TestConfig {
    std::string model_path;
    std::string prompt;
    int max_tokens = 5;
    bool verbose = true;
    bool require_telemetry = true;
};

// ============================================================================
// Test Results
// ============================================================================
struct TestResults {
    bool passed = false;
    std::string error_message;
    
    // Pipeline stages
    bool tokenizer_loaded = false;
    bool model_loaded = false;
    bool seg_initialized = false;
    bool inference_executed = false;
    
    // Metrics
    size_t input_tokens = 0;
    size_t output_tokens = 0;
    double tokens_per_second = 0.0;
    double total_time_ms = 0.0;
    
    // Telemetry
    uint64_t telemetry_events = 0;
    uint64_t telemetry_dropped = 0;
    bool telemetry_valid = false;
    
    std::string generated_text;
};

// ============================================================================
// Test: End-to-End Hello World
// ============================================================================
TestResults RunEndToEndTest(const TestConfig& config) {
    TestResults results;
    auto test_start = std::chrono::high_resolution_clock::now();
    
    try {
        // =====================================================================
        // Stage 1: Load Model (C1 - GGUF Ingestion)
        // =====================================================================
        if (config.verbose) {
            std::cout << "[TEST] Stage 1: Loading model from " << config.model_path << "\n";
        }
        
        auto model_ctx = ModelContextFactory::FromGGUF(config.model_path);
        if (!model_ctx) {
            results.error_message = "Failed to load model: " + config.model_path;
            return results;
        }
        results.model_loaded = true;
        
        if (config.verbose) {
            std::cout << "       ✓ Model loaded\n";
            std::cout << "         Tensors: " << model_ctx->GetTensorCount() << "\n";
            std::cout << "         Metadata: " << model_ctx->GetMetadataCount() << "\n";
        }
        
        // =====================================================================
        // Stage 2: Initialize Tokenizer (C2 - Tokenizer Bridge)
        // =====================================================================
        if (config.verbose) {
            std::cout << "[TEST] Stage 2: Initializing tokenizer\n";
        }
        
        auto tokenizer = TokenizerFactory::FromModel(*model_ctx);
        if (!tokenizer) {
            results.error_message = "Failed to initialize tokenizer";
            return results;
        }
        results.tokenizer_loaded = true;
        
        // Encode prompt
        auto tokens = tokenizer->Encode(config.prompt);
        results.input_tokens = tokens.size();
        
        if (config.verbose) {
            std::cout << "       ✓ Tokenizer ready\n";
            std::cout << "         Input: \"" << config.prompt << "\"\n";
            std::cout << "         Tokens: " << tokens.size() << " [";
            for (size_t i = 0; i < std::min(tokens.size(), size_t(5)); ++i) {
                if (i > 0) std::cout << ", ";
                std::cout << tokens[i];
            }
            if (tokens.size() > 5) std::cout << "...";
            std::cout << "]\n";
        }
        
        // =====================================================================
        // Stage 3: Initialize SEG Gateway
        // =====================================================================
        if (config.verbose) {
            std::cout << "[TEST] Stage 3: Initializing SEG gateway\n";
        }
        
        SegGateway seg_gateway;
        if (!seg_gateway.Initialize(config.model_path)) {
            results.error_message = "Failed to initialize SEG gateway";
            return results;
        }
        results.seg_initialized = true;
        
        if (config.verbose) {
            std::cout << "       ✓ SEG gateway initialized\n";
            std::cout << "         " << seg_gateway.GetModelInfo() << "\n";
        }
        
        // =====================================================================
        // Stage 4: Execute Inference Through SEG
        // =====================================================================
        if (config.verbose) {
            std::cout << "[TEST] Stage 4: Executing inference\n";
        }
        
        execution::ExecutionRequest req;
        req.model_path = config.model_path;
        req.prompt = config.prompt;
        req.max_tokens = config.max_tokens;
        req.dump_telemetry = true;
        req.verbose = config.verbose;
        
        auto inference_start = std::chrono::high_resolution_clock::now();
        auto seg_result = seg_gateway.Run(req);
        auto inference_end = std::chrono::high_resolution_clock::now();
        
        results.inference_executed = true;
        results.total_time_ms = std::chrono::duration<double, std::milli>(
            inference_end - inference_start).count();
        
        // =====================================================================
        // Stage 5: Validate Results
        // =====================================================================
        if (config.verbose) {
            std::cout << "[TEST] Stage 5: Validating results\n";
        }
        
        // Check execution succeeded
        if (seg_result.status != execution::Status::SUCCESS) {
            results.error_message = "Inference failed: " + seg_result.status_message;
            return results;
        }
        
        // Extract metrics
        results.output_tokens = seg_result.tokens_generated.size();
        results.tokens_per_second = seg_result.telemetry.tokens_per_second;
        results.telemetry_events = seg_result.telemetry.events_logged;
        results.telemetry_dropped = seg_result.telemetry.events_dropped;
        results.generated_text = seg_result.text_output;
        
        // Validate telemetry
        results.telemetry_valid = (results.telemetry_events > 0) && 
                                   (results.telemetry_dropped == 0);
        
        if (config.require_telemetry && !results.telemetry_valid) {
            results.error_message = "Telemetry validation failed";
            return results;
        }
        
        // Validate output
        if (results.output_tokens == 0) {
            results.error_message = "No tokens generated";
            return results;
        }
        
        if (config.verbose) {
            std::cout << "       ✓ Results valid\n";
            std::cout << "         Output tokens: " << results.output_tokens << "\n";
            std::cout << "         Tokens/sec: " << results.tokens_per_second << "\n";
            std::cout << "         Telemetry events: " << results.telemetry_events << "\n";
            std::cout << "         Generated: \"" << results.generated_text.substr(0, 50) << "\"\n";
        }
        
        // =====================================================================
        // Stage 6: Cleanup
        // =====================================================================
        seg_gateway.Shutdown();
        
        // All stages passed
        results.passed = true;
        
    } catch (const std::exception& e) {
        results.error_message = std::string("Exception: ") + e.what();
    }
    
    auto test_end = std::chrono::high_resolution_clock::now();
    results.total_time_ms = std::chrono::duration<double, std::milli>(
        test_end - test_start).count();
    
    return results;
}

// ============================================================================
// Print Test Summary
// ============================================================================
void PrintTestSummary(const TestResults& results) {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "SEG Integration Test Results\n";
    std::cout << std::string(60, '=') << "\n\n";
    
    std::cout << "Status: " << (results.passed ? "✓ PASSED" : "✗ FAILED") << "\n";
    
    if (!results.passed && !results.error_message.empty()) {
        std::cout << "Error: " << results.error_message << "\n\n";
    }
    
    std::cout << "Pipeline Stages:\n";
    std::cout << "  [" << (results.model_loaded ? "✓" : " ") << "] Model Load (C1)\n";
    std::cout << "  [" << (results.tokenizer_loaded ? "✓" : " ") << "] Tokenizer (C2)\n";
    std::cout << "  [" << (results.seg_initialized ? "✓" : " ") << "] SEG Gateway\n";
    std::cout << "  [" << (results.inference_executed ? "✓" : " ") << "] Inference\n";
    std::cout << "  [" << (results.telemetry_valid ? "✓" : " ") << "] Telemetry\n";
    
    std::cout << "\nMetrics:\n";
    std::cout << "  Input tokens:  " << results.input_tokens << "\n";
    std::cout << "  Output tokens: " << results.output_tokens << "\n";
    std::cout << "  Total time:    " << results.total_time_ms << " ms\n";
    std::cout << "  Tokens/sec:    " << results.tokens_per_second << "\n";
    
    std::cout << "\nTelemetry:\n";
    std::cout << "  Events logged:  " << results.telemetry_events << "\n";
    std::cout << "  Events dropped: " << results.telemetry_dropped << "\n";
    std::cout << "  Valid:          " << (results.telemetry_valid ? "Yes" : "No") << "\n";
    
    if (!results.generated_text.empty()) {
        std::cout << "\nGenerated Text:\n";
        std::cout << "  \"" << results.generated_text << "\"\n";
    }
    
    std::cout << "\n" << std::string(60, '=') << "\n";
}

// ============================================================================
// Main Entry Point
// ============================================================================
int main(int argc, char* argv[]) {
    std::cout << "\n";
    std::cout << "╔════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     RawrXD SEG Integration Test - Sovereign Pipeline       ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
    
    // Parse arguments
    TestConfig config;
    config.model_path = (argc > 1) ? argv[1] : "test_model.gguf";
    config.prompt = (argc > 2) ? argv[2] : "Hello world";
    config.max_tokens = (argc > 3) ? std::atoi(argv[3]) : 5;
    
    std::cout << "Configuration:\n";
    std::cout << "  Model: " << config.model_path << "\n";
    std::cout << "  Prompt: \"" << config.prompt << "\"\n";
    std::cout << "  Max tokens: " << config.max_tokens << "\n\n";
    
    // Run test
    auto results = RunEndToEndTest(config);
    
    // Print summary
    PrintTestSummary(results);
    
    // Return exit code
    return results.passed ? 0 : 1;
}
