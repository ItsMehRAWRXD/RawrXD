// ============================================================================
// SEG Gateway - Thin wrapper for RawrXD Execution Gateway
// ============================================================================
// Bridges the Execution Gateway to the SEG (Streaming Execution Graph) engine
// with full MASM telemetry integration.
// ============================================================================

#pragma once

#include "../execution/execution_gateway_impl.h"
#include <memory>
#include <string>
#include <vector>

// Forward declarations for SEG
namespace seg {
    class Runtime;
    class Graph;
    struct LlamaGraphConfig;
}

namespace rawrxd {
namespace gateway {

// ============================================================================
// SegExecutionResult
// ============================================================================
// Extended result with SEG-specific telemetry
struct SegExecutionResult {
    // Standard ExecutionResult fields
    execution::Status status = execution::Status::SUCCESS;
    std::string text_output;
    std::string status_message;
    std::string error_details;
    
    // SEG-specific telemetry
    struct SegTelemetry {
        uint64_t events_logged = 0;
        uint64_t events_dropped = 0;
        uint64_t tokens_logged = 0;        // Total tokens processed (prompt + generated)
        double tokens_per_second = 0.0;
        double time_to_first_token_ms = 0.0;
        double total_time_ms = 0.0;
        uint64_t peak_memory_bytes = 0;
        
        // Per-layer breakdown (if available)
        std::vector<std::pair<std::string, double>> layer_timings;
        
        std::string ToJson() const;
        std::string Summary() const;
    } telemetry;
    
    // Token data
    std::vector<uint32_t> tokens_generated;
    std::vector<float> logits_first_token;
    
    // Factory methods
    static SegExecutionResult Success(const std::string& text);
    static SegExecutionResult Error(const std::string& message);
    static SegExecutionResult FromExecutionResult(const execution::ExecutionResult& base);
};

// ============================================================================
// SegGateway
// ============================================================================
// Main entry point for SEG-based inference from the Execution Gateway
class SegGateway {
public:
    SegGateway();
    ~SegGateway();
    
    // Initialize with model path
    bool Initialize(const std::string& model_path);
    
    // Shutdown and cleanup
    void Shutdown();
    
    // Run inference
    SegExecutionResult Run(const execution::ExecutionRequest& req);
    
    // Check if initialized
    bool IsInitialized() const { return initialized_; }
    
    // Get model info
    std::string GetModelInfo() const;
    
private:
    std::unique_ptr<seg::Runtime> runtime_;
    std::string model_path_;
    bool initialized_ = false;
    
    // Internal helpers
    bool BuildGraph();
    std::vector<uint32_t> GenerateTokens(const std::string& prompt, int max_tokens);
    std::string DecodeTokens(const std::vector<uint32_t>& tokens);
    SegExecutionResult::SegTelemetry CollectTelemetry();
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Run SEG inference from ExecutionRequest
SegExecutionResult RunSegInference(const execution::ExecutionRequest& req);

// Check if SEG is available (MASM telemetry compiled)
bool IsSegAvailable();

// Get SEG version info
std::string GetSegVersion();

} // namespace gateway
} // namespace rawrxd
