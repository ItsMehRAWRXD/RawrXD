// VAL-063: Inference Gateway
// Entry point for certified inference execution

#pragma once

#include "inference_attestor.hpp"
#include <functional>
#include <future>

namespace RawrXD {
namespace Gateway {

// Forward declaration
class CertifiedInferenceEngine;

// ============================================================================
// Inference Request
// ============================================================================

struct InferenceRequest {
    std::string prompt;
    std::string model_path;
    SamplingConfig sampling;
    uint64_t seed = 42;
    
    // Optional context for multi-turn
    std::vector<int32_t> context_tokens;
    
    bool Validate() const;
    std::string ComputeHash() const;
};

// ============================================================================
// Inference Response
// ============================================================================

struct InferenceResponse {
    std::string generated_text;
    std::vector<int32_t> token_ids;
    
    // Performance metrics
    uint64_t latency_ms_total = 0;
    uint64_t latency_ms_prompt = 0;
    uint64_t latency_ms_decode = 0;
    
    // Token counts
    size_t prompt_token_count = 0;
    size_t generated_token_count = 0;
    
    // Attestation
    std::string request_id;
    std::string evidence_path;
    
    // Status
    bool success = false;
    std::string error_message;
};

// ============================================================================
// Gateway Configuration
// ============================================================================

struct GatewayConfig {
    // Paths
    std::string evidence_directory = "./evidence";
    std::string model_directory = "./models";
    std::string certification_evidence_path = "./evidence/VAL-060_Release_Freeze.json";
    
    // Runtime settings
    bool require_certified_runtime = true;
    bool verify_model_integrity = true;
    bool enable_bypass_detection = true;
    bool enable_replay_verification = true;
    bool lock_artifact_identity = true;
    
    // Performance
    uint32_t max_concurrent_requests = 4;
    uint64_t request_timeout_ms = 300000; // 5 minutes
    
    // Logging
    bool verbose_logging = false;
    std::string log_path = "./gateway.log";
};

// ============================================================================
// Inference Gateway
// ============================================================================

class InferenceGateway {
public:
    InferenceGateway();
    ~InferenceGateway();
    
    // Non-copyable
    InferenceGateway(const InferenceGateway&) = delete;
    InferenceGateway& operator=(const InferenceGateway&) = delete;
    
    // ------------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------------
    
    // Initialize the gateway with configuration
    // Returns false if certification verification fails
    bool Initialize(const GatewayConfig& config);
    
    // Shutdown and cleanup
    void Shutdown();
    
    // Check if gateway is ready for inference
    bool IsReady() const;
    
    // ------------------------------------------------------------------------
    // Synchronous Execution
    // ------------------------------------------------------------------------
    
    // Execute inference with full attestation
    // This is the primary entry point for certified inference
    InferenceResponse Execute(const InferenceRequest& request);
    
    // ------------------------------------------------------------------------
    // Asynchronous Execution
    // ------------------------------------------------------------------------
    
    // Submit async inference request
    std::future<InferenceResponse> ExecuteAsync(const InferenceRequest& request);
    
    // ------------------------------------------------------------------------
    // Batch Execution
    // ------------------------------------------------------------------------
    
    // Execute batch of requests with shared attestation
    std::vector<InferenceResponse> ExecuteBatch(
        const std::vector<InferenceRequest>& requests
    );
    
    // ------------------------------------------------------------------------
    // Attestation Queries
    // ------------------------------------------------------------------------
    
    // Get current runtime certification state
    RuntimeCertificationState GetRuntimeCertification() const;
    
    // Get gateway statistics
    struct Statistics {
        uint64_t total_requests = 0;
        uint64_t successful_requests = 0;
        uint64_t failed_requests = 0;
        uint64_t rejected_requests = 0;
        uint64_t total_tokens_generated = 0;
        uint64_t total_latency_ms = 0;
        
        double average_latency_ms() const {
            return total_requests > 0 ? 
                (double)total_latency_ms / total_requests : 0.0;
        }
        
        double success_rate() const {
            return total_requests > 0 ? 
                (double)successful_requests / total_requests : 0.0;
        }
    };
    Statistics GetStatistics() const;
    
    // Get latest attestation evidence
    std::string GetLatestEvidence() const;
    
    // ------------------------------------------------------------------------
    // VAL-063A: Bypass Detection
    // ------------------------------------------------------------------------
    
    // Get bypass detection metrics
    BypassDetectionMetrics GetBypassMetrics() const;
    
    // Verify no bypass has occurred
    bool VerifyNoBypass() const;
    
    // ------------------------------------------------------------------------
    // VAL-063B: Artifact Identity
    // ------------------------------------------------------------------------
    
    // Lock a model path to specific identity
    bool LockModelIdentity(
        const std::string& path, 
        const std::string& manifest_hash
    );
    
    // ------------------------------------------------------------------------
    // VAL-063C: Replay Verification
    // ------------------------------------------------------------------------
    
    // Record a run for replay verification
    void RecordForReplay(
        const InferenceRequest& request,
        const InferenceResponse& response
    );
    
    // Verify replay produces identical output
    bool VerifyReplay(
        const InferenceRequest& request,
        const InferenceResponse& response
    ) const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Certified Inference Engine Interface
// ============================================================================

class CertifiedInferenceEngine {
public:
    virtual ~CertifiedInferenceEngine() = default;
    
    // Generate tokens from request
    virtual InferenceResponse Generate(const InferenceRequest& request) = 0;
    
    // Check if engine is ready
    virtual bool IsReady() const = 0;
    
    // Get engine capabilities
    virtual std::vector<std::string> GetSupportedModels() const = 0;
};

// ============================================================================
// Factory Functions
// ============================================================================

// Create a gateway with default configuration
std::unique_ptr<InferenceGateway> CreateGateway();

// Create a gateway with custom configuration
std::unique_ptr<InferenceGateway> CreateGateway(const GatewayConfig& config);

// ============================================================================
// C API
// ============================================================================

extern "C" {

// Gateway handle
typedef struct Val063Gateway* Val063GatewayHandle;

// Create/destroy
typedef struct {
    const char* evidence_directory;
    const char* model_directory;
    int require_certified_runtime;
    int verbose_logging;
} Val063GatewayConfig;

Val063GatewayHandle val063_gateway_create(const Val063GatewayConfig* config);
void val063_gateway_destroy(Val063GatewayHandle handle);

// Execute
typedef struct {
    const char* prompt;
    const char* model_path;
    float temperature;
    float top_p;
    int32_t top_k;
    uint64_t seed;
} Val063InferenceRequest;

typedef struct {
    const char* generated_text;
    int32_t success;
    uint64_t latency_ms;
    const char* request_id;
    const char* error_message;
} Val063InferenceResponse;

Val063InferenceResponse* val063_gateway_execute(
    Val063GatewayHandle handle,
    const Val063InferenceRequest* request
);

void val063_free_response(Val063InferenceResponse* response);

// Evidence
const char* val063_gateway_get_latest_evidence(Val063GatewayHandle handle);

// Statistics
typedef struct {
    uint64_t total_requests;
    uint64_t successful_requests;
    uint64_t failed_requests;
    double success_rate;
    double average_latency_ms;
} Val063GatewayStats;

Val063GatewayStats val063_gateway_get_stats(Val063GatewayHandle handle);

} // extern "C"

} // namespace Gateway
} // namespace RawrXD
