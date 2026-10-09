#pragma once
// ============================================================================
// ValidationPipeline — Orchestrates multi-token parity validation
// ============================================================================
// Purpose: Coordinate native IR execution, llama.cpp reference, and comparison
// Produces: RAWRXD_MODELGENIE_MULTITOKEN_DECODE_001 certificate
// ============================================================================

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <functional>
#include <chrono>
#include <fstream>

#include "reference_runner.hpp"
#include "activation_comparator.hpp"
#include "multitoken_decode_session.hpp"
#include "model_context.hpp"

namespace RawrXD {
namespace CLI {

// Validation configuration
struct ValidationConfig {
    std::string model_path;
    std::string evidence_dir;
    std::string llama_cpp_path;
    std::string output_dir;              // For certificates and logs
    
    // Test parameters
    std::vector<uint32_t> prompt_tokens; // Input prompt
    uint32_t max_tokens = 64;            // Tokens to generate
    uint32_t max_seq_len = 1024;         // KV cache size
    
    // Sampling
    float temperature = 1.0f;
    int top_k = 40;
    float top_p = 0.9f;
    uint32_t seed = 42;
    
    // Comparison
    float atol = 1e-5f;
    float rtol = 1e-4f;
    float min_cosine = 0.999f;
    
    // Output
    bool verbose = true;
    bool save_activations = false;
    bool save_certificate = true;
    std::string certificate_name = "RAWRXD_MODELGENIE_MULTITOKEN_DECODE_001";
    
    // Gates
    bool require_token_parity = true;
    bool require_activation_parity = false;  // For Phase 2
    uint32_t min_matching_tokens = 16;       // Gate P2-P15
    uint32_t target_matching_tokens = 64;    // Gate P16-P63
};

// Validation result certificate
struct ValidationCertificate {
    std::string certificate_id;
    std::string timestamp;
    std::string baseline_commit;
    std::string model_path;
    std::string model_hash;
    
    // Configuration
    ValidationConfig config;
    
    // Results
    struct TokenResult {
        uint32_t position = 0;
        uint32_t native_token = 0;
        uint32_t reference_token = 0;
        bool parity = false;
        double native_time_ms = 0.0;
        double reference_time_ms = 0.0;
        float logit_max_diff = 0.0f;
        float logit_rmse = 0.0f;
        float logit_cosine = 0.0f;
    };
    std::vector<TokenResult> token_results;
    
    // Aggregate metrics
    uint32_t tokens_tested = 0;
    uint32_t tokens_matched = 0;
    uint32_t first_mismatch_position = UINT32_MAX;
    double total_native_time_ms = 0.0;
    double total_reference_time_ms = 0.0;
    float native_tps = 0.0f;
    float reference_tps = 0.0f;
    
    // Activation parity (Phase 2)
    struct ActivationParity {
        uint32_t ops_compared = 0;
        uint32_t ops_passed = 0;
        uint32_t ops_failed = 0;
        float global_max_abs_diff = 0.0f;
        float global_rmse = 0.0f;
        float global_cosine = 0.0f;
        uint32_t first_divergent_op = UINT32_MAX;
    };
    std::vector<ActivationParity> activation_parity_per_token;
    
    // Gates
    bool gate_p0_token0 = false;       // Position 0 reproduces token 185
    bool gate_p1_position1 = false;    // Position 1 matches reference
    bool gate_p2_p15_16tokens = false; // 16 sequential matches
    bool gate_p16_p63_64tokens = false; // 64 sequential matches
    bool gate_kv_reuse = false;        // KV cache persistence
    bool gate_ir_authority = false;    // 300/300 ops each step
    bool gate_finite_logits = false;   // All finite
    
    // Overall verdict
    std::string verdict = "PENDING";
    
    // Save to file
    bool Save(const std::string& path) const;
    
    // Load from file
    static ValidationCertificate Load(const std::string& path);
    
    // Print summary
    void PrintSummary() const;
};

// Validation pipeline orchestrator
class ValidationPipeline {
public:
    explicit ValidationPipeline(const ValidationConfig& config);
    ~ValidationPipeline() = default;
    
    // Run full validation
    ValidationCertificate Run();
    
    // Run specific phase
    ValidationCertificate RunPhase1_TokenParity();      // Position 0
    ValidationCertificate RunPhase2_ActivationParity(); // Full logit comparison
    ValidationCertificate RunPhase3_MultiToken();       // 64 tokens
    
    // Progress callback
    using ProgressCallback = std::function<void(const std::string&, float)>;
    void SetProgressCallback(ProgressCallback cb) { m_progress_callback = cb; }
    
private:
    ValidationConfig m_config;
    ValidationCertificate m_certificate;
    ProgressCallback m_progress_callback;
    
    // Components
    std::unique_ptr<MultiTokenDecodeSession> m_native_session;
    std::unique_ptr<ReferenceRunner> m_reference_runner;
    std::unique_ptr<ActivationComparator> m_comparator;
    
    // Helpers
    bool InitializeComponents();
    void ReportProgress(const std::string& phase, float progress);
    void UpdateCertificate(const MultiTokenDecodeSession::DecodeStepResult& native_step,
                          const ReferenceResult& reference_result,
                          uint32_t position);
    bool CheckGates();
    void FinalizeCertificate();
    
    // Model hash computation
    std::string ComputeModelHash() const;
    
    // Certificate helpers
    void WriteCertificateHeader(std::ofstream& out) const;
    void WriteTokenResults(std::ofstream& out) const;
    void WriteActivationParity(std::ofstream& out) const;
    void WriteGates(std::ofstream& out) const;
    void WriteVerdict(std::ofstream& out) const;
};

// Binary certificate format for compact storage
struct BinaryCertificate {
    static bool Write(const ValidationCertificate& cert, const std::string& path);
    static bool Read(ValidationCertificate& cert, const std::string& path);
};

// Certificate schema version
constexpr uint32_t CERTIFICATE_SCHEMA_VERSION = 1;

} // namespace CLI
} // namespace RawrXD