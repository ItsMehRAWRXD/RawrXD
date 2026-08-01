// execution_contract.h
// RawrXD Sovereign Runtime v1.0-ALPHA
// Single execution contract — all subsystems communicate through this

#ifndef EXECUTION_CONTRACT_H
#define EXECUTION_CONTRACT_H

#include <string>
#include <vector>
#include <map>
#include <cstdint>

namespace sovereign {

// ============================================================
// STAGE 1 — Execution Request (Single Entry Point)
// ============================================================

struct ExecutionRequest {
    // Model configuration
    std::string model_path;
    std::string model_format;  // "gguf", "onnx", etc.
    
    // Input configuration
    std::string prompt;
    std::vector<uint32_t> tokenized_prompt;  // Optional pre-tokenized
    
    // Generation configuration
    size_t max_tokens = 256;
    float temperature = 0.8f;
    float top_p = 0.9f;
    size_t top_k = 40;
    std::string stop_sequences;
    
    // Backend configuration
    std::string backend = "auto";  // "auto", "cpu", "vulkan", "rocm"
    int32_t gpu_layer_count = -1;   // -1 = auto
    
    // Validation mode
    bool validation_mode = true;    // Emit evidence bundle
    bool deterministic = true;        // Fixed seed for reproducibility
    uint32_t seed = 42;
    
    // Agentic mode
    bool autonomous = false;        // Enable agent loop
    size_t max_iterations = 10;
    
    // Recovery configuration
    bool recovery_enabled = true;
    size_t max_retries = 3;
    
    std::string to_json() const;
    static ExecutionRequest from_json(const std::string& json);
    static ExecutionRequest from_cli(int argc, char** argv);
};

// ============================================================
// STAGE 1 — Execution Result (Single Exit Point)
// ============================================================

struct ExecutionResult {
    // Generation output
    std::string generated_text;
    std::vector<uint32_t> generated_tokens;
    size_t tokens_generated = 0;
    
    // Status
    enum class Status {
        SUCCESS,
        PARTIAL_SUCCESS,
        FAILURE,
        RECOVERY_SUCCESS,
        RECOVERY_FAILURE
    };
    Status status = Status::FAILURE;
    std::string status_message;
    int32_t exit_code = 1;
    
    // Telemetry
    struct Telemetry {
        double total_time_ms = 0.0;
        double load_time_ms = 0.0;
        double inference_time_ms = 0.0;
        double tokens_per_second = 0.0;
        size_t peak_memory_mb = 0;
        size_t kv_cache_size = 0;
        
        // Per-kernel timing (if validation_mode)
        std::map<std::string, double> kernel_timings;
    };
    Telemetry telemetry;
    
    // Cryptographic hashes (if validation_mode)
    struct EvidenceHashes {
        std::string model_hash;      // GGUF SHA256
        std::string input_hash;      // Prompt SHA256
        std::string output_hash;     // Generated tokens SHA256
        std::string execution_hash;  // Full execution trace SHA256
    };
    EvidenceHashes hashes;
    
    // Recovery log (if recovery_enabled)
    struct RecoveryLog {
        size_t attempts = 0;
        std::vector<std::string> faults_encountered;
        std::vector<std::string> recovery_actions;
        bool final_success = false;
    };
    RecoveryLog recovery;
    
    // Certification (if validation_mode)
    struct Certificate {
        std::string certificate_id;
        std::string timestamp;
        bool all_gates_passed = false;
        std::vector<std::string> gate_results;
    };
    Certificate certificate;
    
    // Serialization
    std::string to_json() const;
    void save_evidence_bundle(const std::string& run_id) const;
};

// ============================================================
// STAGE 1 — Execution Spine (No subsystem talks directly to another)
// ============================================================

class SovereignExecutionSpine {
public:
    // Single entry point
    ExecutionResult execute(const ExecutionRequest& request);
    
    // Subsystem accessors (spine mediates all communication)
    struct Subsystems {
        class GGUFLoader* loader = nullptr;
        class Tokenizer* tokenizer = nullptr;
        class TensorRuntime* tensor_runtime = nullptr;
        class KernelRegistry* kernel_registry = nullptr;
        class TransformerEngine* transformer = nullptr;
        class KVCacheManager* kv_cache = nullptr;
        class Sampler* sampler = nullptr;
        class AgenticController* agent = nullptr;
        class RecoverySystem* recovery = nullptr;
        class CertificationEngine* certifier = nullptr;
    };
    
    void register_subsystems(const Subsystems& subsystems);
    
private:
    Subsystems subsystems_;
    
    // Internal pipeline stages
    ExecutionResult stage_load_model(const ExecutionRequest& req);
    ExecutionResult stage_tokenize(const ExecutionRequest& req);
    ExecutionResult stage_allocate_tensors(const ExecutionRequest& req);
    ExecutionResult stage_execute_transformer(const ExecutionRequest& req);
    ExecutionResult stage_sample_tokens(const ExecutionRequest& req);
    ExecutionResult stage_agent_loop(const ExecutionRequest& req);
    ExecutionResult stage_certify(const ExecutionRequest& req, ExecutionResult& result);
};

} // namespace sovereign

#endif // EXECUTION_CONTRACT_H
