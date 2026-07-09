/**
 * @file execution_contracts.h
 * @brief RawrXD Execution Contracts - Immutable System Boundary
 *
 * Every subsystem (CLI, benchmarks, tests, GUI, IDE, agents)
 * exchanges ONLY these types. Prevents API fragmentation.
 *
 * @copyright RawrXD 2026
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <optional>

namespace rawrxd {
namespace execution {

// ============================================================================
// Status Codes (Deterministic Contract)
// ============================================================================

enum class Status : uint8_t {
    SUCCESS = 0,              // Execution completed successfully
    USER_ERROR = 1,           // Invalid arguments, user mistake
    VALIDATION_FAILURE = 2, // Validation check failed
    RUNTIME_FAILURE = 3,    // Runtime/kernel execution failed
    CANCELLED = 4,          // Execution was cancelled
    TIMEOUT = 5             // Execution timed out
};

// Convert status to CLI exit code
constexpr int StatusToExitCode(Status s) {
    return static_cast<int>(s);
}

// ============================================================================
// Execution Request (Immutable Input Contract)
// ============================================================================

enum class CommandType : uint8_t {
    UNKNOWN = 0,
    RUN_INFERENCE,           // Full inference pipeline
    KERNEL_VALIDATE,         // Validate specific kernel
    KERNEL_PROFILE,          // Profile kernel performance
    KERNEL_POLICY,           // Generate compression policy
    BENCHMARK,               // Run benchmark suite
    INSPECT_MODEL,           // Inspect GGUF model
    TOKENIZER_VALIDATE,      // Step C2: Tokenizer validation
    EMBEDDING_LOOKUP,        // Step C3: Embedding lookup
    TEST_SUITE               // Run test suite
};

struct ExecutionRequest {
    // Command identification
    CommandType command = CommandType::UNKNOWN;
    std::string command_name;      // For logging/debugging
    
    // Model parameters (for inference)
    std::string model_path;
    std::string prompt;
    uint32_t max_tokens = 128;
    float temperature = 0.8f;
    uint32_t seed = 0;             // 0 = random
    
    // Kernel parameters
    std::string kernel_name;       // "gemm", "rmsnorm", "rope", "softmax"
    std::string kernel_variant;    // "reference", "avx2", "avx512"
    
    // Compression parameters
    std::string compression_codec;
    float compression_ratio_target = 4.0f;
    
    // Execution control
    uint32_t timeout_ms = 300000;  // 5 minute default
    bool dry_run = false;          // Validate without executing
    
    // Output control
    bool json_output = false;
    bool verbose = false;
    bool quiet = false;
    bool dump_telemetry = false;     // Dump SEG/MASM telemetry after execution
    
    // Step C3: Token ID for embedding lookup
    uint32_t token_id = 0;
    
    // Metadata
    std::string request_id;        // Unique identifier for tracing
    std::chrono::steady_clock::time_point created_at;
    
    ExecutionRequest() : created_at(std::chrono::steady_clock::now()) {}
};

// ============================================================================
// Execution Telemetry (Runtime Measurements)
// ============================================================================

struct ExecutionTelemetry {
    // Timing (milliseconds)
    double total_ms = 0.0;
    double kernel_ms = 0.0;
    double io_ms = 0.0;
    double overhead_ms = 0.0;
    
    // Token metrics (inference only)
    uint32_t tokens_generated = 0;
    uint32_t tokens_prompt = 0;
    double tokens_per_second = 0.0;
    double time_to_first_token_ms = 0.0;
    
    // Memory metrics
    uint64_t peak_memory_bytes = 0;
    uint64_t model_memory_bytes = 0;
    uint64_t kv_cache_bytes = 0;
    
    // Kernel metrics
    uint32_t kernel_invocations = 0;
    std::string kernel_implementation;  // "reference", "avx2", "avx512"
    
    // Validation status
    bool validation_passed = false;
    std::string validation_message;
    
    // Timestamps
    std::chrono::steady_clock::time_point started_at;
    std::chrono::steady_clock::time_point completed_at;
    
    // Serialize to JSON
    std::string ToJson() const;
    
    // Human-readable summary
    std::string Summary() const;
};

// ============================================================================
// Validation Results
// ============================================================================

struct ValidationResult {
    bool passed = false;
    std::string check_name;
    double metric_value = 0.0;
    double threshold = 0.0;
    std::string unit;
    std::string message;
    
    // For GEMM validation: cosine similarity, RMSE
    double cosine_similarity = 0.0;
    double rmse = 0.0;
    
    bool IsAcceptable() const {
        return cosine_similarity >= 0.9999 && rmse <= 0.001;
    }
};

// ============================================================================
// Execution Result (Immutable Output Contract)
// ============================================================================

struct ExecutionResult {
    // Status
    Status status = Status::SUCCESS;
    std::string status_message;
    
    // Primary output
    std::string text_output;       // Generated text (inference) or message
    std::vector<uint32_t> token_ids; // Generated token IDs
    
    // Telemetry (always populated)
    ExecutionTelemetry telemetry;
    
    // Validation (populated for kernel commands)
    std::vector<ValidationResult> validations;
    
    // Additional data (JSON-serializable)
    std::map<std::string, std::string> metadata;
    
    // Error details (if status != SUCCESS)
    std::string error_details;
    std::string stack_trace;
    
    // Factory methods for common results
    static ExecutionResult Success(const std::string& text = "");
    static ExecutionResult UserError(const std::string& message);
    static ExecutionResult RuntimeError(const std::string& message);
    static ExecutionResult ValidationFailed(const std::string& message);
    
    // Serialize to JSON
    std::string ToJson() const;
    
    // Human-readable output
    std::string ToHumanReadable() const;
    
    // Exit code for CLI
    int ExitCode() const { return StatusToExitCode(status); }
};

// ============================================================================
// Execution Gateway Interface
// ============================================================================

class ExecutionGateway {
public:
    virtual ~ExecutionGateway() = default;
    
    // Execute a request and return a result
    virtual ExecutionResult Execute(const ExecutionRequest& request) = 0;
    
    // Check if gateway is ready
    virtual bool IsReady() const = 0;
    
    // Get gateway capabilities
    virtual std::vector<std::string> GetAvailableCommands() const = 0;
    virtual std::vector<std::string> GetAvailableKernels() const = 0;
};

// ============================================================================
// Result Stream (for streaming inference)
// ============================================================================

class ExecutionResultStream {
public:
    virtual ~ExecutionResultStream() = default;
    
    // Get next token/result chunk
    virtual bool GetNext(std::string& chunk) = 0;
    virtual bool GetNext(ExecutionResult& partial) = 0;
    
    // Check if stream is complete
    virtual bool IsComplete() const = 0;
    
    // Cancel the stream
    virtual void Cancel() = 0;
};

} // namespace execution
} // namespace rawrxd
