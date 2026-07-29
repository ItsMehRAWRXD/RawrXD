// VAL-063: CLI Gateway Binding
// Enforces rawrxd.exe → Gateway → Certified Runtime as only path

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <optional>

namespace RawrXD {
namespace Gateway {

// Forward declarations
class InferenceGateway;
struct InferenceRequest;
struct InferenceResponse;

// ============================================================================
// Execution Context
// ============================================================================

struct ExecutionContext {
    std::string execution_id;
    std::string gateway_signature;
    uint64_t timestamp_issued;
    uint64_t expires_at;
    
    // Attestation chain
    std::string request_hash;
    std::string runtime_hash;
    std::string model_hash;
    
    bool IsValid() const;
    bool IsExpired() const;
    std::string Serialize() const;
    static std::optional<ExecutionContext> Deserialize(const std::string& data);
};

// ============================================================================
// Gateway Entry Point
// ============================================================================

class GatewayEntryPoint {
public:
    GatewayEntryPoint();
    ~GatewayEntryPoint();
    
    // Non-copyable
    GatewayEntryPoint(const GatewayEntryPoint&) = delete;
    GatewayEntryPoint& operator=(const GatewayEntryPoint&) = delete;
    
    // Initialize with configuration
    bool Initialize(const std::string& config_path);
    
    // Main entry point for CLI
    // This is the ONLY supported entry point for inference
    int Run(int argc, char* argv[]);
    
    // Execute inference request (internal use)
    InferenceResponse Execute(const InferenceRequest& request);
    
    // Get execution context for attestation
    ExecutionContext GetExecutionContext() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Direct Runtime Access Prevention
// ============================================================================

namespace Internal {
    // These functions are marked as internal and should not be called directly
    // They will reject execution without a valid gateway context
    
    class CertifiedRuntimeInternal {
    public:
        // Requires valid execution context from gateway
        static bool ExecuteWithContext(
            const ExecutionContext& context,
            const InferenceRequest& request,
            InferenceResponse& response
        );
        
        // Rejects un-attested execution
        static bool RejectUnattestedExecution();
    };
}

// ============================================================================
// CLI Argument Parser
// ============================================================================

struct CLIArguments {
    std::string model_path;
    std::string prompt;
    std::string prompt_file;
    
    // Sampling parameters
    float temperature = 0.8f;
    float top_p = 0.95f;
    int32_t top_k = 40;
    uint64_t seed = 42;
    int32_t max_tokens = 512;
    
    // Output options
    std::string output_file;
    bool streaming = false;
    bool verbose = false;
    
    // Evidence options
    std::string evidence_dir = "./evidence";
    bool save_evidence = true;
    
    // Validation
    bool Validate() const;
    InferenceRequest ToInferenceRequest() const;
};

class CLIArgumentParser {
public:
    static CLIArguments Parse(int argc, char* argv[]);
    static void PrintUsage();
    static void PrintVersion();
};

// ============================================================================
// Evidence Output Handler
// ============================================================================

class EvidenceOutputHandler {
public:
    EvidenceOutputHandler(const std::string& evidence_dir);
    ~EvidenceOutputHandler();
    
    // Save complete evidence package
    bool SaveEvidencePackage(
        const ExecutionContext& context,
        const InferenceRequest& request,
        const InferenceResponse& response
    );
    
    // Print evidence summary to console
    void PrintEvidenceSummary(const InferenceResponse& response) const;

private:
    std::string evidence_dir_;
};

// ============================================================================
// Main Entry Point
// ============================================================================

// This is the actual main() implementation
// It enforces the gateway path and rejects direct runtime access
int RawrXDMain(int argc, char* argv[]);

// ============================================================================
// C API for ABI Stability
// ============================================================================

extern "C" {

// Gateway entry
typedef struct Val063GatewayEntry* Val063EntryHandle;

Val063EntryHandle val063_gateway_entry_create();
int val063_gateway_entry_run(Val063EntryHandle handle, int argc, char* argv[]);
void val063_gateway_entry_destroy(Val063EntryHandle handle);

// Execution context
const char* val063_get_execution_context(const char* execution_id);
int val063_verify_execution_context(const char* context_json);

// Direct runtime access (returns error - must use gateway)
int val063_direct_runtime_execute(
    const char* model_path,
    const char* prompt,
    char* output_buffer,
    size_t output_buffer_size
);

} // extern "C"

} // namespace Gateway
} // namespace RawrXD
