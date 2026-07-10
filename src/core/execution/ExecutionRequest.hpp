// ============================================================================
// Execution Request
// ============================================================================
// Input contract for RawrXD inference execution
// ============================================================================

#pragma once

#include <string>
#include <cstdint>

namespace RawrXD {
namespace Execution {

// ============================================================================
// Execution Request Structure
// ============================================================================
// Single invocation parameters for the execution backend
// ============================================================================

struct ExecutionRequest {
    // Command identifier (e.g., "run", "think", "complete")
    std::string command;
    
    // Model identifier (e.g., "phi3.gguf", "local::qwen32b")
    std::string model;
    
    // Input prompt/text
    std::string prompt;
    
    // Generation parameters
    uint32_t max_tokens = 128;
    float temperature = 0.7f;
    float top_p = 0.9f;
    uint32_t top_k = 40;
    
    // Output format flags
    bool stream = false;      // Stream tokens as generated
    bool json = false;        // Output JSON format
    bool verbose = false;     // Include diagnostics
    
    // Backend selection
    std::string backend_preference;  // "auto", "vulkan", "cpu", "simulator"
    
    // Context management
    uint32_t context_length = 4096;
    bool use_cache = true;
};

} // namespace Execution
} // namespace RawrXD
