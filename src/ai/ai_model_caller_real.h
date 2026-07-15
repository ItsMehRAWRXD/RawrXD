// ============================================================================
// RawrXD AI Model Caller - Real Inference with Tokenizer Integration
// ============================================================================
// Header for production inference with end-to-end text generation
// Includes tokenizer integration for text -> tokens -> text pipeline
// ============================================================================

#pragma once

#include <vector>
#include <string>

// ============================================================================
// Inference Result Structure
// ============================================================================

struct InferenceResult {
    std::vector<int> tokens;
    float* logits;
    float confidence;
    float perplexity;
    unsigned long timestamp;
    int error_code;
    std::string error_message;
    std::string text;
    int n_vocab;
};

// ============================================================================
// Initialization
// ============================================================================

// Initialize inference engine with model and tokenizer
// Returns true on success, false on failure
bool InitInference(const char* model_path);

// Initialize tokenizer from GGUF model
bool InitTokenizer(const char* model_path);

// Check if inference is ready
bool IsInferenceReady();

// ============================================================================
// Inference API
// ============================================================================

// Run inference with token IDs (low-level API)
InferenceResult RunRealInference(const std::vector<int>& input_tokens, 
                                  int max_new_tokens = 1);

// Run inference with text input (high-level API with tokenizer)
// Automatically tokenizes input and decodes output
InferenceResult RunInferenceWithText(const char* prompt_text, 
                                      int max_new_tokens = 10);

// Generate text from prompt (convenience wrapper)
// Returns generated text string (empty on error)
std::string GenerateText(const char* prompt, int max_tokens = 100);

// ============================================================================
// Cleanup
// ============================================================================

// Cleanup inference resources
void CleanupInference();

// Cleanup tokenizer resources
void CleanupTokenizer();

// Full cleanup (inference + tokenizer)
void CleanupAll();

// ============================================================================
// Configuration
// ============================================================================

struct InferenceConfig {
    float temperature = 0.8f;
    float top_p = 0.9f;
    int top_k = 40;
    int max_tokens = 256;
    unsigned int seed = 42;
};

// Set inference configuration
void SetInferenceConfig(const InferenceConfig& config);

// Get current configuration
InferenceConfig GetInferenceConfig();

// ============================================================================
// Status and Errors
// ============================================================================

// Get last error message
const char* GetLastErrorMessage();

// Get inference statistics
struct InferenceStats {
    int tokens_generated;
    float tokens_per_second;
    float avg_latency_ms;
    unsigned long total_time_ms;
};

InferenceStats GetInferenceStats();

// ============================================================================
// Checkpoint Integration
// ============================================================================

// Enable/disable checkpoint recording
void EnableCheckpoints(bool enable);

// Export proof to file
bool ExportProof(const char* output_path);

// Get vocab hash for proof metadata
unsigned long long GetVocabHash();
