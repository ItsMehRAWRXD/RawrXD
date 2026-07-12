//==============================================================================
// AgentSubsystem.h - Phase 13: Real Agent Integration (LLM + Sovereign Runtime)
//
// Provides LLM-powered intelligence for code generation, error fixing,
// optimization, and workflow planning. The LLM is a tool within the runtime,
// not the owner of it.
//
// Design Principles:
// - LLM advises and generates, never executes directly
// - All execution goes through Sovereign runtime (52 subsystems)
// - LLM output is validated before use
// - Offline-first: supports local models (llama.cpp, Ollama)
//==============================================================================

#ifndef AGENT_SUBSYSTEM_H
#define AGENT_SUBSYSTEM_H

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// Version & Constants
//==============================================================================

#define AGENT_VERSION "13.0.0"
#define AGENT_MAX_PROMPT 8192
#define AGENT_MAX_RESPONSE 65536
#define AGENT_MAX_CONTEXT 32768
#define AGENT_TIMEOUT_MS 120000  // 2 minutes for LLM calls

//==============================================================================
// LLM Provider Types
//==============================================================================

typedef enum {
    AGENT_PROVIDER_LOCAL = 0,      // llama.cpp, local GGUF
    AGENT_PROVIDER_OLLAMA,         // Ollama API
    AGENT_PROVIDER_OPENAI,         // OpenAI API (if online)
    AGENT_PROVIDER_CUSTOM          // Custom endpoint
} AgentProviderType;

//==============================================================================
// Agent Commands
//==============================================================================

typedef enum {
    AGENT_CMD_GENERATE_CODE = 0,   // Generate code from spec
    AGENT_CMD_FIX_CODE,            // Fix errors in code
    AGENT_CMD_OPTIMIZE_CODE,       // Optimize for performance
    AGENT_CMD_TRANSLATE_CODE,      // Translate between languages
    AGENT_CMD_PLAN_WORKFLOW,       // Generate SEG workflow
    AGENT_CMD_ANALYZE_ERROR,       // Analyze error output
    AGENT_CMD_SUGGEST_REFACTOR,    // Suggest refactoring
    AGENT_CMD_GENERATE_TESTS,      // Generate test cases
    AGENT_CMD_EXPLAIN_CODE,        // Explain code functionality
    AGENT_CMD_COMPLETE_CODE        // Code completion
} AgentCommandType;

//==============================================================================
// Agent Request
//==============================================================================

typedef struct AgentRequest {
    AgentCommandType command;
    
    // Input context
    const char* prompt;              // Primary prompt
    const char* context;             // Additional context (code, errors, etc.)
    const char* language;            // Target language (rust, python, etc.)
    
    // Constraints
    int max_tokens;                  // Max response length
    float temperature;               // Creativity (0.0 - 1.0)
    int timeout_ms;                  // Timeout override
    
    // Validation
    int validate_output;             // Require validation before return
    const char* expected_pattern;    // Regex pattern for validation
} AgentRequest;

//==============================================================================
// Agent Response
//==============================================================================

typedef struct AgentResponse {
    int success;                     // 0 = success, non-zero = error
    char content[AGENT_MAX_RESPONSE]; // Generated content
    size_t content_len;
    
    // Metadata
    int tokens_generated;
          // Tokens in response
    int tokens_prompt;               // Tokens in prompt
    uint64_t duration_ms;            // Time taken
    
    // Error info
    char error_message[256];
    int http_status;                 // HTTP status if applicable
} AgentResponse;

//==============================================================================
// Agent Configuration
//==============================================================================

typedef struct AgentConfig {
    AgentProviderType provider;
    
    // Endpoint configuration
    char endpoint[256];              // URL or path
    char model[128];               // Model name
    char api_key[256];             // API key (if required)
    
    // Default parameters
    int default_max_tokens;
    float default_temperature;
    int default_timeout_ms;
    
    // Local model settings
    char model_path[MAX_PATH];       // Path to GGUF file
    int num_gpu_layers;              // GPU offload layers
    int context_size;                // Context window size
} AgentConfig;

//==============================================================================
// Agent Context (Conversation Memory)
//==============================================================================

typedef struct AgentContext {
    char history[AGENT_MAX_CONTEXT]; // Conversation history
    size_t history_len;
    int turn_count;                  // Number of exchanges
} AgentContext;

//==============================================================================
// API Functions
//==============================================================================

// Initialize Agent subsystem
int Agent_Init(const AgentConfig* config);

// Shutdown Agent subsystem
int Agent_Shutdown(void);

// Execute agent command
int Agent_Execute(const AgentRequest* request, AgentResponse* response);

// Execute with conversation context
int Agent_ExecuteWithContext(const AgentRequest* request, 
                              AgentContext* context,
                              AgentResponse* response);

// Validate generated code (syntax check)
int Agent_ValidateCode(const char* code, const char* language);

// Clear conversation context
void Agent_ClearContext(AgentContext* context);

// Get agent status
int Agent_GetStatus(char* status, size_t status_size);

// Update configuration
int Agent_Configure(const AgentConfig* config);

// Get current configuration
int Agent_GetConfig(AgentConfig* config);

//==============================================================================
// High-Level Helper Functions
//==============================================================================

// Generate code from specification
int Agent_GenerateCode(const char* spec, const char* language,
                       char* output, size_t output_size);

// Fix code based on error output
int Agent_FixCode(const char* code, const char* error_output,
                  const char* language, char* fixed_code, size_t fixed_size);

// Optimize code for performance
int Agent_OptimizeCode(const char* code, const char* language,
                       const char* metric, char* optimized, size_t opt_size);

// Translate code between languages
int Agent_TranslateCode(const char* code, const char* source_lang,
                        const char* target_lang, char* translated, size_t trans_size);

// Generate SEG workflow from description
int Agent_PlanWorkflow(const char* description, char* workflow_json, 
                        size_t workflow_size);

// Analyze error and suggest fix
int Agent_AnalyzeError(const char* error_output, const char* context,
                       char* analysis, size_t analysis_size);

//==============================================================================
// Subsystem Handler (for CLI integration)
//==============================================================================

int AgentSubsystem_Handler(int argc, char** argv, char* output, size_t output_size);
int AgentSubsystem_Init(void);
int AgentSubsystem_Shutdown(void);
int AgentSubsystem_GetStatus(char* status, size_t status_size);

#ifdef __cplusplus
}
#endif

#endif // AGENT_SUBSYSTEM_H
