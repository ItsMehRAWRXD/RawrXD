//==============================================================================
// SovereignAutoLoop.h - Phase 12: Autonomous Code Generation + Execution Loops
//
// Self-healing, self-optimizing code generation using SEG orchestration
// and agentic decision-making across 52 subsystems.
//==============================================================================

#ifndef SOVEREIGN_AUTOLOOP_H
#define SOVEREIGN_AUTOLOOP_H

#include "SovereignSEG.h"
#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// Version & Constants
//==============================================================================

#define AUTOLOOP_VERSION "12.0.0"
#define AUTOLOOP_VERSION_MAJOR 12
#define AUTOLOOP_VERSION_MINOR 0
#define AUTOLOOP_VERSION_PATCH 0

#define AUTOLOOP_MAX_STEPS 16
#define AUTOLOOP_MAX_ITERATIONS 10
#define AUTOLOOP_MAX_PROMPT 4096
#define AUTOLOOP_MAX_CODE 65536

//==============================================================================
// Loop Step Types
//==============================================================================

typedef enum {
    AUTO_STEP_GENERATE = 0,     // Generate code from spec
    AUTO_STEP_COMPILE,          // Compile code
    AUTO_STEP_EXECUTE,        // Run code
    AUTO_STEP_TEST,           // Run tests
    AUTO_STEP_FIX,            // Fix errors
    AUTO_STEP_OPTIMIZE,       // Optimize code
    AUTO_STEP_TRANSLATE,      // Translate to another language
    AUTO_STEP_VERIFY,         // Verify with audit
    AUTO_STEP_BENCHMARK,      // Benchmark performance
    AUTO_STEP_COMPARE,        // Compare variants
    AUTO_STEP_DECIDE          // Decide next action
} AutoStepType;

//==============================================================================
// Loop Step Definition
//==============================================================================

typedef struct AutoLoopStep {
    AutoStepType type;                          // Step type
    const char* description;                      // Human-readable description
    const char* subsystem;                      // Target subsystem
    const char* command;                        // Command to execute
    const char* args_template;                  // Args with placeholders
    
    // Conditional execution
    int run_on_success;                         // Run if previous succeeded
    int run_on_failure;                         // Run if previous failed
    int run_always;                             // Always run this step
    
    // Output handling
    char output_var[64];                        // Variable to store output
    char error_var[64];                         // Variable to store error
} AutoLoopStep;

//==============================================================================
// Autonomous Loop Definition
//==============================================================================

typedef struct AutoLoop {
    const char* name;                           // Loop identifier
    const char* description;                    // Human-readable description
    AutoLoopStep steps[AUTOLOOP_MAX_STEPS];     // Step array
    int step_count;                             // Total steps
    int max_iterations;                         // Max iterations before giving up
    int convergence_threshold;                  // Successes needed to converge
} AutoLoop;

//==============================================================================
// Loop Context (Runtime State)
//==============================================================================

typedef struct AutoLoopContext {
    // Iteration tracking
    int current_iteration;
    int current_step;
    int success_count;
    int failure_count;
    
    // Variables (key-value store for step outputs)
    char vars[16][256];                        // Variable values
    char var_names[16][64];                     // Variable names
    int var_count;
    
    // Code state
    char source_code[AUTOLOOP_MAX_CODE];         // Current code being worked on
    char source_file[MAX_PATH];                 // File path
    char target_language[32];                   // Language (rust, python, etc.)
    
    // Telemetry
    uint64_t start_time_ms;
    uint64_t last_iteration_time_ms;
    SegResult last_seg_result;                  // Last SEG execution result
    
    // Convergence
    int converged;                              // Loop has converged
    int converged_on_iteration;                 // Which iteration converged
} AutoLoopContext;

//==============================================================================
// Loop Result
//==============================================================================

typedef struct AutoLoopResult {
    int success;                                // Overall success
    int iterations_executed;                    // Total iterations run
    int final_step_reached;                     // Last step executed
    uint64_t total_duration_ms;                 // Total time
    char final_code[AUTOLOOP_MAX_CODE];          // Final code state
    char convergence_reason[256];                 // Why loop stopped
} AutoLoopResult;

//==============================================================================
// Predefined Loop Types
//==============================================================================

typedef enum {
    AUTOLOOP_WRITE_EXECUTE_FIX = 0,             // Generate, run, fix loop
    AUTOLOOP_OPTIMIZE_BENCHMARK,                // Optimize until converged
    AUTOLOOP_MULTI_LANGUAGE,                    // Generate in multiple languages
    AUTOLOOP_TEST_DRIVEN,                       // Write tests first, then code
    AUTOLOOP_REFACTOR,                          // Refactor existing code
    AUTOLOOP_CUSTOM                             // User-defined
} AutoLoopTemplate;

//==============================================================================
// API Functions
//==============================================================================

// Initialize AutoLoop subsystem
int AutoLoop_Init(void);

// Shutdown AutoLoop subsystem
int AutoLoop_Shutdown(void);

// Create loop from template
int AutoLoop_CreateFromTemplate(AutoLoopTemplate template_type, 
                                   const char* target_file,
                                   const char* language,
                                   AutoLoop* out_loop);

// Load loop from JSON
int AutoLoop_Load(const char* path, AutoLoop* out_loop);

// Save loop to JSON
int AutoLoop_Save(const AutoLoop* loop, const char* path);

// Execute autonomous loop
int AutoLoop_Execute(const AutoLoop* loop, AutoLoopContext* ctx, 
                     AutoLoopResult* out_result);

// Execute single iteration
int AutoLoop_ExecuteIteration(const AutoLoop* loop, AutoLoopContext* ctx);

// Execute single step
int AutoLoop_ExecuteStep(const AutoLoopStep* step, AutoLoopContext* ctx);

// Check if loop has converged
int AutoLoop_CheckConvergence(const AutoLoop* loop, const AutoLoopContext* ctx);

// Get variable value
const char* AutoLoop_GetVar(const AutoLoopContext* ctx, const char* name);

// Set variable value
int AutoLoop_SetVar(AutoLoopContext* ctx, const char* name, const char* value);

// Get summary as JSON
int AutoLoop_GetSummaryJSON(const AutoLoop* loop, const AutoLoopResult* result,
                            char* buffer, size_t buffer_size);

//==============================================================================
// Template Functions
//==============================================================================

int AutoLoop_CreateWriteExecuteFix(const char* target_file, 
                                    const char* language,
                                    const char* spec,
                                    AutoLoop* out_loop);

int AutoLoop_CreateOptimizeBenchmark(const char* target_file,
                                        const char* language,
                                        const char* metric,
                                        AutoLoop* out_loop);

int AutoLoop_CreateMultiLanguage(const char* spec,
                                  const char** languages,
                                  int language_count,
                                  AutoLoop* out_loop);

//==============================================================================
// Utility Functions
//==============================================================================

const char* AutoLoop_StepTypeToString(AutoStepType type);
const char* AutoLoop_TemplateToString(AutoLoopTemplate tpl);

#ifdef __cplusplus
}
#endif

#endif // SOVEREIGN_AUTOLOOP_H
