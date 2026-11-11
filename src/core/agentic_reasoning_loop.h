// ============================================================================
// agentic_reasoning_loop.h — Agentic Reasoning Engine API
// ============================================================================

#ifndef AGENTIC_REASONING_LOOP_H
#define AGENTIC_REASONING_LOOP_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Agent states
typedef enum {
    AGENT_STATE_IDLE,
    AGENT_STATE_THINKING,
    AGENT_STATE_EXECUTING_TOOL,
    AGENT_STATE_COMPLETE,
    AGENT_STATE_ERROR
} AgentState;

// Decision types
typedef enum {
    DECISION_THINK,
    DECISION_ACT,
    DECISION_DONE
} DecisionType;

// Tool function signature
typedef int (*ToolFunction)(const char* args, char* result, size_t result_len);

// Agent context (opaque handle)
typedef struct AgentContext AgentContext;

// API Functions

// Initialize the agentic system
void agentic_init(void);

// Create a new agent context
AgentContext* agent_create(void);

// Destroy an agent context
void agent_destroy(AgentContext* ctx);

// Set the task for the agent
void agent_set_task(AgentContext* ctx, const char* task);

// Run the agentic reasoning loop (blocking)
void agent_run(AgentContext* ctx);

// Register a new tool
void agent_register_tool(const char* name, const char* description, ToolFunction func);

// Get current agent state
AgentState agent_get_state(const AgentContext* ctx);

// Get performance statistics
typedef struct {
    int steps_completed;
    int tokens_generated;
    int tool_calls_made;
    double total_time_ms;
    double tokens_per_sec;
} AgentStats;

void agent_get_stats(const AgentContext* ctx, AgentStats* stats);

// Integration with Aperture inference
// This would be implemented to call the actual Aperture engine
typedef void (*InferenceCallback)(const char* prompt, char* response, size_t response_len);
void agent_set_inference_callback(InferenceCallback callback);

#ifdef __cplusplus
}
#endif

#endif // AGENTIC_REASONING_LOOP_H
