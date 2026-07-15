// Sovereign SDK - Public C API
// Bridges the Sovereign Engine to IDE/UI applications
// Version: 1.0.0
// Platform: Win64 (x64)

#ifndef SOVEREIGN_SDK_H
#define SOVEREIGN_SDK_H

#if defined(_WIN32) || defined(_WIN64)
#  if defined(SOVEREIGN_SDK_BUILD)
#    define SOVEREIGN_API __declspec(dllexport)
#  else
#    define SOVEREIGN_API __declspec(dllimport)
#  endif
#else
#  define SOVEREIGN_API
#endif

#define SOVEREIGN_STR2(x) #x
#define SOVEREIGN_STR(x) SOVEREIGN_STR2(x)

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// ============================================================================
// Version & Capability Constants
// ============================================================================

#define SOVEREIGN_SDK_VERSION_MAJOR 1
#define SOVEREIGN_SDK_VERSION_MINOR 0
#define SOVEREIGN_SDK_VERSION_PATCH 0

#define SOVEREIGN_MAX_NODES 8
#define SOVEREIGN_MAX_LAYERS 256
#define SOVEREIGN_MAX_TOKENS 32768
#define SOVEREIGN_MAX_PATH 260

// Capability flags
#define SOVEREIGN_CAP_AVX512     0x0001
#define SOVEREIGN_CAP_AMX        0x0002
#define SOVEREIGN_CAP_GPU        0x0004
#define SOVEREIGN_CAP_RING       0x0008
#define SOVEREIGN_CAP_DISTRIBUTED 0x0010
#define SOVEREIGN_CAP_SUPER_NODE  0x0020

// ============================================================================
// Opaque Handles
// ============================================================================

typedef struct SovereignContext* SovereignHandle;
typedef struct SovereignModel* SovereignModelHandle;
typedef struct SovereignTask* SovereignTaskHandle;
typedef struct SovereignGraph* SovereignGraphHandle;
typedef struct SovereignTaskWaitHandleImpl* SovereignTaskWaitHandle;

typedef enum {
    SOVEREIGN_TASK_STATE_PENDING = 0,
    SOVEREIGN_TASK_STATE_RUNNING = 1,
    SOVEREIGN_TASK_STATE_COMPLETED = 2
} SovereignTaskState;

// ============================================================================
// Configuration Structures
// ============================================================================

typedef struct {
    uint32_t node_id;
    uint32_t total_nodes;
    bool is_head;
    bool enable_gpu;
    bool enable_amx;
    uint32_t thread_pool_size;
    uint64_t kv_cache_size;      // Bytes per node
    const char* head_node_ip;    // For distributed mode
    uint16_t router_port;
    uint16_t pub_port;
} SovereignNodeConfig;

typedef struct {
    const char* model_path;
    uint32_t quantization;       // 8=Q8_0, 4=Q4_K, 2=Q2_K
    bool memory_map;             // Use memory-mapped I/O
    bool lazy_load;              // Load layers on demand
    uint32_t max_context;        // Maximum context length
} SovereignModelConfig;

typedef struct {
    uint32_t flags;              // Capability flags (read-only)
    uint64_t memory_available;
    uint64_t memory_used;
    uint32_t active_nodes;
    uint32_t tasks_queued;
    float avg_latency_ms;
    float throughput_tps;
} SovereignStatus;

typedef struct {
    uint32_t worker_threads;         // 0 = auto
    bool enable_thread_pinning;      // Pin workers to logical CPUs
    bool enable_memory_mapping;      // Prefer memory-mapped model I/O
    bool enable_numa_locality;       // Keep worker allocations NUMA-local
    bool enable_deterministic_mode;  // Stable scheduling for reproducibility
    uint64_t max_resident_bytes;     // 0 = auto
    uint32_t reserved;
} SovereignSuperNodeConfig;

typedef struct {
    uint32_t worker_threads;
    uint32_t active_workers;
    uint32_t queue_depth;
    uint64_t tokens_processed;
    float current_tps;
    float p50_latency_ms;
    float p95_latency_ms;
    float p99_latency_ms;
} SovereignSuperNodeStatus;

// ============================================================================
// Task & Graph Structures
// ============================================================================

typedef enum {
    SOVEREIGN_TASK_INFERENCE = 0,
    SOVEREIGN_TASK_ANALYSIS,
    SOVEREIGN_TASK_REFACTOR,
    SOVEREIGN_TASK_COMPLETE,
    SOVEREIGN_TASK_EXPLAIN
} SovereignTaskType;

typedef struct {
    SovereignTaskType type;
    const char* input;
    size_t input_len;
    char* output;
    size_t output_capacity;
    size_t* output_len;
    uint32_t max_tokens;
    float temperature;
    void* user_data;
    void (*on_progress)(float percent, void* user_data);
    void (*on_complete)(int error_code, void* user_data);
} SovereignTaskParams;

// Semantic graph node (for code analysis)
typedef struct {
    uint32_t id;
    const char* name;
    const char* type;            // "function", "class", "variable", etc.
    const char* file_path;
    uint32_t line_start;
    uint32_t line_end;
    uint32_t* dependencies;      // Array of node IDs
    uint32_t dependency_count;
    float embedding[512];        // Semantic embedding vector
} SovereignGraphNode;

typedef struct {
    uint32_t line;
    uint32_t column;
    uint32_t end_line;
    uint32_t end_column;
    const char* symbol;
    const char* kind;            // declaration, definition, reference, call
    const char* file_path;
} SovereignASTMatch;

typedef struct {
    uint32_t symbol_id;
    const char* symbol;
    const char* type_name;
    const char* scope;
    const char* file_path;
    uint32_t decl_line;
    uint32_t decl_column;
} SovereignSymbolInfo;

// ============================================================================
// Lifecycle API
// ============================================================================

// Initialize the Sovereign Engine
// Returns: Handle to engine context, or NULL on failure
SOVEREIGN_API SovereignHandle Sovereign_Init(const SovereignNodeConfig* config);

// Shutdown and cleanup
// Returns: 0 on success, error code on failure
SOVEREIGN_API int Sovereign_Shutdown(SovereignHandle handle);

// Get engine capabilities and status
// Returns: 0 on success
SOVEREIGN_API int Sovereign_GetStatus(SovereignHandle handle, SovereignStatus* status);

// Get SDK version string
SOVEREIGN_API const char* Sovereign_GetVersion(void);

SOVEREIGN_API uint32_t Sovereign_GetApiVersion(void);

// Super-Node lifecycle helper.
// Equivalent to Sovereign_Init with a single-node, local-first policy.
SOVEREIGN_API SovereignHandle Sovereign_InitSuperNode(const SovereignSuperNodeConfig* config);

// Query high-throughput local runtime state.
SOVEREIGN_API int Sovereign_GetSuperNodeStatus(
    SovereignHandle engine,
    SovereignSuperNodeStatus* status
);

// ============================================================================
// Model Management API
// ============================================================================

// Load a model (GGUF format)
// Returns: Model handle, or NULL on failure
SOVEREIGN_API SovereignModelHandle Sovereign_LoadModel(
    SovereignHandle engine,
    const SovereignModelConfig* config
);

// Unload a model
SOVEREIGN_API int Sovereign_UnloadModel(SovereignHandle engine, SovereignModelHandle model);

// Get model information
SOVEREIGN_API int Sovereign_GetModelInfo(
    SovereignModelHandle model,
    char* name, size_t name_capacity,
    uint32_t* num_layers,
    uint64_t* memory_usage
);

// ============================================================================
// Task Execution API (Async)
// ============================================================================

// Submit a task for execution
// Returns: Task handle, or NULL on failure
SOVEREIGN_API SovereignTaskHandle Sovereign_SubmitTask(
    SovereignHandle engine,
    SovereignModelHandle model,
    const SovereignTaskParams* params
);

// Submit a task and receive a per-task wait handle for agentic workflows.
SOVEREIGN_API int Sovereign_SubmitTaskWithHandle(
    SovereignHandle engine,
    SovereignModelHandle model,
    const SovereignTaskParams* params,
    SovereignTaskWaitHandle* out_handle
);

// Cancel a pending task
SOVEREIGN_API int Sovereign_CancelTask(SovereignHandle engine, SovereignTaskHandle task);

// Wait for task completion (blocking)
// timeout_ms: 0 = infinite, >0 = timeout in milliseconds
// Returns: 0 = success, 1 = timeout, <0 = error
SOVEREIGN_API int Sovereign_WaitForTask(
    SovereignHandle engine,
    SovereignTaskHandle task,
    uint32_t timeout_ms
);

// Poll task status (non-blocking)
// Returns: 0 = pending, 1 = complete, 2 = cancelled, <0 = error
SOVEREIGN_API int Sovereign_PollTask(SovereignHandle engine, SovereignTaskHandle task);

// Wait on a specific task wait handle.
SOVEREIGN_API int Sovereign_WaitTaskHandle(
    SovereignHandle engine,
    SovereignTaskWaitHandle handle,
    uint32_t timeout_ms
);

// Inspect the state of a specific task wait handle.
SOVEREIGN_API int Sovereign_GetTaskState(
    SovereignHandle engine,
    SovereignTaskWaitHandle handle,
    uint32_t* out_state
);

// Release a task wait handle when the caller is done with it.
SOVEREIGN_API void Sovereign_ReleaseTaskHandle(
    SovereignHandle engine,
    SovereignTaskWaitHandle handle
);

// ============================================================================
// Semantic Graph API (Code Intelligence)
// ============================================================================

// Load a codebase into the semantic graph
SOVEREIGN_API SovereignGraphHandle Sovereign_LoadCodeBase(
    SovereignHandle engine,
    const char* root_path,
    const char** file_patterns,    // e.g., ["*.cpp", "*.h", NULL]
    uint32_t num_patterns
);

// Query the semantic graph
// query: Natural language or structured query
// results: Array of node IDs (caller allocates, SDK fills)
// max_results: Size of results array
// Returns: Number of results found
SOVEREIGN_API int Sovereign_QuerySemanticGraph(
    SovereignGraphHandle graph,
    const char* query,
    uint32_t* results,
    uint32_t max_results,
    float* relevance_scores
);

// Get node details
SOVEREIGN_API int Sovereign_GetGraphNode(
    SovereignGraphHandle graph,
    uint32_t node_id,
    SovereignGraphNode* node
);

// Find references to a symbol
SOVEREIGN_API int Sovereign_FindReferences(
    SovereignGraphHandle graph,
    uint32_t node_id,
    uint32_t* references,
    uint32_t max_references
);

// Get call graph (who calls whom)
SOVEREIGN_API int Sovereign_GetCallGraph(
    SovereignGraphHandle graph,
    uint32_t node_id,
    uint32_t* callers,
    uint32_t* callees,
    uint32_t max_entries
);

// ============================================================================
// Ring Attention API (Distributed Compute)
// ============================================================================

// Initialize ring topology for distributed processing
SOVEREIGN_API int Sovereign_InitRing(
    SovereignHandle engine,
    uint32_t num_nodes,
    const char** node_ips,
    uint16_t base_port
);

// Join the ring (for worker nodes)
SOVEREIGN_API int Sovereign_JoinRing(SovereignHandle engine, const char* head_ip);

// Execute task across ring (distributed inference)
SOVEREIGN_API SovereignTaskHandle Sovereign_ExecuteRingTask(
    SovereignHandle engine,
    SovereignModelHandle model,
    const SovereignTaskParams* params
);

// Get ring status
SOVEREIGN_API int Sovereign_GetRingStatus(
    SovereignHandle engine,
    uint32_t* active_nodes,
    float* avg_latency_ms,
    uint64_t* tokens_processed
);

// ============================================================================
// Telemetry & Monitoring API
// ============================================================================

// Start telemetry collection
SOVEREIGN_API int Sovereign_StartTelemetry(SovereignHandle engine, const char* endpoint);

// Stop telemetry
SOVEREIGN_API int Sovereign_StopTelemetry(SovereignHandle engine);

// Get performance metrics
SOVEREIGN_API int Sovereign_GetMetrics(
    SovereignHandle engine,
    float* tokens_per_sec,
    float* latency_ms,
    uint64_t* memory_used,
    uint32_t* active_tasks
);

// Export profiling data
SOVEREIGN_API int Sovereign_ExportProfile(
    SovereignHandle engine,
    const char* output_path
);

// ============================================================================
// Error Handling
// ============================================================================

// Get last error code
SOVEREIGN_API int Sovereign_GetLastError(void);

// Get error message
SOVEREIGN_API const char* Sovereign_GetErrorString(int error_code);

// Set log level (0=none, 1=error, 2=warn, 3=info, 4=debug)
SOVEREIGN_API void Sovereign_SetLogLevel(int level);

// Set log callback
SOVEREIGN_API void Sovereign_SetLogCallback(
    void (*callback)(int level, const char* message, void* user_data),
    void* user_data
);

// ============================================================================
// IDE-Specific Extensions
// ============================================================================

// LSP-compatible completion request
SOVEREIGN_API int Sovereign_GetCompletions(
    SovereignHandle engine,
    SovereignGraphHandle graph,
    const char* file_path,
    uint32_t line,
    uint32_t column,
    char** completions,          // Array of completion strings
    uint32_t max_completions,
    uint32_t* num_completions
);

// Intent-based refactoring
SOVEREIGN_API SovereignTaskHandle Sovereign_Refactor(
    SovereignHandle engine,
    SovereignGraphHandle graph,
    const char* intent,          // Natural language intent
    uint32_t* target_nodes,      // Nodes to refactor
    uint32_t num_targets
);

// Explain code (generate explanation)
SOVEREIGN_API SovereignTaskHandle Sovereign_Explain(
    SovereignHandle engine,
    SovereignGraphHandle graph,
    uint32_t node_id,
    char* explanation,
    size_t explanation_capacity
);

// ============================================================================
// Utility Functions
// ============================================================================

// Check if hardware supports AVX-512
SOVEREIGN_API bool Sovereign_HasAVX512(void);

// Check if hardware supports AMX
SOVEREIGN_API bool Sovereign_HasAMX(void);

// Get optimal thread count
SOVEREIGN_API uint32_t Sovereign_GetOptimalThreadCount(void);

// Memory info
SOVEREIGN_API void Sovereign_GetMemoryInfo(uint64_t* total, uint64_t* available);

// Runtime controls for contention-sensitive IDE workloads.
SOVEREIGN_API int Sovereign_SetWorkerAffinityMask(
    SovereignHandle engine,
    uint64_t affinity_mask
);

SOVEREIGN_API int Sovereign_SetDeterministicMode(
    SovereignHandle engine,
    bool enabled
);

// ============================================================================
// AST/Symbol API (IDE-first hooks)
// ============================================================================

SOVEREIGN_API int Sovereign_QueryAST(
    SovereignGraphHandle graph,
    const char* pattern,
    SovereignASTMatch* out_matches,
    uint32_t max_matches,
    uint32_t* out_count
);

SOVEREIGN_API int Sovereign_GetSymbolInfo(
    SovereignGraphHandle graph,
    const char* symbol,
    SovereignSymbolInfo* out_info
);

SOVEREIGN_API int Sovereign_FindSymbolUsages(
    SovereignGraphHandle graph,
    const char* symbol,
    SovereignASTMatch* out_usages,
    uint32_t max_usages,
    uint32_t* out_count
);

SOVEREIGN_API int Sovereign_ComputeSemanticDiff(
    SovereignGraphHandle graph,
    const char* old_text,
    const char* new_text,
    uint32_t* affected_node_ids,
    uint32_t max_nodes,
    uint32_t* out_count
);

#ifdef __cplusplus
}
#endif

#endif // SOVEREIGN_SDK_H