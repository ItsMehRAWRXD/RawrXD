//==============================================================================
// SovereignSEG.h - Phase 11: Sovereign Execution Graph
//
// Graph-based orchestration engine for the Sovereign Runtime.
// Executes multi-node workflows with dependency resolution, telemetry,
// and error propagation across all 52 subsystems.
//==============================================================================

#ifndef SOVEREIGN_SEG_H
#define SOVEREIGN_SEG_H

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// SEG Version & Constants
//==============================================================================

#define SEG_VERSION "11.0.0"
#define SEG_VERSION_MAJOR 11
#define SEG_VERSION_MINOR 0
#define SEG_VERSION_PATCH 0

#define SEG_MAX_NODES 256
#define SEG_MAX_DEPENDENCIES 8
#define SEG_MAX_ARGS 1024
#define SEG_MAX_OUTPUT 4096

//==============================================================================
// Node Types
//==============================================================================

typedef enum {
    SEG_NODE_CPU = 0,           // C++, MASM, AVX2 kernels
    SEG_NODE_GPU,               // Vulkan compute shaders
    SEG_NODE_LANGUAGE,          // Python, Rust, Go, Java, etc.
    SEG_NODE_AGENT,             // Autonomous reasoning/planning
    SEG_NODE_AUDIT,             // Health verification
    SEG_NODE_IO,                // File operations, network
    SEG_NODE_CUSTOM             // User-defined nodes
} SegNodeType;

//==============================================================================
// Node States
//==============================================================================

typedef enum {
    SEG_STATE_PENDING = 0,      // Waiting for dependencies
    SEG_STATE_RUNNING,          // Currently executing
    SEG_STATE_COMPLETED,        // Success
    SEG_STATE_FAILED,           // Error
    SEG_STATE_SKIPPED           // Dependency failed, skipped
} SegNodeState;

//==============================================================================
// SEG Node Definition
//==============================================================================

typedef struct SegNode {
    // Identity
    int id;                                     // Unique node ID
    SegNodeType type;                           // Node type
    const char* name;                           // Human-readable name
    
    // Execution
    const char* subsystem;                      // Target subsystem (e.g., "python")
    const char* command;                        // Command (e.g., "run", "compile")
    const char* args;                           // Arguments (JSON or CLI-style)
    
    // Dependencies
    int depends_on[SEG_MAX_DEPENDENCIES];       // Prerequisite node IDs
    int depends_count;                          // Number of dependencies
    
    // State (runtime)
    SegNodeState state;                         // Current execution state
    int exit_code;                              // Subsystem exit code
    
    // Telemetry
    uint64_t start_time_ms;                     // Execution start timestamp
    uint64_t end_time_ms;                       // Execution end timestamp
    uint64_t duration_ms;                       // Total execution time
    
    // Output
    char output[SEG_MAX_OUTPUT];                // Captured stdout/stderr
    size_t output_len;                          // Output length
    
    // Error tracking
    char error_message[256];                    // Error description if failed
} SegNode;

//==============================================================================
// SEG Workflow Definition
//==============================================================================

typedef struct SegWorkflow {
    const char* name;                           // Workflow identifier
    const char* description;                    // Human-readable description
    SegNode nodes[SEG_MAX_NODES];               // Node array
    int node_count;                             // Total nodes
    int version;                                // Workflow format version
} SegWorkflow;

//==============================================================================
// SEG Execution Result
//==============================================================================

typedef struct SegResult {
    int success_count;                          // Nodes that completed
    int failed_count;                           // Nodes that failed
    int skipped_count;                          // Nodes skipped due to deps
    uint64_t total_duration_ms;                 // Total workflow time
    int overall_success;                        // 1 if all nodes succeeded
} SegResult;

//==============================================================================
// SEG API Functions
//==============================================================================

// Initialize SEG subsystem
int Seg_Init(void);

// Shutdown SEG subsystem
int Seg_Shutdown(void);

// Load workflow from JSON file
int Seg_LoadWorkflow(const char* path, SegWorkflow* out_workflow);

// Save workflow to JSON file
int Seg_SaveWorkflow(const SegWorkflow* workflow, const char* path);

// Execute workflow with dependency resolution
int Seg_ExecuteGraph(const SegWorkflow* workflow, SegResult* out_result);

// Execute single node
int Seg_ExecuteNode(SegNode* node);

// Check if all dependencies are satisfied
int Seg_CheckDependencies(const SegWorkflow* workflow, const SegNode* node);

// Get node by ID
SegNode* Seg_GetNodeById(SegWorkflow* workflow, int id);

// Get execution summary as JSON
int Seg_GetSummaryJSON(const SegWorkflow* workflow, const SegResult* result, 
                       char* buffer, size_t buffer_size);

// Validate workflow (check for cycles, missing deps, etc.)
int Seg_ValidateWorkflow(const SegWorkflow* workflow, char* error_buffer, size_t error_size);

//==============================================================================
// Utility Functions
//==============================================================================

const char* Seg_NodeTypeToString(SegNodeType type);
const char* Seg_NodeStateToString(SegNodeState state);
SegNodeType Seg_StringToNodeType(const char* str);

#ifdef __cplusplus
}
#endif

#endif // SOVEREIGN_SEG_H
