//==============================================================================
// DistributedInference.h - Phase 15C: SEG-Aware Distributed Inference
//
// Multi-node inference across SRIP cluster:
// - Parallel generation across nodes (tensor parallelism)
// - Pipeline parallelism for multi-layer models
// - SEG workflow distribution (tasks target specific nodes)
// - Real-time metrics feedback to ModelPanel
// - Automatic load balancing based on node performance
//==============================================================================

#ifndef DISTRIBUTED_INFERENCE_H
#define DISTRIBUTED_INFERENCE_H

#include "RemoteCluster.h"
#include "InferenceRequest.h"
#include "ExecutionJournal.h"
#include <windows.h>

#define MAX_DISTRIBUTED_NODES 16
#define MAX_PARALLEL_REQUESTS 64
#define DISTRIBUTION_STRATEGY_TENSOR 0
#define DISTRIBUTION_STRATEGY_PIPELINE 1
#define DISTRIBUTION_STRATEGY_TASK 2

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// Distributed Request
//==============================================================================

typedef struct DistributedRequest {
    int request_id;
    InferenceRequest base_request;
    
    // Distribution
    int strategy;              // TENSOR, PIPELINE, or TASK
    int num_nodes;
    char node_ids[MAX_DISTRIBUTED_NODES][MAX_NODE_ID_LEN];
    
    // Progress
    int tokens_generated;
    int tokens_total;
    int nodes_completed;
    
    // Results
    InferenceResponse partial_responses[MAX_DISTRIBUTED_NODES];
    int partial_count;
    
    // Callbacks
    void (*on_token)(const char* token, int node_idx, void* user_data);
    void (*on_complete)(int request_id, const InferenceResponse* response, void* user_data);
    void* user_data;
} DistributedRequest;

//==============================================================================
// Node Performance Metrics (for SEG scheduling)
//==============================================================================

typedef struct NodePerformance {
    char node_id[MAX_NODE_ID_LEN];
    float tokens_per_second;
    uint64_t latency_ms;
    uint64_t memory_available_mb;
    int queue_depth;
    float reliability_score;     // 0.0 - 1.0 based on success rate
    uint64_t last_updated_ms;
} NodePerformance;

//==============================================================================
// Distributed Inference Context
//==============================================================================

typedef struct DistributedContext {
    int initialized;
    int strategy;
    
    // Node tracking
    NodePerformance node_perf[MAX_DISTRIBUTED_NODES];
    int node_count;
    
    // Active requests
    DistributedRequest* active_requests[MAX_PARALLEL_REQUESTS];
    int active_count;
    CRITICAL_SECTION lock;
    
    // Metrics thread
    HANDLE metrics_thread;
    int metrics_running;
    
    // SEG integration
    void* seg_context;  // Pointer to SEG workflow context
} DistributedContext;

//==============================================================================
// Lifecycle
//==============================================================================

int DistributedInference_Init(int strategy);
int DistributedInference_Shutdown(void);
int DistributedInference_IsInitialized(void);

//==============================================================================
// Strategy Configuration
//==============================================================================

int DistributedInference_SetStrategy(int strategy);
int DistributedInference_GetStrategy(void);
const char* DistributedInference_StrategyName(int strategy);

//==============================================================================
// Distributed Generation
//==============================================================================

// Submit a distributed inference request
// Returns request ID (>0) on success, -1 on failure
int DistributedInference_Submit(const InferenceRequest* req, 
                                 const char** target_nodes,
                                 int num_nodes,
                                 void (*on_token)(const char*, int, void*),
                                 void (*on_complete)(int, const InferenceResponse*, void*),
                                 void* user_data);

// Cancel a distributed request
int DistributedInference_Cancel(int request_id);

// Get request status
int DistributedInference_GetStatus(int request_id, DistributedRequest* out);

//==============================================================================
// Parallel Strategies
//==============================================================================

// Tensor parallelism: split tensors across nodes
int DistributedInference_TensorParallel(const InferenceRequest* req,
                                          const char** node_ids,
                                          int num_nodes,
                                          InferenceResponse* out);

// Pipeline parallelism: split layers across nodes
int DistributedInference_PipelineParallel(const InferenceRequest* req,
                                          const char** node_ids,
                                          int num_nodes,
                                          InferenceResponse* out);

// Task parallelism: multiple independent generations
int DistributedInference_TaskParallel(const InferenceRequest* reqs,
                                       int num_requests,
                                       const char** node_ids,
                                       InferenceResponse* outs);

//==============================================================================
// SEG Workflow Integration
//==============================================================================

// Register distributed inference as SEG node type
int DistributedInference_RegisterWithSEG(void);

// SEG node handler for distributed generation
int DistributedInference_SEGHandler(void* workflow, void* node_data, void* output);

// Target specific nodes for SEG task
int DistributedInference_SetSEGTargetNodes(void* workflow_node, 
                                            const char** node_ids,
                                            int num_nodes);

//==============================================================================
// Performance Metrics & Feedback
//==============================================================================

// Update node performance (called by metrics thread)
void DistributedInference_UpdateNodeMetrics(const char* node_id,
                                              float tokens_per_sec,
                                              uint64_t latency_ms,
                                              uint64_t memory_mb);

// Get best nodes for a request (based on performance)
int DistributedInference_SelectOptimalNodes(const InferenceRequest* req,
                                              char** out_node_ids,
                                              int max_nodes,
                                              int* out_count);

// Get cluster performance summary
void DistributedInference_GetClusterMetrics(float* out_total_tps,
                                               uint64_t* out_avg_latency,
                                               int* out_active_requests);

// Export metrics for ModelPanel
int DistributedInference_ExportMetricsForGUI(char* json_buffer, size_t buffer_size);

//==============================================================================
// Benchmarking
//==============================================================================

typedef struct BenchmarkResult {
    char node_id[MAX_NODE_ID_LEN];
    float tokens_per_second;
    uint64_t latency_ms;
    uint64_t memory_used_mb;
    int success;
    char error_message[256];
} BenchmarkResult;

// Benchmark a specific node
int DistributedInference_BenchmarkNode(const char* node_id,
                                        const char* model_id,
                                        const char* test_prompt,
                                        BenchmarkResult* out);

// Benchmark entire cluster
int DistributedInference_BenchmarkCluster(const char* model_id,
                                            const char* test_prompt,
                                            BenchmarkResult* outs,
                                            int max_results,
                                            int* out_count);

// Run continuous benchmark (for metrics collection)
DWORD WINAPI DistributedInference_MetricsThread(LPVOID param);
int DistributedInference_StartMetricsCollection(void);
int DistributedInference_StopMetricsCollection(void);

//==============================================================================
// Real-time Feedback to ModelPanel
//==============================================================================

// Callback for ModelPanel updates
typedef void (*ModelPanelUpdateCallback)(const char* node_id, 
                                         float tokens_per_sec,
                                         uint64_t latency_ms,
                                         int status);

void DistributedInference_SetModelPanelCallback(ModelPanelUpdateCallback cb);
void DistributedInference_NotifyModelPanel(const char* node_id);

#ifdef __cplusplus
}
#endif

#endif // DISTRIBUTED_INFERENCE_H
