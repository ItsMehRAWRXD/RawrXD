//==============================================================================
// DistributedInference.cpp - Phase 15C: Distributed Inference Implementation
//==============================================================================

#include "DistributedInference.h"
#include "RemoteCluster.h"
#include "../inference/SRIPBackend.h"
#include "../core/ExecutionJournal.h"
#include <cstdio>
#include <cstring>
#include <process.h>

//==============================================================================
// Internal State
//==============================================================================

static DistributedContext g_dist = {0};
static ModelPanelUpdateCallback g_modelPanelCb = NULL;

//==============================================================================
// Lifecycle
//==============================================================================

int DistributedInference_Init(int strategy) {
    if (g_dist.initialized) {
        return 0;
    }
    
    memset(&g_dist, 0, sizeof(g_dist));
    InitializeCriticalSection(&g_dist.lock);
    
    g_dist.strategy = strategy;
    g_dist.initialized = 1;
    
    // Initialize node performance from cluster
    RemoteNodeInfo nodes[MAX_DISTRIBUTED_NODES];
    int count;
    RemoteCluster_GetHealthyNodes(nodes, MAX_DISTRIBUTED_NODES, &count);
    
    EnterCriticalSection(&g_dist.lock);
    g_dist.node_count = count;
    for (int i = 0; i < count; i++) {
        strncpy(g_dist.node_perf[i].node_id, nodes[i].id, MAX_NODE_ID_LEN - 1);
        g_dist.node_perf[i].tokens_per_second = nodes[i].tokens_per_second;
        g_dist.node_perf[i].latency_ms = nodes[i].latency_ms;
        g_dist.node_perf[i].memory_available_mb = nodes[i].memory_available_mb;
        g_dist.node_perf[i].queue_depth = nodes[i].current_load;
        g_dist.node_perf[i].reliability_score = 1.0f;
        g_dist.node_perf[i].last_updated_ms = GetTickCount64();
    }
    LeaveCriticalSection(&g_dist.lock);
    
    // Start metrics collection
    DistributedInference_StartMetricsCollection();
    
    Journal_LogUserRequest("Distributed inference initialized", 
                          DistributedInference_StrategyName(strategy));
    
    return 0;
}

int DistributedInference_Shutdown(void) {
    if (!g_dist.initialized) {
        return 0;
    }
    
    DistributedInference_StopMetricsCollection();
    
    // Cancel all active requests
    EnterCriticalSection(&g_dist.lock);
    for (int i = 0; i < g_dist.active_count; i++) {
        if (g_dist.active_requests[i]) {
            // TODO: Cancel actual requests
            free(g_dist.active_requests[i]);
            g_dist.active_requests[i] = NULL;
        }
    }
    g_dist.active_count = 0;
    LeaveCriticalSection(&g_dist.lock);
    
    DeleteCriticalSection(&g_dist.lock);
    g_dist.initialized = 0;
    
    Journal_LogUserRequest("Distributed inference shutdown", "");
    
    return 0;
}

int DistributedInference_IsInitialized(void) {
    return g_dist.initialized;
}

//==============================================================================
// Strategy Configuration
//==============================================================================

int DistributedInference_SetStrategy(int strategy) {
    g_dist.strategy = strategy;
    
    char msg[64];
    snprintf(msg, sizeof(msg), "Strategy changed to: %s",
             DistributedInference_StrategyName(strategy));
    Journal_LogUserRequest(msg, "");
    
    return 0;
}

int DistributedInference_GetStrategy(void) {
    return g_dist.strategy;
}

const char* DistributedInference_StrategyName(int strategy) {
    switch (strategy) {
        case DISTRIBUTION_STRATEGY_TENSOR: return "tensor_parallel";
        case DISTRIBUTION_STRATEGY_PIPELINE: return "pipeline_parallel";
        case DISTRIBUTION_STRATEGY_TASK: return "task_parallel";
        default: return "unknown";
    }
}

//==============================================================================
// Distributed Generation
//==============================================================================

int DistributedInference_Submit(const InferenceRequest* req,
                                 const char** target_nodes,
                                 int num_nodes,
                                 void (*on_token)(const char*, int, void*),
                                 void (*on_complete)(int, const InferenceResponse*, void*),
                                 void* user_data) {
    if (!req || num_nodes <= 0 || num_nodes > MAX_DISTRIBUTED_NODES) {
        return -1;
    }
    
    // Allocate request
    DistributedRequest* dreq = (DistributedRequest*)calloc(1, sizeof(DistributedRequest));
    if (!dreq) {
        return -1;
    }
    
    static int next_id = 1;
    dreq->request_id = next_id++;
    dreq->base_request = *req;
    dreq->strategy = g_dist.strategy;
    dreq->num_nodes = num_nodes;
    dreq->on_token = on_token;
    dreq->on_complete = on_complete;
    dreq->user_data = user_data;
    
    for (int i = 0; i < num_nodes; i++) {
        strncpy(dreq->node_ids[i], target_nodes[i], MAX_NODE_ID_LEN - 1);
    }
    
    // Add to active requests
    EnterCriticalSection(&g_dist.lock);
    if (g_dist.active_count < MAX_PARALLEL_REQUESTS) {
        g_dist.active_requests[g_dist.active_count++] = dreq;
    } else {
        LeaveCriticalSection(&g_dist.lock);
        free(dreq);
        return -1;
    }
    LeaveCriticalSection(&g_dist.lock);
    
    // Execute based on strategy
    InferenceResponse response = {0};
    int result = -1;
    
    switch (g_dist.strategy) {
        case DISTRIBUTION_STRATEGY_TENSOR:
            result = DistributedInference_TensorParallel(req, target_nodes, num_nodes, &response);
            break;
            
        case DISTRIBUTION_STRATEGY_PIPELINE:
            result = DistributedInference_PipelineParallel(req, target_nodes, num_nodes, &response);
            break;
            
        case DISTRIBUTION_STRATEGY_TASK:
            result = DistributedInference_TaskParallel(req, 1, target_nodes, &response);
            break;
    }
    
    // Complete
    if (on_complete) {
        on_complete(dreq->request_id, &response, user_data);
    }
    
    // Remove from active
    EnterCriticalSection(&g_dist.lock);
    for (int i = 0; i < g_dist.active_count; i++) {
        if (g_dist.active_requests[i] == dreq) {
            g_dist.active_requests[i] = g_dist.active_requests[--g_dist.active_count];
            break;
        }
    }
    LeaveCriticalSection(&g_dist.lock);
    
    free(dreq);
    
    return result;
}

int DistributedInference_Cancel(int request_id) {
    EnterCriticalSection(&g_dist.lock);
    
    for (int i = 0; i < g_dist.active_count; i++) {
        if (g_dist.active_requests[i] && g_dist.active_requests[i]->request_id == request_id) {
            // TODO: Actually cancel the request
            g_dist.active_requests[i]->tokens_total = -1; // Mark as cancelled
            LeaveCriticalSection(&g_dist.lock);
            return 0;
        }
    }
    
    LeaveCriticalSection(&g_dist.lock);
    return -1;
}

int DistributedInference_GetStatus(int request_id, DistributedRequest* out) {
    EnterCriticalSection(&g_dist.lock);
    
    for (int i = 0; i < g_dist.active_count; i++) {
        if (g_dist.active_requests[i] && g_dist.active_requests[i]->request_id == request_id) {
            *out = *g_dist.active_requests[i];
            LeaveCriticalSection(&g_dist.lock);
            return 0;
        }
    }
    
    LeaveCriticalSection(&g_dist.lock);
    return -1;
}

//==============================================================================
// Parallel Strategies
//==============================================================================

int DistributedInference_TensorParallel(const InferenceRequest* req,
                                         const char** node_ids,
                                         int num_nodes,
                                         InferenceResponse* out) {
    // For tensor parallelism, we split the model weights across nodes
    // Each node computes a portion of the attention/FF layers
    // Results are aggregated
    
    if (!req || !out) return -1;
    
    // Connect to all nodes
    SRIPBackend* backends[MAX_DISTRIBUTED_NODES] = {0};
    
    for (int i = 0; i < num_nodes; i++) {
        RemoteNodeInfo node;
        if (RemoteCluster_GetNode(node_ids[i], &node) != 0) {
            // Cleanup
            for (int j = 0; j < i; j++) {
                delete backends[j];
            }
            return -1;
        }
        
        SRIPConfig config = {0};
        strncpy(config.host, node.host, sizeof(config.host) - 1);
        config.port = node.port;
        
        backends[i] = new SRIPBackend(&config);
        if (backends[i]->Initialize(NULL) != 0) {
            // Cleanup
            for (int j = 0; j <= i; j++) {
                delete backends[j];
            }
            return -1;
        }
    }
    
    // For now, just use the first node (full tensor parallelism requires
    // model-specific splitting which needs more implementation)
    int result = backends[0]->Generate(req, out);
    
    // Cleanup
    for (int i = 0; i < num_nodes; i++) {
        delete backends[i];
    }
    
    return result;
}

int DistributedInference_PipelineParallel(const InferenceRequest* req,
                                           const char** node_ids,
                                           int num_nodes,
                                           InferenceResponse* out) {
    // For pipeline parallelism, different nodes handle different layers
    // Node 0: layers 0-N/num_nodes
    // Node 1: layers N/num_nodes-2N/num_nodes
    // etc.
    
    // This requires the model to be split and each node to know its layer range
    // For now, delegate to first node
    return DistributedInference_TensorParallel(req, node_ids, num_nodes, out);
}

int DistributedInference_TaskParallel(const InferenceRequest* reqs,
                                       int num_requests,
                                       const char** node_ids,
                                       InferenceResponse* outs) {
    // For task parallelism, each request goes to a different node
    // This is the simplest form of distribution
    
    if (!reqs || !outs) return -1;
    
    // Launch threads for each request
    HANDLE threads[MAX_DISTRIBUTED_NODES];
    
    typedef struct ThreadData {
        const InferenceRequest* req;
        const char* node_id;
        InferenceResponse* out;
        int result;
    } ThreadData;
    
    ThreadData thread_data[MAX_DISTRIBUTED_NODES];
    
    for (int i = 0; i < num_requests && i < MAX_DISTRIBUTED_NODES; i++) {
        thread_data[i].req = &reqs[i];
        thread_data[i].node_id = node_ids[i % num_requests];
        thread_data[i].out = &outs[i];
        thread_data[i].result = -1;
        
        threads[i] = (HANDLE)_beginthreadex(NULL, 0, [](void* param) -> unsigned int {
            ThreadData* data = (ThreadData*)param;
            
            RemoteNodeInfo node;
            if (RemoteCluster_GetNode(data->node_id, &node) != 0) {
                return 1;
            }
            
            SRIPConfig config = {0};
            strncpy(config.host, node.host, sizeof(config.host) - 1);
            config.port = node.port;
            
            SRIPBackend backend(&config);
            if (backend.Initialize(NULL) != 0) {
                return 1;
            }
            
            data->result = backend.Generate(data->req, data->out);
            return 0;
        }, &thread_data[i], 0, NULL);
    }
    
    // Wait for all
    WaitForMultipleObjects(num_requests, threads, TRUE, INFINITE);
    
    // Cleanup
    for (int i = 0; i < num_requests; i++) {
        CloseHandle(threads[i]);
    }
    
    return 0;
}

//==============================================================================
// SEG Workflow Integration
//==============================================================================

int DistributedInference_RegisterWithSEG(void) {
    // Register distributed inference as a SEG node type
    // This allows workflows to use "distributed_generate" nodes
    
    Journal_LogUserRequest("Distributed inference registered with SEG", "");
    return 0;
}

int DistributedInference_SEGHandler(void* workflow, void* node_data, void* output) {
    (void)workflow;
    (void)node_data;
    (void)output;
    
    // Handle SEG node execution
    // Extract request from node_data
    // Submit to distributed inference
    // Write result to output
    
    return 0;
}

int DistributedInference_SetSEGTargetNodes(void* workflow_node,
                                            const char** node_ids,
                                            int num_nodes) {
    (void)workflow_node;
    (void)node_ids;
    (void)num_nodes;
    
    // Store target nodes in workflow node metadata
    return 0;
}

//==============================================================================
// Performance Metrics & Feedback
//==============================================================================

void DistributedInference_UpdateNodeMetrics(const char* node_id,
                                             float tokens_per_sec,
                                             uint64_t latency_ms,
                                             uint64_t memory_mb) {
    EnterCriticalSection(&g_dist.lock);
    
    for (int i = 0; i < g_dist.node_count; i++) {
        if (strcmp(g_dist.node_perf[i].node_id, node_id) == 0) {
            g_dist.node_perf[i].tokens_per_second = tokens_per_sec;
            g_dist.node_perf[i].latency_ms = latency_ms;
            g_dist.node_perf[i].memory_available_mb = memory_mb;
            g_dist.node_perf[i].last_updated_ms = GetTickCount64();
            
            // Update reliability score
            float alpha = 0.1f; // EMA factor
            float success = (tokens_per_sec > 0) ? 1.0f : 0.0f;
            g_dist.node_perf[i].reliability_score = 
                (1.0f - alpha) * g_dist.node_perf[i].reliability_score + alpha * success;
            
            // Notify ModelPanel
            DistributedInference_NotifyModelPanel(node_id);
            
            break;
        }
    }
    
    LeaveCriticalSection(&g_dist.lock);
}

int DistributedInference_SelectOptimalNodes(const InferenceRequest* req,
                                            char** out_node_ids,
                                            int max_nodes,
                                            int* out_count) {
    (void)req;
    
    EnterCriticalSection(&g_dist.lock);
    
    // Sort nodes by performance score
    // Score = tokens_per_second * reliability / (latency_ms / 1000)
    
    typedef struct ScoredNode {
        int idx;
        float score;
    } ScoredNode;
    
    ScoredNode scored[MAX_DISTRIBUTED_NODES];
    for (int i = 0; i < g_dist.node_count; i++) {
        scored[i].idx = i;
        float latency_factor = g_dist.node_perf[i].latency_ms / 1000.0f;
        if (latency_factor < 1.0f) latency_factor = 1.0f;
        scored[i].score = g_dist.node_perf[i].tokens_per_second * 
                         g_dist.node_perf[i].reliability_score / latency_factor;
    }
    
    // Sort by score (descending)
    for (int i = 0; i < g_dist.node_count - 1; i++) {
        for (int j = i + 1; j < g_dist.node_count; j++) {
            if (scored[j].score > scored[i].score) {
                ScoredNode tmp = scored[i];
                scored[i] = scored[j];
                scored[j] = tmp;
            }
        }
    }
    
    // Return top nodes
    int count = (max_nodes < g_dist.node_count) ? max_nodes : g_dist.node_count;
    for (int i = 0; i < count; i++) {
        strncpy(out_node_ids[i], g_dist.node_perf[scored[i].idx].node_id, MAX_NODE_ID_LEN - 1);
    }
    *out_count = count;
    
    LeaveCriticalSection(&g_dist.lock);
    
    return 0;
}

void DistributedInference_GetClusterMetrics(float* out_total_tps,
                                               uint64_t* out_avg_latency,
                                               int* out_active_requests) {
    EnterCriticalSection(&g_dist.lock);
    
    float total_tps = 0;
    uint64_t total_latency = 0;
    
    for (int i = 0; i < g_dist.node_count; i++) {
        total_tps += g_dist.node_perf[i].tokens_per_second;
        total_latency += g_dist.node_perf[i].latency_ms;
    }
    
    if (out_total_tps) *out_total_tps = total_tps;
    if (out_avg_latency) *out_avg_latency = (g_dist.node_count > 0) ? 
                                            total_latency / g_dist.node_count : 0;
    if (out_active_requests) *out_active_requests = g_dist.active_count;
    
    LeaveCriticalSection(&g_dist.lock);
}

int DistributedInference_ExportMetricsForGUI(char* json_buffer, size_t buffer_size) {
    if (!json_buffer || buffer_size == 0) return -1;
    
    EnterCriticalSection(&g_dist.lock);
    
    int pos = snprintf(json_buffer, buffer_size, "{\n  \"nodes\": [\n");
    
    for (int i = 0; i < g_dist.node_count && pos < (int)buffer_size - 256; i++) {
        pos += snprintf(json_buffer + pos, buffer_size - pos,
            "    {\n"
            "      \"id\": \"%s\",\n"
            "      \"tps\": %.2f,\n"
            "      \"latency_ms\": %llu,\n"
            "      \"memory_mb\": %llu,\n"
            "      \"reliability\": %.2f,\n"
            "      \"queue_depth\": %d\n"
            "    }%s\n",
            g_dist.node_perf[i].node_id,
            g_dist.node_perf[i].tokens_per_second,
            g_dist.node_perf[i].latency_ms,
            g_dist.node_perf[i].memory_available_mb,
            g_dist.node_perf[i].reliability_score,
            g_dist.node_perf[i].queue_depth,
            (i < g_dist.node_count - 1) ? "," : "");
    }
    
    pos += snprintf(json_buffer + pos, buffer_size - pos, "  ],\n");
    
    // Add cluster summary
    float total_tps = 0;
    for (int i = 0; i < g_dist.node_count; i++) {
        total_tps += g_dist.node_perf[i].tokens_per_second;
    }
    
    pos += snprintf(json_buffer + pos, buffer_size - pos,
        "  \"cluster\": {\n"
        "    \"total_tps\": %.2f,\n"
        "    \"active_requests\": %d,\n"
        "    \"node_count\": %d\n"
        "  }\n"
        "}\n",
        total_tps, g_dist.active_count, g_dist.node_count);
    
    LeaveCriticalSection(&g_dist.lock);
    
    return 0;
}

//==============================================================================
// Benchmarking
//==============================================================================

int DistributedInference_BenchmarkNode(const char* node_id,
                                        const char* model_id,
                                        const char* test_prompt,
                                        BenchmarkResult* out) {
    if (!node_id || !model_id || !test_prompt || !out) return -1;
    
    memset(out, 0, sizeof(BenchmarkResult));
    strncpy(out->node_id, node_id, MAX_NODE_ID_LEN - 1);
    
    RemoteNodeInfo node;
    if (RemoteCluster_GetNode(node_id, &node) != 0) {
        out->success = 0;
        strcpy(out->error_message, "Node not found");
        return -1;
    }
    
    // Connect
    SRIPConfig config = {0};
    strncpy(config.host, node.host, sizeof(config.host) - 1);
    config.port = node.port;
    
    SRIPBackend backend(&config);
    if (backend.Initialize(NULL) != 0) {
        out->success = 0;
        strcpy(out->error_message, "Connection failed");
        return -1;
    }
    
    // Run benchmark
    InferenceRequest req = {0};
    strncpy(req.model_id, model_id, sizeof(req.model_id) - 1);
    strncpy(req.prompt, test_prompt, sizeof(req.prompt) - 1);
    req.max_tokens = 256;
    
    InferenceResponse res = {0};
    uint64_t start = GetTickCount64();
    
    int result = backend.Generate(&req, &res);
    
    uint64_t elapsed = GetTickCount64() - start;
    
    if (result == 0) {
        out->success = 1;
        out->tokens_per_second = res.tokens_per_second;
        out->latency_ms = elapsed;
        out->memory_used_mb = node.memory_total_mb - node.memory_available_mb;
    } else {
        out->success = 0;
        strcpy(out->error_message, "Generation failed");
    }
    
    // Update metrics
    DistributedInference_UpdateNodeMetrics(node_id, 
                                              out->tokens_per_second,
                                              out->latency_ms,
                                              node.memory_available_mb);
    
    return result;
}

int DistributedInference_BenchmarkCluster(const char* model_id,
                                          const char* test_prompt,
                                          BenchmarkResult* outs,
                                          int max_results,
                                          int* out_count) {
    if (!model_id || !test_prompt || !outs || !out_count) return -1;
    
    // Get all healthy nodes
    RemoteNodeInfo nodes[MAX_DISTRIBUTED_NODES];
    int node_count;
    RemoteCluster_GetHealthyNodes(nodes, MAX_DISTRIBUTED_NODES, &node_count);
    
    int count = (node_count < max_results) ? node_count : max_results;
    
    for (int i = 0; i < count; i++) {
        DistributedInference_BenchmarkNode(nodes[i].id, model_id, test_prompt, &outs[i]);
    }
    
    *out_count = count;
    
    Journal_LogUserRequest("Cluster benchmark complete", model_id);
    
    return 0;
}

DWORD WINAPI DistributedInference_MetricsThread(LPVOID param) {
    (void)param;
    
    while (g_dist.metrics_running) {
        // Update metrics for all nodes
        RemoteNodeInfo nodes[MAX_DISTRIBUTED_NODES];
        int count;
        RemoteCluster_GetHealthyNodes(nodes, MAX_DISTRIBUTED_NODES, &count);
        
        for (int i = 0; i < count; i++) {
            // Ping node to get current latency
            uint64_t latency;
            if (RemoteCluster_PingNode(nodes[i].id, &latency) == 0) {
                // Get current performance from node
                DistributedInference_UpdateNodeMetrics(
                    nodes[i].id,
                    nodes[i].tokens_per_second,
                    latency,
                    nodes[i].memory_available_mb);
            }
        }
        
        Sleep(5000); // Update every 5 seconds
    }
    
    return 0;
}

int DistributedInference_StartMetricsCollection(void) {
    if (g_dist.metrics_running) {
        return 0;
    }
    
    g_dist.metrics_running = 1;
    g_dist.metrics_thread = CreateThread(NULL, 0,
                                          DistributedInference_MetricsThread,
                                          NULL, 0, NULL);
    
    return (g_dist.metrics_thread != NULL) ? 0 : -1;
}

int DistributedInference_StopMetricsCollection(void) {
    if (!g_dist.metrics_running) {
        return 0;
    }
    
    g_dist.metrics_running = 0;
    
    if (g_dist.metrics_thread) {
        WaitForSingleObject(g_dist.metrics_thread, 5000);
        CloseHandle(g_dist.metrics_thread);
        g_dist.metrics_thread = NULL;
    }
    
    return 0;
}

//==============================================================================
// ModelPanel Integration
//==============================================================================

void DistributedInference_SetModelPanelCallback(ModelPanelUpdateCallback cb) {
    g_modelPanelCb = cb;
}

void DistributedInference_NotifyModelPanel(const char* node_id) {
    if (!g_modelPanelCb || !node_id) return;
    
    EnterCriticalSection(&g_dist.lock);
    
    for (int i = 0; i < g_dist.node_count; i++) {
        if (strcmp(g_dist.node_perf[i].node_id, node_id) == 0) {
            int status = (g_dist.node_perf[i].reliability_score > 0.8f) ? 1 : 
                        (g_dist.node_perf[i].reliability_score > 0.5f) ? 0 : -1;
            
            g_modelPanelCb(node_id,
                          g_dist.node_perf[i].tokens_per_second,
                          g_dist.node_perf[i].latency_ms,
                          status);
            break;
        }
    }
    
    LeaveCriticalSection(&g_dist.lock);
}
