//==============================================================================
// RemoteCluster.h - Phase LMM-2: Remote Inference Cluster
//
// Distributed inference for Low-Memory Mode:
// - Load-balanced cluster of inference nodes
// - Health monitoring and failover
// - Capability-based routing
// - ExecutionJournal integration
//==============================================================================

#ifndef REMOTE_CLUSTER_H
#define REMOTE_CLUSTER_H

#include <windows.h>
#include <cstdint>
#include "ModelRegistry.h"
#include "InferenceRequest.h"

#define MAX_CLUSTER_NODES 32
#define MAX_NODE_ID_LEN 64
#define MAX_HOST_LEN 128
#define CLUSTER_HEARTBEAT_INTERVAL_MS 5000
#define CLUSTER_TIMEOUT_MS 30000

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// Node State
//==============================================================================

typedef enum {
    NODE_STATE_UNKNOWN = 0,
    NODE_STATE_HEALTHY = 1,
    NODE_STATE_DEGRADED = 2,
    NODE_STATE_DOWN = -1,
    NODE_STATE_MAINTENANCE = -2
} NodeState;

//==============================================================================
// Remote Node Info
//==============================================================================

typedef struct RemoteNodeInfo {
    char id[MAX_NODE_ID_LEN];
    char host[MAX_HOST_LEN];
    int port;
    char backend_type[32];      // "srip", "remote_native", "remote_http"
    
    // Capacity
    int max_concurrent;
    int current_load;
    unsigned int capabilities;    // Bitmask of ModelCapability
    
    // Health
    NodeState health_state;
    uint64_t last_heartbeat_ms;
    uint64_t latency_ms;
    
    // Metrics
    float tokens_per_second;
    uint64_t memory_available_mb;
    uint64_t memory_total_mb;
    
    // Models available on this node
    char available_models[16][64];  // Model IDs
    int model_count;
} RemoteNodeInfo;

//==============================================================================
// Cluster Configuration
//==============================================================================

typedef struct ClusterConfig {
    char config_path[MAX_PATH];
    int heartbeat_interval_ms;
    int timeout_ms;
    int auto_failover;
    int enable_metrics;
} ClusterConfig;

//==============================================================================
// Scheduler Strategy
//==============================================================================

typedef enum {
    SCHEDULER_ROUND_ROBIN = 0,
    SCHEDULER_LEAST_LOADED = 1,
    SCHEDULER_CAPABILITY_MATCH = 2,
    SCHEDULER_LATENCY_AWARE = 3,
    SCHEDULER_MODEL_PINNED = 4
} SchedulerStrategy;

//==============================================================================
// Cluster Lifecycle
//==============================================================================

int RemoteCluster_Init(const ClusterConfig* config);
int RemoteCluster_Shutdown(void);
int RemoteCluster_IsInitialized(void);

//==============================================================================
// Node Management
//==============================================================================

int RemoteCluster_LoadFromJSON(const char* path);
int RemoteCluster_SaveToJSON(const char* path);

int RemoteCluster_AddNode(const RemoteNodeInfo* node);
int RemoteCluster_RemoveNode(const char* node_id);
int RemoteCluster_UpdateNode(const RemoteNodeInfo* node);

int RemoteCluster_GetNode(const char* node_id, RemoteNodeInfo* out);
int RemoteCluster_GetAllNodes(RemoteNodeInfo* out, int max_nodes, int* out_count);
int RemoteCluster_GetHealthyNodes(RemoteNodeInfo* out, int max_nodes, int* out_count);

//==============================================================================
// Scheduler
//==============================================================================

int RemoteCluster_SetStrategy(SchedulerStrategy strategy);
SchedulerStrategy RemoteCluster_GetStrategy(void);

// Select best node for request
// Returns node index (>= 0) on success, -1 on failure
int RemoteCluster_SelectNode(const InferenceRequest* req, RemoteNodeInfo* out);

// Select node that has specific model loaded
int RemoteCluster_SelectNodeWithModel(const char* model_id, RemoteNodeInfo* out);

// Get current load across cluster
void RemoteCluster_GetClusterLoad(int* total_capacity, int* current_load, float* utilization);

//==============================================================================
// Health Monitoring
//==============================================================================

void RemoteCluster_Heartbeat(void);
int RemoteCluster_PingNode(const char* node_id, uint64_t* out_latency_ms);
void RemoteCluster_UpdateNodeHealth(const char* node_id, NodeState state);

// Background health check thread
DWORD WINAPI RemoteCluster_HealthCheckThread(LPVOID param);
int RemoteCluster_StartHealthMonitor(void);
int RemoteCluster_StopHealthMonitor(void);

//==============================================================================
// Metrics
//==============================================================================

void RemoteCluster_ReportNodeMetrics(const char* node_id, 
                                      float tokens_per_sec,
                                      uint64_t memory_used_mb);

void RemoteCluster_GetNodeMetrics(const char* node_id, 
                                   float* out_tokens_per_sec,
                                   uint64_t* out_memory_used_mb);

//==============================================================================
// Failover
//==============================================================================

int RemoteCluster_EnableFailover(int enable);
int RemoteCluster_IsFailoverEnabled(void);

// Get failover node for a failed node
int RemoteCluster_GetFailoverNode(const char* failed_node_id, RemoteNodeInfo* out);

//==============================================================================
// Utility
//==============================================================================

const char* RemoteCluster_StrategyToString(SchedulerStrategy s);
SchedulerStrategy RemoteCluster_StringToStrategy(const char* str);

const char* RemoteCluster_NodeStateToString(NodeState state);

// Format node info for display
void RemoteCluster_FormatNodeInfo(const RemoteNodeInfo* node, char* out, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif // REMOTE_CLUSTER_H
