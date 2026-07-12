//==============================================================================
// RemoteCluster.cpp - Phase LMM-2: Remote Inference Cluster Implementation
//==============================================================================

#include "RemoteCluster.h"
#include "ExecutionJournal.h"
#include "LowMemProfile.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

//==============================================================================
// Internal State
//==============================================================================

typedef struct ClusterState {
    RemoteNodeInfo nodes[MAX_CLUSTER_NODES];
    int node_count;
    ClusterConfig config;
    SchedulerStrategy strategy;
    int initialized;
    int failover_enabled;
    HANDLE health_thread;
    int health_thread_running;
    int round_robin_index;
    CRITICAL_SECTION lock;
} ClusterState;

static ClusterState g_cluster = {0};

//==============================================================================
// Lifecycle
//==============================================================================

int RemoteCluster_Init(const ClusterConfig* config) {
    if (g_cluster.initialized) {
        return 0;
    }
    
    memset(&g_cluster, 0, sizeof(g_cluster));
    InitializeCriticalSection(&g_cluster.lock);
    
    if (config) {
        g_cluster.config = *config;
    } else {
        // Default config
        strcpy(g_cluster.config.config_path, "config/remote_cluster.json");
        g_cluster.config.heartbeat_interval_ms = CLUSTER_HEARTBEAT_INTERVAL_MS;
        g_cluster.config.timeout_ms = CLUSTER_TIMEOUT_MS;
        g_cluster.config.auto_failover = 1;
        g_cluster.config.enable_metrics = 1;
    }
    
    g_cluster.strategy = SCHEDULER_LEAST_LOADED;
    g_cluster.failover_enabled = 1;
    g_cluster.round_robin_index = 0;
    
    // Initialize Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    // Try to load existing config
    RemoteCluster_LoadFromJSON(g_cluster.config.config_path);
    
    g_cluster.initialized = 1;
    
    Journal_LogUserRequest("Remote cluster initialized", g_cluster.config.config_path);
    
    return 0;
}

int RemoteCluster_Shutdown(void) {
    if (!g_cluster.initialized) {
        return 0;
    }
    
    RemoteCluster_StopHealthMonitor();
    
    // Save config
    RemoteCluster_SaveToJSON(g_cluster.config.config_path);
    
    WSACleanup();
    
    DeleteCriticalSection(&g_cluster.lock);
    g_cluster.initialized = 0;
    
    Journal_LogUserRequest("Remote cluster shutdown", "");
    
    return 0;
}

int RemoteCluster_IsInitialized(void) {
    return g_cluster.initialized;
}

//==============================================================================
// Node Management
//==============================================================================

int RemoteCluster_LoadFromJSON(const char* path) {
    // TODO: Implement JSON parsing
    // For now, add some example nodes
    
    EnterCriticalSection(&g_cluster.lock);
    
    // Example node 1
    if (g_cluster.node_count < MAX_CLUSTER_NODES) {
        RemoteNodeInfo* node = &g_cluster.nodes[g_cluster.node_count++];
        strcpy(node->id, "node01");
        strcpy(node->host, "10.0.0.21");
        node->port = 8080;
        strcpy(node->backend_type, "srip");
        node->max_concurrent = 4;
        node->current_load = 0;
        node->capabilities = CAP_CODE_GENERATION | CAP_CHAT | CAP_REASONING;
        node->health_state = NODE_STATE_UNKNOWN;
        node->tokens_per_second = 0;
        node->memory_available_mb = 16000;
        node->memory_total_mb = 32000;
        node->model_count = 0;
    }
    
    LeaveCriticalSection(&g_cluster.lock);
    
    return 0;
}

int RemoteCluster_SaveToJSON(const char* path) {
    // TODO: Implement JSON serialization
    (void)path;
    return 0;
}

int RemoteCluster_AddNode(const RemoteNodeInfo* node) {
    if (!node) return -1;
    
    EnterCriticalSection(&g_cluster.lock);
    
    if (g_cluster.node_count >= MAX_CLUSTER_NODES) {
        LeaveCriticalSection(&g_cluster.lock);
        return -1;
    }
    
    // Check for duplicate ID
    for (int i = 0; i < g_cluster.node_count; i++) {
        if (strcmp(g_cluster.nodes[i].id, node->id) == 0) {
            LeaveCriticalSection(&g_cluster.lock);
            return -1;
        }
    }
    
    g_cluster.nodes[g_cluster.node_count++] = *node;
    
    LeaveCriticalSection(&g_cluster.lock);
    
    char msg[256];
    snprintf(msg, sizeof(msg), "Added node: %s", node->id);
    Journal_LogUserRequest(msg, node->host);
    
    return 0;
}

int RemoteCluster_RemoveNode(const char* node_id) {
    if (!node_id) return -1;
    
    EnterCriticalSection(&g_cluster.lock);
    
    for (int i = 0; i < g_cluster.node_count; i++) {
        if (strcmp(g_cluster.nodes[i].id, node_id) == 0) {
            // Shift remaining nodes
            for (int j = i; j < g_cluster.node_count - 1; j++) {
                g_cluster.nodes[j] = g_cluster.nodes[j + 1];
            }
            g_cluster.node_count--;
            
            LeaveCriticalSection(&g_cluster.lock);
            
            Journal_LogUserRequest("Removed node", node_id);
            return 0;
        }
    }
    
    LeaveCriticalSection(&g_cluster.lock);
    return -1;
}

int RemoteCluster_UpdateNode(const RemoteNodeInfo* node) {
    if (!node) return -1;
    
    EnterCriticalSection(&g_cluster.lock);
    
    for (int i = 0; i < g_cluster.node_count; i++) {
        if (strcmp(g_cluster.nodes[i].id, node->id) == 0) {
            g_cluster.nodes[i] = *node;
            LeaveCriticalSection(&g_cluster.lock);
            return 0;
        }
    }
    
    LeaveCriticalSection(&g_cluster.lock);
    return -1;
}

int RemoteCluster_GetNode(const char* node_id, RemoteNodeInfo* out) {
    if (!node_id || !out) return -1;
    
    EnterCriticalSection(&g_cluster.lock);
    
    for (int i = 0; i < g_cluster.node_count; i++) {
        if (strcmp(g_cluster.nodes[i].id, node_id) == 0) {
            *out = g_cluster.nodes[i];
            LeaveCriticalSection(&g_cluster.lock);
            return 0;
        }
    }
    
    LeaveCriticalSection(&g_cluster.lock);
    return -1;
}

int RemoteCluster_GetAllNodes(RemoteNodeInfo* out, int max_nodes, int* out_count) {
    if (!out || !out_count) return -1;
    
    EnterCriticalSection(&g_cluster.lock);
    
    int count = (g_cluster.node_count < max_nodes) ? g_cluster.node_count : max_nodes;
    memcpy(out, g_cluster.nodes, sizeof(RemoteNodeInfo) * count);
    *out_count = count;
    
    LeaveCriticalSection(&g_cluster.lock);
    return 0;
}

int RemoteCluster_GetHealthyNodes(RemoteNodeInfo* out, int max_nodes, int* out_count) {
    if (!out || !out_count) return -1;
    
    EnterCriticalSection(&g_cluster.lock);
    
    int count = 0;
    for (int i = 0; i < g_cluster.node_count && count < max_nodes; i++) {
        if (g_cluster.nodes[i].health_state == NODE_STATE_HEALTHY) {
            out[count++] = g_cluster.nodes[i];
        }
    }
    *out_count = count;
    
    LeaveCriticalSection(&g_cluster.lock);
    return 0;
}

//==============================================================================
// Scheduler
//==============================================================================

int RemoteCluster_SetStrategy(SchedulerStrategy strategy) {
    g_cluster.strategy = strategy;
    
    char msg[64];
    snprintf(msg, sizeof(msg), "Scheduler strategy: %s", 
             RemoteCluster_StrategyToString(strategy));
    Journal_LogUserRequest(msg, "");
    
    return 0;
}

SchedulerStrategy RemoteCluster_GetStrategy(void) {
    return g_cluster.strategy;
}

int RemoteCluster_SelectNode(const InferenceRequest* req, RemoteNodeInfo* out) {
    if (!req || !out) return -1;
    
    EnterCriticalSection(&g_cluster.lock);
    
    int best_idx = -1;
    int best_score = INT_MAX;
    
    for (int i = 0; i < g_cluster.node_count; i++) {
        RemoteNodeInfo* node = &g_cluster.nodes[i];
        
        // Skip unhealthy nodes
        if (node->health_state != NODE_STATE_HEALTHY) {
            continue;
        }
        
        // Check capability match
        if (req->required_capabilities && 
            (node->capabilities & req->required_capabilities) != req->required_capabilities) {
            continue;
        }
        
        // Check capacity
        if (node->current_load >= node->max_concurrent) {
            continue;
        }
        
        int score = 0;
        
        switch (g_cluster.strategy) {
            case SCHEDULER_ROUND_ROBIN:
                score = g_cluster.round_robin_index++ % g_cluster.node_count;
                break;
                
            case SCHEDULER_LEAST_LOADED:
                score = node->current_load;
                break;
                
            case SCHEDULER_CAPABILITY_MATCH:
                // Prefer nodes with exact capability match
                score = __builtin_popcount(node->capabilities ^ req->required_capabilities);
                break;
                
            case SCHEDULER_LATENCY_AWARE:
                score = (int)node->latency_ms;
                break;
                
            case SCHEDULER_MODEL_PINNED:
                // Prefer nodes that have the model loaded
                score = 1000;
                for (int m = 0; m < node->model_count; m++) {
                    if (strcmp(node->available_models[m], req->model_id) == 0) {
                        score = 0;
                        break;
                    }
                }
                break;
        }
        
        if (score < best_score) {
            best_score = score;
            best_idx = i;
        }
    }
    
    if (best_idx >= 0) {
        *out = g_cluster.nodes[best_idx];
        
        // Increment load
        g_cluster.nodes[best_idx].current_load++;
        
        LeaveCriticalSection(&g_cluster.lock);
        
        char msg[256];
        snprintf(msg, sizeof(msg), "Selected node %s for request", out->id);
        Journal_LogUserRequest(msg, req->model_id);
        
        return best_idx;
    }
    
    LeaveCriticalSection(&g_cluster.lock);
    return -1;
}

int RemoteCluster_SelectNodeWithModel(const char* model_id, RemoteNodeInfo* out) {
    if (!model_id || !out) return -1;
    
    EnterCriticalSection(&g_cluster.lock);
    
    for (int i = 0; i < g_cluster.node_count; i++) {
        if (g_cluster.nodes[i].health_state != NODE_STATE_HEALTHY) {
            continue;
        }
        
        for (int m = 0; m < g_cluster.nodes[i].model_count; m++) {
            if (strcmp(g_cluster.nodes[i].available_models[m], model_id) == 0) {
                *out = g_cluster.nodes[i];
                LeaveCriticalSection(&g_cluster.lock);
                return i;
            }
        }
    }
    
    LeaveCriticalSection(&g_cluster.lock);
    return -1;
}

void RemoteCluster_GetClusterLoad(int* total_capacity, int* current_load, float* utilization) {
    EnterCriticalSection(&g_cluster.lock);
    
    int capacity = 0;
    int load = 0;
    
    for (int i = 0; i < g_cluster.node_count; i++) {
        if (g_cluster.nodes[i].health_state == NODE_STATE_HEALTHY) {
            capacity += g_cluster.nodes[i].max_concurrent;
            load += g_cluster.nodes[i].current_load;
        }
    }
    
    if (total_capacity) *total_capacity = capacity;
    if (current_load) *current_load = load;
    if (utilization) *utilization = (capacity > 0) ? (float)load / capacity : 0;
    
    LeaveCriticalSection(&g_cluster.lock);
}

//==============================================================================
// Health Monitoring
//==============================================================================

void RemoteCluster_Heartbeat(void) {
    uint64_t now = GetTickCount64();
    
    EnterCriticalSection(&g_cluster.lock);
    
    for (int i = 0; i < g_cluster.node_count; i++) {
        RemoteNodeInfo* node = &g_cluster.nodes[i];
        
        // Check for timeout
        if (node->health_state == NODE_STATE_HEALTHY) {
            if (now - node->last_heartbeat_ms > g_cluster.config.timeout_ms) {
                node->health_state = NODE_STATE_DOWN;
                
                char msg[256];
                snprintf(msg, sizeof(msg), "Node %s timed out", node->id);
                Journal_LogUserRequest(msg, "");
                
                // Trigger failover if enabled
                if (g_cluster.failover_enabled) {
                    // TODO: Implement failover
                }
            }
        }
    }
    
    LeaveCriticalSection(&g_cluster.lock);
}

int RemoteCluster_PingNode(const char* node_id, uint64_t* out_latency_ms) {
    RemoteNodeInfo node;
    if (RemoteCluster_GetNode(node_id, &node) != 0) {
        return -1;
    }
    
    // Create socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return -1;
    }
    
    // Set timeout
    DWORD timeout = 5000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    
    // Connect
    sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(node.port);
    inet_pton(AF_INET, node.host, &addr.sin_addr);
    
    uint64_t start = GetTickCount64();
    
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        RemoteCluster_UpdateNodeHealth(node_id, NODE_STATE_DOWN);
        return -1;
    }
    
    uint64_t latency = GetTickCount64() - start;
    
    closesocket(sock);
    
    if (out_latency_ms) {
        *out_latency_ms = latency;
    }
    
    // Update node latency
    EnterCriticalSection(&g_cluster.lock);
    for (int i = 0; i < g_cluster.node_count; i++) {
        if (strcmp(g_cluster.nodes[i].id, node_id) == 0) {
            g_cluster.nodes[i].latency_ms = latency;
            g_cluster.nodes[i].last_heartbeat_ms = GetTickCount64();
            g_cluster.nodes[i].health_state = NODE_STATE_HEALTHY;
            break;
        }
    }
    LeaveCriticalSection(&g_cluster.lock);
    
    return 0;
}

void RemoteCluster_UpdateNodeHealth(const char* node_id, NodeState state) {
    EnterCriticalSection(&g_cluster.lock);
    
    for (int i = 0; i < g_cluster.node_count; i++) {
        if (strcmp(g_cluster.nodes[i].id, node_id) == 0) {
            NodeState old_state = g_cluster.nodes[i].health_state;
            g_cluster.nodes[i].health_state = state;
            
            if (old_state != NODE_STATE_HEALTHY && state == NODE_STATE_HEALTHY) {
                Journal_LogUserRequest("Node recovered", node_id);
            } else if (old_state == NODE_STATE_HEALTHY && state != NODE_STATE_HEALTHY) {
                Journal_LogUserRequest("Node failed", node_id);
            }
            
            break;
        }
    }
    
    LeaveCriticalSection(&g_cluster.lock);
}

DWORD WINAPI RemoteCluster_HealthCheckThread(LPVOID param) {
    (void)param;
    
    while (g_cluster.health_thread_running) {
        // Ping all nodes
        for (int i = 0; i < g_cluster.node_count; i++) {
            RemoteCluster_PingNode(g_cluster.nodes[i].id, NULL);
        }
        
        // Run heartbeat check
        RemoteCluster_Heartbeat();
        
        Sleep(g_cluster.config.heartbeat_interval_ms);
    }
    
    return 0;
}

int RemoteCluster_StartHealthMonitor(void) {
    if (g_cluster.health_thread_running) {
        return 0;
    }
    
    g_cluster.health_thread_running = 1;
    g_cluster.health_thread = CreateThread(NULL, 0, 
                                           RemoteCluster_HealthCheckThread, 
                                           NULL, 0, NULL);
    
    return (g_cluster.health_thread != NULL) ? 0 : -1;
}

int RemoteCluster_StopHealthMonitor(void) {
    if (!g_cluster.health_thread_running) {
        return 0;
    }
    
    g_cluster.health_thread_running = 0;
    
    if (g_cluster.health_thread) {
        WaitForSingleObject(g_cluster.health_thread, 5000);
        CloseHandle(g_cluster.health_thread);
        g_cluster.health_thread = NULL;
    }
    
    return 0;
}

//==============================================================================
// Metrics
//==============================================================================

void RemoteCluster_ReportNodeMetrics(const char* node_id, 
                                      float tokens_per_sec,
                                      uint64_t memory_used_mb) {
    EnterCriticalSection(&g_cluster.lock);
    
    for (int i = 0; i < g_cluster.node_count; i++) {
        if (strcmp(g_cluster.nodes[i].id, node_id) == 0) {
            g_cluster.nodes[i].tokens_per_second = tokens_per_sec;
            g_cluster.nodes[i].memory_available_mb = 
                g_cluster.nodes[i].memory_total_mb - memory_used_mb;
            break;
        }
    }
    
    LeaveCriticalSection(&g_cluster.lock);
}

void RemoteCluster_GetNodeMetrics(const char* node_id, 
                                   float* out_tokens_per_sec,
                                   uint64_t* out_memory_used_mb) {
    EnterCriticalSection(&g_cluster.lock);
    
    for (int i = 0; i < g_cluster.node_count; i++) {
        if (strcmp(g_cluster.nodes[i].id, node_id) == 0) {
            if (out_tokens_per_sec) {
                *out_tokens_per_sec = g_cluster.nodes[i].tokens_per_second;
            }
            if (out_memory_used_mb) {
                *out_memory_used_mb = g_cluster.nodes[i].memory_total_mb - 
                                      g_cluster.nodes[i].memory_available_mb;
            }
            break;
        }
    }
    
    LeaveCriticalSection(&g_cluster.lock);
}

//==============================================================================
// Failover
//==============================================================================

int RemoteCluster_EnableFailover(int enable) {
    g_cluster.failover_enabled = enable;
    return 0;
}

int RemoteCluster_IsFailoverEnabled(void) {
    return g_cluster.failover_enabled;
}

int RemoteCluster_GetFailoverNode(const char* failed_node_id, RemoteNodeInfo* out) {
    if (!failed_node_id || !out) return -1;
    
    // Find a healthy node with similar capabilities
    RemoteNodeInfo failed;
    if (RemoteCluster_GetNode(failed_node_id, &failed) != 0) {
        return -1;
    }
    
    EnterCriticalSection(&g_cluster.lock);
    
    for (int i = 0; i < g_cluster.node_count; i++) {
        if (g_cluster.nodes[i].health_state == NODE_STATE_HEALTHY &&
            strcmp(g_cluster.nodes[i].id, failed_node_id) != 0) {
            // Check capability match
            if ((g_cluster.nodes[i].capabilities & failed.capabilities) == failed.capabilities) {
                *out = g_cluster.nodes[i];
                LeaveCriticalSection(&g_cluster.lock);
                
                Journal_LogUserRequest("Failover node selected", out->id);
                return i;
            }
        }
    }
    
    LeaveCriticalSection(&g_cluster.lock);
    return -1;
}

//==============================================================================
// Utility
//==============================================================================

const char* RemoteCluster_StrategyToString(SchedulerStrategy s) {
    switch (s) {
        case SCHEDULER_ROUND_ROBIN: return "round_robin";
        case SCHEDULER_LEAST_LOADED: return "least_loaded";
        case SCHEDULER_CAPABILITY_MATCH: return "capability_match";
        case SCHEDULER_LATENCY_AWARE: return "latency_aware";
        case SCHEDULER_MODEL_PINNED: return "model_pinned";
        default: return "unknown";
    }
}

SchedulerStrategy RemoteCluster_StringToStrategy(const char* str) {
    if (!str) return SCHEDULER_LEAST_LOADED;
    
    if (_stricmp(str, "round_robin") == 0) return SCHEDULER_ROUND_ROBIN;
    if (_stricmp(str, "least_loaded") == 0) return SCHEDULER_LEAST_LOADED;
    if (_stricmp(str, "capability_match") == 0) return SCHEDULER_CAPABILITY_MATCH;
    if (_stricmp(str, "latency_aware") == 0) return SCHEDULER_LATENCY_AWARE;
    if (_stricmp(str, "model_pinned") == 0) return SCHEDULER_MODEL_PINNED;
    
    return SCHEDULER_LEAST_LOADED;
}

const char* RemoteCluster_NodeStateToString(NodeState state) {
    switch (state) {
        case NODE_STATE_UNKNOWN: return "unknown";
        case NODE_STATE_HEALTHY: return "healthy";
        case NODE_STATE_DEGRADED: return "degraded";
        case NODE_STATE_DOWN: return "down";
        case NODE_STATE_MAINTENANCE: return "maintenance";
        default: return "unknown";
    }
}

void RemoteCluster_FormatNodeInfo(const RemoteNodeInfo* node, char* out, size_t out_size) {
    if (!node || !out || out_size == 0) return;
    
    snprintf(out, out_size,
             "[%s] %s:%d | %s | Load: %d/%d | TPS: %.1f | Mem: %llu/%llu MB",
             node->id,
             node->host,
             node->port,
             RemoteCluster_NodeStateToString(node->health_state),
             node->current_load,
             node->max_concurrent,
             node->tokens_per_second,
             node->memory_available_mb,
             node->memory_total_mb);
}
