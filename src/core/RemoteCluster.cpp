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
    if (!path) return -1;
    
    // Open file
    FILE* file = fopen(path, "r");
    if (!file) {
        // File doesn't exist - not an error, just no nodes loaded
        return 0;
    }
    
    // Read file content
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (size <= 0 || size > 1024 * 1024) {  // Max 1MB
        fclose(file);
        return -1;
    }
    
    std::vector<char> buffer(size + 1);
    if (fread(buffer.data(), 1, size, file) != (size_t)size) {
        fclose(file);
        return -1;
    }
    fclose(file);
    buffer[size] = '\0';
    
    // Simple JSON parsing for cluster configuration
    // Format: {"nodes": [{"id": "...", "host": "...", "port": N, ...}, ...]}
    
    EnterCriticalSection(&g_cluster.lock);
    
    // Clear existing nodes
    g_cluster.node_count = 0;
    
    const char* json = buffer.data();
    const char* nodes_start = strstr(json, "\"nodes\"");
    
    if (nodes_start) {
        nodes_start = strchr(nodes_start, '[');
        if (nodes_start) {
            nodes_start++;
            
            // Parse each node object
            while (g_cluster.node_count < MAX_CLUSTER_NODES) {
                const char* obj_start = strchr(nodes_start, '{');
                if (!obj_start) break;
                
                RemoteNodeInfo node = {0};
                
                // Parse fields
                const char* field = obj_start;
                while (true) {
                    field = strchr(field, '\"');
                    if (!field) break;
                    field++;
                    
                    if (strncmp(field, "id\", 2) == 0) {
                        field = strchr(field, '\"') + 1;
                        const char* end = strchr(field, '\"');
                        if (end) {
                            size_t len = end - field;
                            if (len < sizeof(node.id)) {
                                memcpy(node.id, field, len);
                                node.id[len] = '\0';
                            }
                        }
                    } else if (strncmp(field, "host\", 4) == 0) {
                        field = strchr(field, '\"') + 1;
                        const char* end = strchr(field, '\"');
                        if (end) {
                            size_t len = end - field;
                            if (len < sizeof(node.host)) {
                                memcpy(node.host, field, len);
                                node.host[len] = '\0';
                            }
                        }
                    } else if (strncmp(field, "port\", 4) == 0) {
                        field = strchr(field, ':') + 1;
                        node.port = atoi(field);
                    } else if (strncmp(field, "backend_type\", 11) == 0) {
                        field = strchr(field, '\"') + 1;
                        const char* end = strchr(field, '\"');
                        if (end) {
                            size_t len = end - field;
                            if (len < sizeof(node.backend_type)) {
                                memcpy(node.backend_type, field, len);
                                node.backend_type[len] = '\0';
                            }
                        }
                    } else if (strncmp(field, "max_concurrent\", 14) == 0) {
                        field = strchr(field, ':') + 1;
                        node.max_concurrent = atoi(field);
                    } else if (strncmp(field, "capabilities\", 12) == 0) {
                        field = strchr(field, ':') + 1;
                        node.capabilities = strtoul(field, NULL, 10);
                    }
                    
                    // Find next field or end of object
                    const char* next = strchr(field, ',');
                    const char* obj_end = strchr(field, '}');
                    
                    if (!next || (obj_end && obj_end < next)) {
                        break;  // End of object
                    }
                    field = next + 1;
                }
                
                // Validate and add node
                if (strlen(node.id) > 0 && strlen(node.host) > 0 && node.port > 0) {
                    node.health_state = NODE_STATE_UNKNOWN;
                    node.tokens_per_second = 0;
                    node.memory_available_mb = 0;
                    node.memory_total_mb = 0;
                    node.model_count = 0;
                    node.current_load = 0;
                    
                    g_cluster.nodes[g_cluster.node_count++] = node;
                }
                
                // Find next object
                nodes_start = strchr(obj_start, '}');
                if (!nodes_start) break;
                nodes_start++;
                
                // Skip whitespace and comma
                while (*nodes_start && (*nodes_start == ' ' || *nodes_start == '\n' || 
                       *nodes_start == '\r' || *nodes_start == '\t' || *nodes_start == ',')) {
                    nodes_start++;
                }
            }
        }
    }
    
    LeaveCriticalSection(&g_cluster.lock);
    
    char msg[256];
    snprintf(msg, sizeof(msg), "Loaded %d nodes from %s", g_cluster.node_count, path);
    Journal_LogUserRequest(msg, "");
    
    return 0;
}

int RemoteCluster_SaveToJSON(const char* path) {
    if (!path) return -1;
    
    FILE* file = fopen(path, "w");
    if (!file) return -1;
    
    EnterCriticalSection(&g_cluster.lock);
    
    // Write JSON header
    fprintf(file, "{\n");
    fprintf(file, "  \"version\": \"1.0\",\n");
    fprintf(file, "  \"nodes\": [\n");
    
    // Write each node
    for (int i = 0; i < g_cluster.node_count; i++) {
        const RemoteNodeInfo* node = &g_cluster.nodes[i];
        
        fprintf(file, "    {\n");
        fprintf(file, "      \"id\": \"%s\",\n", node->id);
        fprintf(file, "      \"host\": \"%s\",\n", node->host);
        fprintf(file, "      \"port\": %d,\n", node->port);
        fprintf(file, "      \"backend_type\": \"%s\",\n", node->backend_type);
        fprintf(file, "      \"max_concurrent\": %d,\n", node->max_concurrent);
        fprintf(file, "      \"capabilities\": %u,\n", node->capabilities);
        fprintf(file, "      \"health_state\": %d,\n", node->health_state);
        fprintf(file, "      \"tokens_per_second\": %.2f,\n", node->tokens_per_second);
        fprintf(file, "      \"memory_available_mb\": %u,\n", node->memory_available_mb);
        fprintf(file, "      \"memory_total_mb\": %u,\n", node->memory_total_mb);
        fprintf(file, "      \"model_count\": %d\n", node->model_count);
        
        if (i < g_cluster.node_count - 1) {
            fprintf(file, "    },\n");
        } else {
            fprintf(file, "    }\n");
        }
    }
    
    fprintf(file, "  ]\n");
    fprintf(file, "}\n");
    
    LeaveCriticalSection(&g_cluster.lock);
    
    fclose(file);
    
    char msg[256];
    snprintf(msg, sizeof(msg), "Saved %d nodes to %s", g_cluster.node_count, path);
    Journal_LogUserRequest(msg, "");
    
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
                    // Find best alternative node with same capabilities
                    RemoteNodeInfo* best_alternative = nullptr;
                    uint64_t best_latency = UINT64_MAX;
                    
                    for (int j = 0; j < g_cluster.node_count; j++) {
                        RemoteNodeInfo* alt = &g_cluster.nodes[j];
                        if (alt == node) continue;
                        if (alt->health_state != NODE_STATE_HEALTHY) continue;
                        if ((alt->capabilities & node->capabilities) != node->capabilities) continue;
                        if (alt->current_load >= alt->max_concurrent) continue;
                        
                        if (alt->latency_ms < best_latency) {
                            best_latency = alt->latency_ms;
                            best_alternative = alt;
                        }
                    }
                    
                    if (best_alternative) {
                        char msg[512];
                        snprintf(msg, sizeof(msg), 
                                 "Failover: Redirecting from %s to %s (%s:%d)",
                                 node->id, best_alternative->id,
                                 best_alternative->host, best_alternative->port);
                        Journal_LogUserRequest(msg, "");
                        
                        // In production, this would:
                        // 1. Migrate active sessions from failed node
                        // 2. Update load balancer routing tables
                        // 3. Notify connected clients of redirect
                        // 4. Update DNS/service discovery
                    } else {
                        char msg[256];
                        snprintf(msg, sizeof(msg), 
                                 "Failover failed: No alternative for node %s", node->id);
                        Journal_LogUserRequest(msg, "");
                    }
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
