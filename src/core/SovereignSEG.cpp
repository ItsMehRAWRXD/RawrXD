//==============================================================================
// SovereignSEG.cpp - Phase 11: Sovereign Execution Graph Implementation
//
// Graph-based orchestration engine for the Sovereign Runtime.
// Executes multi-node workflows with dependency resolution.
//==============================================================================

#include "SovereignSEG.h"
#include "SovereignSubsystemRegistry.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <windows.h>

//==============================================================================
// Internal State
//==============================================================================

static int g_seg_initialized = 0;
static uint64_t g_seg_start_time = 0;

//==============================================================================
// Timing Utilities
//==============================================================================

static uint64_t GetCurrentTimeMs() {
    return GetTickCount64();
}

//==============================================================================
// Initialization
//==============================================================================

int Seg_Init(void) {
    if (g_seg_initialized) {
        return 0;
    }
    
    g_seg_start_time = GetCurrentTimeMs();
    g_seg_initialized = 1;
    
    return 0;
}

int Seg_Shutdown(void) {
    g_seg_initialized = 0;
    return 0;
}

//==============================================================================
// String Utilities
//==============================================================================

const char* Seg_NodeTypeToString(SegNodeType type) {
    switch (type) {
        case SEG_NODE_CPU: return "cpu";
        case SEG_NODE_GPU: return "gpu";
        case SEG_NODE_LANGUAGE: return "language";
        case SEG_NODE_AGENT: return "agent";
        case SEG_NODE_AUDIT: return "audit";
        case SEG_NODE_IO: return "io";
        case SEG_NODE_CUSTOM: return "custom";
        default: return "unknown";
    }
}

const char* Seg_NodeStateToString(SegNodeState state) {
    switch (state) {
        case SEG_STATE_PENDING: return "pending";
        case SEG_STATE_RUNNING: return "running";
        case SEG_STATE_COMPLETED: return "completed";
        case SEG_STATE_FAILED: return "failed";
        case SEG_STATE_SKIPPED: return "skipped";
        default: return "unknown";
    }
}

SegNodeType Seg_StringToNodeType(const char* str) {
    if (strcmp(str, "cpu") == 0) return SEG_NODE_CPU;
    if (strcmp(str, "gpu") == 0) return SEG_NODE_GPU;
    if (strcmp(str, "language") == 0) return SEG_NODE_LANGUAGE;
    if (strcmp(str, "agent") == 0) return SEG_NODE_AGENT;
    if (strcmp(str, "audit") == 0) return SEG_NODE_AUDIT;
    if (strcmp(str, "io") == 0) return SEG_NODE_IO;
    if (strcmp(str, "custom") == 0) return SEG_NODE_CUSTOM;
    return SEG_NODE_CUSTOM;
}

//==============================================================================
// Workflow I/O
//==============================================================================

// Simple JSON parser for workflow files
// In production, use a proper JSON library

static const char* FindJsonValue(const char* json, const char* key, char* buffer, size_t buffer_size) {
    char search_key[256];
    snprintf(search_key, sizeof(search_key), "\"%s\"", key);
    
    const char* pos = strstr(json, search_key);
    if (!pos) return NULL;
    
    pos = strchr(pos, ':');
    if (!pos) return NULL;
    pos++;
    
    // Skip whitespace
    while (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r') pos++;
    
    // Handle string values
    if (*pos == '"') {
        pos++;
        const char* end = strchr(pos, '"');
        if (!end) return NULL;
        
        size_t len = end - pos;
        if (len >= buffer_size) len = buffer_size - 1;
        strncpy(buffer, pos, len);
        buffer[len] = '\0';
        return buffer;
    }
    
    // Handle number values
    const char* end = pos;
    while (*end && *end != ',' && *end != '}' && *end != ']') end++;
    
    size_t len = end - pos;
    if (len >= buffer_size) len = buffer_size - 1;
    strncpy(buffer, pos, len);
    buffer[len] = '\0';
    
    return buffer;
}

static int ParseIntArray(const char* json, const char* key, int* out_array, int max_count) {
    char search_key[256];
    snprintf(search_key, sizeof(search_key), "\"%s\"", key);
    
    const char* pos = strstr(json, search_key);
    if (!pos) return 0;
    
    pos = strchr(pos, '[');
    if (!pos) return 0;
    pos++;
    
    int count = 0;
    while (*pos && *pos != ']' && count < max_count) {
        // Skip whitespace
        while (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r') pos++;
        
        // Parse number
        if (*pos >= '0' && *pos <= '9') {
            out_array[count++] = atoi(pos);
        }
        
        // Find next number or end
        while (*pos && *pos != ',' && *pos != ']') pos++;
        if (*pos == ',') pos++;
    }
    
    return count;
}

int Seg_LoadWorkflow(const char* path, SegWorkflow* out_workflow) {
    if (!out_workflow) return -1;
    
    // Read file
    FILE* file = fopen(path, "r");
    if (!file) return -2;
    
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char* json = (char*)malloc(size + 1);
    if (!json) {
        fclose(file);
        return -3;
    }
    
    fread(json, 1, size, file);
    json[size] = '\0';
    fclose(file);
    
    // Initialize workflow
    memset(out_workflow, 0, sizeof(SegWorkflow));
    
    // Parse workflow metadata
    char buffer[1024];
    if (FindJsonValue(json, "workflow", buffer, sizeof(buffer))) {
        out_workflow->name = _strdup(buffer);
    }
    if (FindJsonValue(json, "description", buffer, sizeof(buffer))) {
        out_workflow->description = _strdup(buffer);
    }
    
    // Parse nodes array
    const char* nodes_start = strstr(json, "\"nodes\"");
    if (nodes_start) {
        nodes_start = strchr(nodes_start, '[');
        if (nodes_start) {
            nodes_start++;
            
            int node_count = 0;
            const char* node_start = nodes_start;
            
            while (*node_start && node_count < SEG_MAX_NODES) {
                // Find next node object
                node_start = strstr(node_start, "{");
                if (!node_start) break;
                
                const char* node_end = strstr(node_start, "}");
                if (!node_end) break;
                
                // Extract node JSON
                size_t node_len = node_end - node_start + 1;
                char* node_json = (char*)malloc(node_len + 1);
                strncpy(node_json, node_start, node_len);
                node_json[node_len] = '\0';
                
                // Parse node fields
                SegNode* node = &out_workflow->nodes[node_count];
                memset(node, 0, sizeof(SegNode));
                
                if (FindJsonValue(node_json, "id", buffer, sizeof(buffer))) {
                    node->id = atoi(buffer);
                }
                if (FindJsonValue(node_json, "type", buffer, sizeof(buffer))) {
                    node->type = Seg_StringToNodeType(buffer);
                }
                if (FindJsonValue(node_json, "name", buffer, sizeof(buffer))) {
                    node->name = _strdup(buffer);
                }
                if (FindJsonValue(node_json, "subsystem", buffer, sizeof(buffer))) {
                    node->subsystem = _strdup(buffer);
                }
                if (FindJsonValue(node_json, "command", buffer, sizeof(buffer))) {
                    node->command = _strdup(buffer);
                }
                if (FindJsonValue(node_json, "args", buffer, sizeof(buffer))) {
                    node->args = _strdup(buffer);
                }
                
                node->depends_count = ParseIntArray(node_json, "depends_on", 
                    node->depends_on, SEG_MAX_DEPENDENCIES);
                
                node->state = SEG_STATE_PENDING;
                node_count++;
                
                free(node_json);
                node_start = node_end + 1;
            }
            
            out_workflow->node_count = node_count;
        }
    }
    
    free(json);
    return 0;
}

int Seg_SaveWorkflow(const SegWorkflow* workflow, const char* path) {
    if (!workflow || !path) return -1;
    
    FILE* file = fopen(path, "w");
    if (!file) return -2;
    
    fprintf(file, "{\n");
    fprintf(file, "  \"workflow\": \"%s\",\n", workflow->name ? workflow->name : "unnamed");
    fprintf(file, "  \"description\": \"%s\",\n", workflow->description ? workflow->description : "");
    fprintf(file, "  \"version\": %d,\n", workflow->version);
    fprintf(file, "  \"nodes\": [\n");
    
    for (int i = 0; i < workflow->node_count; i++) {
        const SegNode* node = &workflow->nodes[i];
        fprintf(file, "    {\n");
        fprintf(file, "      \"id\": %d,\n", node->id);
        fprintf(file, "      \"type\": \"%s\",\n", Seg_NodeTypeToString(node->type));
        fprintf(file, "      \"name\": \"%s\",\n", node->name ? node->name : "");
        fprintf(file, "      \"subsystem\": \"%s\",\n", node->subsystem ? node->subsystem : "");
        fprintf(file, "      \"command\": \"%s\",\n", node->command ? node->command : "");
        fprintf(file, "      \"args\": \"%s\",\n", node->args ? node->args : "");
        
        // Dependencies
        fprintf(file, "      \"depends_on\": [");
        for (int j = 0; j < node->depends_count; j++) {
            fprintf(file, "%d", node->depends_on[j]);
            if (j < node->depends_count - 1) fprintf(file, ", ");
        }
        fprintf(file, "]\n");
        
        fprintf(file, "    }");
        if (i < workflow->node_count - 1) fprintf(file, ",");
        fprintf(file, "\n");
    }
    
    fprintf(file, "  ]\n");
    fprintf(file, "}\n");
    
    fclose(file);
    return 0;
}

//==============================================================================
// Dependency Resolution
//==============================================================================

int Seg_CheckDependencies(const SegWorkflow* workflow, const SegNode* node) {
    if (!workflow || !node) return 0;
    
    for (int i = 0; i < node->depends_count; i++) {
        int dep_id = node->depends_on[i];
        SegNode* dep = Seg_GetNodeById((SegWorkflow*)workflow, dep_id);
        
        if (!dep) return 0;  // Dependency not found
        if (dep->state != SEG_STATE_COMPLETED) return 0;  // Not completed
    }
    
    return 1;  // All dependencies satisfied
}

SegNode* Seg_GetNodeById(SegWorkflow* workflow, int id) {
    if (!workflow) return NULL;
    
    for (int i = 0; i < workflow->node_count; i++) {
        if (workflow->nodes[i].id == id) {
            return &workflow->nodes[i];
        }
    }
    
    return NULL;
}

//==============================================================================
// Node Execution
//==============================================================================

int Seg_ExecuteNode(SegNode* node) {
    if (!node) return -1;
    if (!node->subsystem || !node->command) return -2;
    
    // Mark as running
    node->state = SEG_STATE_RUNNING;
    node->start_time_ms = GetCurrentTimeMs();
    
    // Build CLI command
    char cmd_line[2048];
    if (node->args && strlen(node->args) > 0) {
        snprintf(cmd_line, sizeof(cmd_line), "SovereignCLI_Unified.exe %s %s %s",
            node->subsystem, node->command, node->args);
    } else {
        snprintf(cmd_line, sizeof(cmd_line), "SovereignCLI_Unified.exe %s %s",
            node->subsystem, node->command);
    }
    
    // Execute via system call
    FILE* pipe = _popen(cmd_line, "r");
    if (!pipe) {
        node->state = SEG_STATE_FAILED;
        snprintf(node->error_message, sizeof(node->error_message), 
            "Failed to execute command");
        return -3;
    }
    
    // Capture output
    node->output[0] = '\0';
    char buffer[512];
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        strncat(node->output, buffer, SEG_MAX_OUTPUT - strlen(node->output) - 1);
    }
    node->output_len = strlen(node->output);
    
    // Get exit code
    node->exit_code = _pclose(pipe);
    node->end_time_ms = GetCurrentTimeMs();
    node->duration_ms = node->end_time_ms - node->start_time_ms;
    
    // Determine state
    if (node->exit_code == 0) {
        node->state = SEG_STATE_COMPLETED;
    } else {
        node->state = SEG_STATE_FAILED;
        snprintf(node->error_message, sizeof(node->error_message),
            "Exit code %d", node->exit_code);
    }
    
    return node->exit_code;
}

//==============================================================================
// Graph Execution
//==============================================================================

int Seg_ExecuteGraph(const SegWorkflow* workflow, SegResult* out_result) {
    if (!workflow || !out_result) return -1;
    if (!g_seg_initialized) Seg_Init();
    
    memset(out_result, 0, sizeof(SegResult));
    uint64_t workflow_start = GetCurrentTimeMs();
    
    // Execute nodes in order, respecting dependencies
    int completed_count = 0;
    int failed_count = 0;
    int skipped_count = 0;
    
    while (completed_count + failed_count + skipped_count < workflow->node_count) {
        int made_progress = 0;
        
        for (int i = 0; i < workflow->node_count; i++) {
            SegNode* node = (SegNode*)&workflow->nodes[i];
            
            // Skip already processed nodes
            if (node->state != SEG_STATE_PENDING) continue;
            
            // Check dependencies
            if (!Seg_CheckDependencies(workflow, node)) continue;
            
            // Execute node
            int result = Seg_ExecuteNode(node);
            made_progress = 1;
            
            if (node->state == SEG_STATE_COMPLETED) {
                completed_count++;
            } else if (node->state == SEG_STATE_FAILED) {
                failed_count++;
            }
        }
        
        // Check for deadlock (no progress but nodes remaining)
        if (!made_progress) {
            // Mark remaining pending nodes as skipped
            for (int i = 0; i < workflow->node_count; i++) {
                SegNode* node = (SegNode*)&workflow->nodes[i];
                if (node->state == SEG_STATE_PENDING) {
                    node->state = SEG_STATE_SKIPPED;
                    snprintf(node->error_message, sizeof(node->error_message),
                        "Dependencies not satisfied");
                    skipped_count++;
                }
            }
            break;
        }
    }
    
    // Populate result
    out_result->success_count = completed_count;
    out_result->failed_count = failed_count;
    out_result->skipped_count = skipped_count;
    out_result->total_duration_ms = GetCurrentTimeMs() - workflow_start;
    out_result->overall_success = (failed_count == 0 && skipped_count == 0) ? 1 : 0;
    
    return out_result->overall_success;
}

//==============================================================================
// Validation
//==============================================================================

int Seg_ValidateWorkflow(const SegWorkflow* workflow, char* error_buffer, size_t error_size) {
    if (!workflow) {
        snprintf(error_buffer, error_size, "Null workflow");
        return -1;
    }
    
    if (workflow->node_count <= 0) {
        snprintf(error_buffer, error_size, "Workflow has no nodes");
        return -1;
    }
    
    // Check for duplicate IDs
    for (int i = 0; i < workflow->node_count; i++) {
        for (int j = i + 1; j < workflow->node_count; j++) {
            if (workflow->nodes[i].id == workflow->nodes[j].id) {
                snprintf(error_buffer, error_size, "Duplicate node ID: %d", 
                    workflow->nodes[i].id);
                return -1;
            }
        }
    }
    
    // Check for missing dependencies
    for (int i = 0; i < workflow->node_count; i++) {
        const SegNode* node = &workflow->nodes[i];
        for (int j = 0; j < node->depends_count; j++) {
            int dep_id = node->depends_on[j];
            if (!Seg_GetNodeById((SegWorkflow*)workflow, dep_id)) {
                snprintf(error_buffer, error_size, 
                    "Node %d depends on non-existent node %d", node->id, dep_id);
                return -1;
            }
        }
    }
    
    // Check for cycles (simplified - just check direct cycles)
    for (int i = 0; i < workflow->node_count; i++) {
        const SegNode* node = &workflow->nodes[i];
        for (int j = 0; j < node->depends_count; j++) {
            int dep_id = node->depends_on[j];
            SegNode* dep = Seg_GetNodeById((SegWorkflow*)workflow, dep_id);
            if (dep) {
                for (int k = 0; k < dep->depends_count; k++) {
                    if (dep->depends_on[k] == node->id) {
                        snprintf(error_buffer, error_size,
                            "Circular dependency between nodes %d and %d", 
                            node->id, dep_id);
                        return -1;
                    }
                }
            }
        }
    }
    
    return 0;  // Valid
}

//==============================================================================
// JSON Summary
//==============================================================================

int Seg_GetSummaryJSON(const SegWorkflow* workflow, const SegResult* result,
                       char* buffer, size_t buffer_size) {
    if (!workflow || !result || !buffer) return -1;
    
    int written = snprintf(buffer, buffer_size,
        "{\n"
        "  \"workflow\": \"%s\",\n"
        "  \"summary\": {\n"
        "    \"total_nodes\": %d,\n"
        "    \"success\": %d,\n"
        "    \"failed\": %d,\n"
        "    \"skipped\": %d,\n"
        "    \"total_duration_ms\": %llu,\n"
        "    \"overall_success\": %s\n"
        "  },\n"
        "  \"nodes\": [\n",
        workflow->name ? workflow->name : "unnamed",
        workflow->node_count,
        result->success_count,
        result->failed_count,
        result->skipped_count,
        result->total_duration_ms,
        result->overall_success ? "true" : "false"
    );
    
    if (written >= (int)buffer_size) return -1;
    
    // Add node details
    for (int i = 0; i < workflow->node_count; i++) {
        const SegNode* node = &workflow->nodes[i];
        
        int node_written = snprintf(buffer + written, buffer_size - written,
            "    {\n"
            "      \"id\": %d,\n"
            "      \"name\": \"%s\",\n"
            "      \"state\": \"%s\",\n"
            "      \"duration_ms\": %llu,\n"
            "      \"exit_code\": %d%s%s\n"
            "    }%s\n",
            node->id,
            node->name ? node->name : "",
            Seg_NodeStateToString(node->state),
            node->duration_ms,
            node->exit_code,
            node->error_message[0] ? ",\n      \"error\": \"" : "",
            node->error_message[0] ? node->error_message : "",
            node->error_message[0] ? "\"" : "",
            (i < workflow->node_count - 1) ? "," : ""
        );
        
        written += node_written;
        if (written >= (int)buffer_size) return -1;
    }
    
    // Close JSON
    int close_written = snprintf(buffer + written, buffer_size - written,
        "  ]\n"
        "}\n"
    );
    
    return (written + close_written < (int)buffer_size) ? 0 : -1;
}
