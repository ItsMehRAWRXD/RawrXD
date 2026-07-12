//==============================================================================
// ModelRegistry.cpp - Phase 14: Multi-Model Registry Implementation
//==============================================================================

#include "ModelRegistry.h"
#include "ExecutionJournal.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cjson/cJSON.h>

//==============================================================================
// Internal State
//==============================================================================

typedef struct RegistryState {
    ModelInfo models[MAX_MODELS];
    int model_count;
    char registry_path[MAX_PATH_LEN];
    char active_model_id[64];
    int is_initialized;
} RegistryState;

static RegistryState g_registry = {0};

//==============================================================================
// Utility Functions
//==============================================================================

static uint64_t GetTimestampMs() {
    return GetTickCount64();
}

static int FindModelIndex(const char* model_id) {
    if (!model_id) return -1;
    for (int i = 0; i < g_registry.model_count; i++) {
        if (strcmp(g_registry.models[i].id, model_id) == 0) {
            return i;
        }
    }
    return -1;
}

static int FindModelByName(const char* name) {
    if (!name) return -1;
    for (int i = 0; i < g_registry.model_count; i++) {
        if (strstr(g_registry.models[i].name, name) != NULL ||
            strcmp(g_registry.models[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

//==============================================================================
// Initialization
//==============================================================================

int ModelRegistry_Init(const char* registry_path) {
    if (g_registry.is_initialized) {
        return 0;
    }
    
    memset(&g_registry, 0, sizeof(g_registry));
    
    if (registry_path) {
        strncpy(g_registry.registry_path, registry_path, sizeof(g_registry.registry_path) - 1);
    } else {
        strcpy(g_registry.registry_path, "models/registry.json");
    }
    
    // Try to load existing registry
    ModelRegistry_LoadFromJSON(g_registry.registry_path);
    
    g_registry.is_initialized = 1;
    
    printf("[ModelRegistry] Initialized with %d models\n", g_registry.model_count);
    
    // Log to journal
    Journal_LogUserRequest("ModelRegistry initialized", g_registry.registry_path);
    
    return 0;
}

int ModelRegistry_Shutdown(void) {
    if (!g_registry.is_initialized) {
        return 0;
    }
    
    // Save registry
    ModelRegistry_SaveToJSON(g_registry.registry_path);
    
    g_registry.is_initialized = 0;
    printf("[ModelRegistry] Shutdown complete\n");
    
    return 0;
}

//==============================================================================
// JSON Persistence
//==============================================================================

int ModelRegistry_LoadFromJSON(const char* json_path) {
    FILE* f = fopen(json_path, "r");
    if (!f) {
        printf("[ModelRegistry] No existing registry at %s, starting fresh\n", json_path);
        return 0;
    }
    
    // Read file
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* buffer = (char*)malloc(size + 1);
    fread(buffer, 1, size, f);
    buffer[size] = '\0';
    fclose(f);
    
    // Parse JSON
    cJSON* root = cJSON_Parse(buffer);
    free(buffer);
    
    if (!root) {
        fprintf(stderr, "[ModelRegistry] Failed to parse JSON\n");
        return -1;
    }
    
    cJSON* models_array = cJSON_GetObjectItem(root, "models");
    if (!models_array || !cJSON_IsArray(models_array)) {
        cJSON_Delete(root);
        return -1;
    }
    
    // Load models
    int count = cJSON_GetArraySize(models_array);
    for (int i = 0; i < count && i < MAX_MODELS; i++) {
        cJSON* model_json = cJSON_GetArrayItem(models_array, i);
        ModelInfo* model = &g_registry.models[g_registry.model_count];
        
        cJSON* item = cJSON_GetObjectItem(model_json, "id");
        if (item) strncpy(model->id, item->valuestring, sizeof(model->id) - 1);
        
        item = cJSON_GetObjectItem(model_json, "name");
        if (item) strncpy(model->name, item->valuestring, sizeof(model->name) - 1);
        
        item = cJSON_GetObjectItem(model_json, "path");
        if (item) strncpy(model->path, item->valuestring, sizeof(model->path) - 1);
        
        item = cJSON_GetObjectItem(model_json, "backend_type");
        if (item) strncpy(model->backend_type, item->valuestring, sizeof(model->backend_type) - 1);
        
        item = cJSON_GetObjectItem(model_json, "is_local");
        if (item) model->is_local = cJSON_IsTrue(item);
        
        item = cJSON_GetObjectItem(model_json, "parameter_count");
        if (item) model->parameter_count = (size_t)item->valuedouble;
        
        item = cJSON_GetObjectItem(model_json, "context_window");
        if (item) model->context_window = item->valueint;
        
        item = cJSON_GetObjectItem(model_json, "capabilities");
        if (item) model->capabilities = (unsigned int)item->valuedouble;
        
        item = cJSON_GetObjectItem(model_json, "is_default");
        if (item) model->is_default = cJSON_IsTrue(item);
        
        g_registry.model_count++;
    }
    
    cJSON_Delete(root);
    printf("[ModelRegistry] Loaded %d models from %s\n", g_registry.model_count, json_path);
    
    return 0;
}

int ModelRegistry_SaveToJSON(const char* json_path) {
    cJSON* root = cJSON_CreateObject();
    cJSON* models_array = cJSON_CreateArray();
    
    for (int i = 0; i < g_registry.model_count; i++) {
        ModelInfo* model = &g_registry.models[i];
        cJSON* model_json = cJSON_CreateObject();
        
        cJSON_AddStringToObject(model_json, "id", model->id);
        cJSON_AddStringToObject(model_json, "name", model->name);
        cJSON_AddStringToObject(model_json, "path", model->path);
        cJSON_AddStringToObject(model_json, "backend_type", model->backend_type);
        cJSON_AddBoolToObject(model_json, "is_local", model->is_local);
        cJSON_AddNumberToObject(model_json, "parameter_count", (double)model->parameter_count);
        cJSON_AddNumberToObject(model_json, "context_window", model->context_window);
        cJSON_AddNumberToObject(model_json, "capabilities", model->capabilities);
        cJSON_AddBoolToObject(model_json, "is_default", model->is_default);
        cJSON_AddNumberToObject(model_json, "tokens_per_second", model->tokens_per_second);
        cJSON_AddNumberToObject(model_json, "memory_required_mb", (double)model->memory_required_mb);
        
        cJSON_AddItemToArray(models_array, model_json);
    }
    
    cJSON_AddItemToObject(root, "models", models_array);
    cJSON_AddStringToObject(root, "version", MODEL_REGISTRY_VERSION);
    
    char* json_str = cJSON_Print(root);
    
    FILE* f = fopen(json_path, "w");
    if (f) {
        fprintf(f, "%s", json_str);
        fclose(f);
    }
    
    free(json_str);
    cJSON_Delete(root);
    
    return 0;
}

//==============================================================================
// Model Management
//==============================================================================

int ModelRegistry_AddModel(const ModelInfo* model) {
    if (!model || g_registry.model_count >= MAX_MODELS) {
        return -1;
    }
    
    // Check for duplicate ID
    if (FindModelIndex(model->id) >= 0) {
        fprintf(stderr, "[ModelRegistry] Model %s already exists\n", model->id);
        return -1;
    }
    
    memcpy(&g_registry.models[g_registry.model_count], model, sizeof(ModelInfo));
    g_registry.model_count++;
    
    printf("[ModelRegistry] Added model: %s (%s)\n", model->name, model->id);
    
    // Log to journal
    char desc[256];
    snprintf(desc, sizeof(desc), "Added model %s", model->id);
    Journal_LogUserRequest(desc, model->path);
    
    return 0;
}

int ModelRegistry_GetModel(const char* model_id, ModelInfo* out_model) {
    int idx = FindModelIndex(model_id);
    if (idx < 0) return -1;
    
    memcpy(out_model, &g_registry.models[idx], sizeof(ModelInfo));
    return 0;
}

int ModelRegistry_GetModelByName(const char* name, ModelInfo* out_model) {
    int idx = FindModelByName(name);
    if (idx < 0) return -1;
    
    memcpy(out_model, &g_registry.models[idx], sizeof(ModelInfo));
    return 0;
}

int ModelRegistry_SetDefaultModel(const char* model_id) {
    int idx = FindModelIndex(model_id);
    if (idx < 0) return -1;
    
    // Clear previous default
    for (int i = 0; i < g_registry.model_count; i++) {
        g_registry.models[i].is_default = 0;
    }
    
    // Set new default
    g_registry.models[idx].is_default = 1;
    strncpy(g_registry.active_model_id, model_id, sizeof(g_registry.active_model_id) - 1);
    
    printf("[ModelRegistry] Default model set to: %s\n", model_id);
    
    return 0;
}

int ModelRegistry_GetDefaultModel(ModelInfo* out_model) {
    for (int i = 0; i < g_registry.model_count; i++) {
        if (g_registry.models[i].is_default) {
            memcpy(out_model, &g_registry.models[i], sizeof(ModelInfo));
            return 0;
        }
    }
    
    // Return first model if no default set
    if (g_registry.model_count > 0) {
        memcpy(out_model, &g_registry.models[0], sizeof(ModelInfo));
        return 0;
    }
    
    return -1;
}

int ModelRegistry_ListModels(ModelInfo* out_models, int max_models, int* count) {
    *count = (max_models < g_registry.model_count) ? max_models : g_registry.model_count;
    memcpy(out_models, g_registry.models, (*count) * sizeof(ModelInfo));
    return 0;
}

//==============================================================================
// Model Selection
//==============================================================================

int ModelRegistry_SelectModelForTask(
    const char* task_type,
    const char* language,
    int prefer_speed,
    int prefer_quality,
    ModelInfo* out_model
) {
    // Map task type to capabilities
    unsigned int required_caps = 0;
    if (strcmp(task_type, "code") == 0) {
        required_caps = CAP_CODE_GENERATION;
    } else if (strcmp(task_type, "fix") == 0) {
        required_caps = CAP_CODE_FIXING;
    } else if (strcmp(task_type, "optimize") == 0) {
        required_caps = CAP_OPTIMIZATION;
    } else if (strcmp(task_type, "chat") == 0) {
        required_caps = CAP_CHAT;
    } else if (strcmp(task_type, "reasoning") == 0) {
        required_caps = CAP_REASONING;
    }
    
    // Find best matching model
    int best_idx = -1;
    float best_score = -1;
    
    for (int i = 0; i < g_registry.model_count; i++) {
        ModelInfo* model = &g_registry.models[i];
        
        // Check if model has required capabilities
        if ((model->capabilities & required_caps) != required_caps) {
            continue;
        }
        
        // Calculate score
        float score = 0;
        if (prefer_speed) {
            score += model->tokens_per_second;
        }
        if (prefer_quality) {
            score += (float)model->parameter_count / 1000000000.0f;  // Billions of params
        }
        
        if (score > best_score) {
            best_score = score;
            best_idx = i;
        }
    }
    
    if (best_idx < 0) {
        // Fall back to default
        return ModelRegistry_GetDefaultModel(out_model);
    }
    
    memcpy(out_model, &g_registry.models[best_idx], sizeof(ModelInfo));
    return 0;
}

//==============================================================================
// Hot-Swap Operations
//==============================================================================

int ModelRegistry_SwitchModel(const char* model_id) {
    ModelInfo model;
    if (ModelRegistry_GetModel(model_id, &model) != 0) {
        fprintf(stderr, "[ModelRegistry] Model not found: %s\n", model_id);
        return -1;
    }
    
    // Update active model
    strncpy(g_registry.active_model_id, model_id, sizeof(g_registry.active_model_id) - 1);
    
    // Log to journal
    char desc[256];
    snprintf(desc, sizeof(desc), "Switched to model %s", model_id);
    Journal_LogUserRequest(desc, model.path);
    
    printf("[ModelRegistry] Switched to model: %s (%s)\n", model.name, model_id);
    
    return 0;
}

int ModelRegistry_GetActiveModel(ModelInfo* out_model) {
    if (g_registry.active_model_id[0]) {
        return ModelRegistry_GetModel(g_registry.active_model_id, out_model);
    }
    return ModelRegistry_GetDefaultModel(out_model);
}

//==============================================================================
// CLI Integration
//==============================================================================

int ModelRegistrySubsystem_Handler(int argc, char** argv, char* output, size_t output_size) {
    if (argc < 1) {
        snprintf(output, output_size,
            "Model Registry v%s\n"
            "Usage: models <command> [args...]\n\n"
            "Commands:\n"
            "  list                    List all models\n"
            "  info <id>               Show model details\n"
            "  set-default <id>        Set default model\n"
            "  select <task>           Select model for task\n"
            "  switch <id>             Switch active model\n",
            MODEL_REGISTRY_VERSION);
        return 0;
    }
    
    const char* cmd = argv[0];
    
    if (strcmp(cmd, "list") == 0) {
        ModelInfo models[MAX_MODELS];
        int count;
        ModelRegistry_ListModels(models, MAX_MODELS, &count);
        
        snprintf(output, output_size, "{\"models\":[");
        size_t pos = strlen(output);
        
        for (int i = 0; i < count; i++) {
            char entry[512];
            snprintf(entry, sizeof(entry),
                "%s{\"id\":\"%s\",\"name\":\"%s\",\"default\":%s,\"loaded\":%s}",
                i > 0 ? "," : "",
                models[i].id,
                models[i].name,
                models[i].is_default ? "true" : "false",
                models[i].is_loaded ? "true" : "false");
            
            size_t entry_len = strlen(entry);
            if (pos + entry_len < output_size - 2) {
                strcpy(output + pos, entry);
                pos += entry_len;
            }
        }
        
        strcat(output, "]}");
        return 0;
    }
    else if (strcmp(cmd, "info") == 0) {
        if (argc < 2) {
            snprintf(output, output_size, "{\"error\":\"Usage: models info <id>\"}");
            return -1;
        }
        
        ModelInfo model;
        if (ModelRegistry_GetModel(argv[1], &model) == 0) {
            snprintf(output, output_size,
                "{\"id\":\"%s\",\"name\":\"%s\",\"path\":\"%s\","
                "\"parameters\":%llu,\"context\":%d,\"capabilities\":%u}",
                model.id, model.name, model.path,
                model.parameter_count, model.context_window, model.capabilities);
            return 0;
        } else {
            snprintf(output, output_size, "{\"error\":\"Model not found: %s\"}", argv[1]);
            return -1;
        }
    }
    else if (strcmp(cmd, "set-default") == 0) {
        if (argc < 2) {
            snprintf(output, output_size, "{\"error\":\"Usage: models set-default <id>\"}");
            return -1;
        }
        
        if (ModelRegistry_SetDefaultModel(argv[1]) == 0) {
            snprintf(output, output_size, "{\"success\":true,\"default\":\"%s\"}", argv[1]);
            return 0;
        } else {
            snprintf(output, output_size, "{\"error\":\"Failed to set default\"}");
            return -1;
        }
    }
    else if (strcmp(cmd, "switch") == 0) {
        if (argc < 2) {
            snprintf(output, output_size, "{\"error\":\"Usage: models switch <id>\"}");
            return -1;
        }
        
        if (ModelRegistry_SwitchModel(argv[1]) == 0) {
            snprintf(output, output_size, "{\"success\":true,\"active\":\"%s\"}", argv[1]);
            return 0;
        } else {
            snprintf(output, output_size, "{\"error\":\"Failed to switch model\"}");
            return -1;
        }
    }
    
    snprintf(output, output_size, "{\"error\":\"Unknown command: %s\"}", cmd);
    return -1;
}

int ModelRegistrySubsystem_Init(void) {
    return ModelRegistry_Init(nullptr);
}

int ModelRegistrySubsystem_Shutdown(void) {
    return ModelRegistry_Shutdown();
}
