//==============================================================================
// SovereignSubsystemRegistry.cpp
// Implementation of unified subsystem registry
//
// This is the central hub that binds all sovereign subsystems together
// without merging source code - only interfaces
//==============================================================================

#include "SovereignSubsystemRegistry.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

//==============================================================================
// Internal State
//==============================================================================

#define MAX_SUBSYSTEMS 64

static SovereignSubsystem* g_registry[MAX_SUBSYSTEMS];
static int g_subsystem_count = 0;
static int g_initialized = 0;

//==============================================================================
// Helper Functions
//==============================================================================

static int FindSubsystemIndex(const char* name) {
    for (int i = 0; i < g_subsystem_count; i++) {
        if (g_registry[i] && strcmp(g_registry[i]->name, name) == 0) {
            return i;
        }
    }
    return -1;
}

static const char* StateToString(SovereignSubsystemState state) {
    switch (state) {
        case STATE_UNINITIALIZED: return "UNINITIALIZED";
        case STATE_INITIALIZING: return "INITIALIZING";
        case STATE_READY: return "READY";
        case STATE_BUSY: return "BUSY";
        case STATE_ERROR: return "ERROR";
        case STATE_SHUTDOWN: return "SHUTDOWN";
        default: return "UNKNOWN";
    }
}

static const char* TypeToString(SovereignSubsystemType type) {
    switch (type) {
        case SUBSYSTEM_KERNEL: return "KERNEL";
        case SUBSYSTEM_ROSLYN: return "ROSLYN";
        case SUBSYSTEM_JAVA: return "JAVA";
        case SUBSYSTEM_CODEXPRO: return "CODEXPRO";
        case SUBSYSTEM_SUNSHINEFPS: return "SUNSHINEFPS";
        case SUBSYSTEM_TITAN: return "TITAN";
        case SUBSYSTEM_VULKAN: return "VULKAN";
        case SUBSYSTEM_MEMORYBRIDGE: return "MEMORYBRIDGE";
        case SUBSYSTEM_AUDIT: return "AUDIT";
        case SUBSYSTEM_CLI: return "CLI";
        case SUBSYSTEM_GUI: return "GUI";
        default: return "UNKNOWN";
    }
}

//==============================================================================
// Registry Functions
//==============================================================================

int Sovereign_InitRegistry(void) {
    if (g_initialized) {
        return 0; // Already initialized
    }
    
    g_subsystem_count = 0;
    for (int i = 0; i < MAX_SUBSYSTEMS; i++) {
        g_registry[i] = nullptr;
    }
    
    g_initialized = 1;
    return 0;
}

int Sovereign_ShutdownRegistry(void) {
    if (!g_initialized) {
        return 0;
    }
    
    // Shutdown all subsystems
    for (int i = 0; i < g_subsystem_count; i++) {
        if (g_registry[i] && g_registry[i]->shutdown) {
            g_registry[i]->shutdown();
            g_registry[i]->state = STATE_SHUTDOWN;
        }
    }
    
    g_subsystem_count = 0;
    g_initialized = 0;
    return 0;
}

int Sovereign_RegisterSubsystem(SovereignSubsystem* subsystem) {
    if (!g_initialized) {
        return -1;
    }
    
    if (!subsystem || !subsystem->name) {
        return -2;
    }
    
    if (g_subsystem_count >= MAX_SUBSYSTEMS) {
        return -3; // Registry full
    }
    
    // Check if already registered
    if (FindSubsystemIndex(subsystem->name) >= 0) {
        return -4; // Already exists
    }
    
    // Initialize subsystem if init function exists
    if (subsystem->init) {
        subsystem->state = STATE_INITIALIZING;
        int result = subsystem->init();
        if (result != 0) {
            subsystem->state = STATE_ERROR;
            return -5; // Init failed
        }
    }
    
    subsystem->state = STATE_READY;
    g_registry[g_subsystem_count++] = subsystem;
    
    return 0;
}

int Sovereign_UnregisterSubsystem(const char* name) {
    if (!g_initialized || !name) {
        return -1;
    }
    
    int index = FindSubsystemIndex(name);
    if (index < 0) {
        return -2; // Not found
    }
    
    // Shutdown subsystem
    if (g_registry[index] && g_registry[index]->shutdown) {
        g_registry[index]->shutdown();
        g_registry[index]->state = STATE_SHUTDOWN;
    }
    
    // Remove from registry (shift remaining)
    for (int i = index; i < g_subsystem_count - 1; i++) {
        g_registry[i] = g_registry[i + 1];
    }
    g_registry[--g_subsystem_count] = nullptr;
    
    return 0;
}

SovereignSubsystem* Sovereign_FindSubsystem(const char* name) {
    if (!g_initialized || !name) {
        return nullptr;
    }
    
    int index = FindSubsystemIndex(name);
    if (index >= 0) {
        return g_registry[index];
    }
    
    return nullptr;
}

SovereignSubsystem* Sovereign_FindSubsystemByType(SovereignSubsystemType type) {
    if (!g_initialized) {
        return nullptr;
    }
    
    for (int i = 0; i < g_subsystem_count; i++) {
        if (g_registry[i] && g_registry[i]->type == type) {
            return g_registry[i];
        }
    }
    
    return nullptr;
}

int Sovereign_Dispatch(const char* subsystem_name, int argc, char** argv,
                       char* output, size_t output_size) {
    if (!g_initialized || !subsystem_name) {
        if (output && output_size > 0) {
            snprintf(output, output_size, "ERROR: Registry not initialized");
        }
        return -1;
    }
    
    SovereignSubsystem* sub = Sovereign_FindSubsystem(subsystem_name);
    if (!sub) {
        if (output && output_size > 0) {
            snprintf(output, output_size, "ERROR: Subsystem '%s' not found", subsystem_name);
        }
        return -2;
    }
    
    if (sub->state != STATE_READY) {
        if (output && output_size > 0) {
            snprintf(output, output_size, "ERROR: Subsystem '%s' not ready (state: %s)",
                     subsystem_name, StateToString(sub->state));
        }
        return -3;
    }
    
    if (!sub->handler) {
        if (output && output_size > 0) {
            snprintf(output, output_size, "ERROR: Subsystem '%s' has no handler", subsystem_name);
        }
        return -4;
    }
    
    sub->state = STATE_BUSY;
    int result = sub->handler(argc, argv, output, output_size);
    sub->state = STATE_READY;
    
    return result;
}

int Sovereign_DispatchByType(SovereignSubsystemType type, int argc, char** argv,
                              char* output, size_t output_size) {
    SovereignSubsystem* sub = Sovereign_FindSubsystemByType(type);
    if (!sub) {
        if (output && output_size > 0) {
            snprintf(output, output_size, "ERROR: No subsystem of type %d found", type);
        }
        return -1;
    }
    
    return Sovereign_Dispatch(sub->name, argc, argv, output, output_size);
}

int Sovereign_GetAllSubsystems(SovereignSubsystem** subsystems, int* count) {
    if (!g_initialized || !subsystems || !count) {
        return -1;
    }
    
    *count = g_subsystem_count;
    for (int i = 0; i < g_subsystem_count; i++) {
        subsystems[i] = g_registry[i];
    }
    
    return 0;
}

int Sovereign_GetSubsystemsByCap(uint32_t capabilities, SovereignSubsystem** subsystems,
                                   int* count) {
    if (!g_initialized || !subsystems || !count) {
        return -1;
    }
    
    int found = 0;
    for (int i = 0; i < g_subsystem_count && found < MAX_SUBSYSTEMS; i++) {
        if (g_registry[i] && (g_registry[i]->capabilities & capabilities)) {
            subsystems[found++] = g_registry[i];
        }
    }
    
    *count = found;
    return 0;
}

int Sovereign_GetRegistryStatus(char* status, size_t status_size) {
    if (!status || status_size == 0) {
        return -1;
    }
    
    int ready_count = 0;
    int error_count = 0;
    
    for (int i = 0; i < g_subsystem_count; i++) {
        if (g_registry[i]) {
            if (g_registry[i]->state == STATE_READY) ready_count++;
            if (g_registry[i]->state == STATE_ERROR) error_count++;
        }
    }
    
    snprintf(status, status_size,
             "Registry: %d/%d subsystems registered, %d ready, %d error",
             g_subsystem_count, MAX_SUBSYSTEMS, ready_count, error_count);
    
    return 0;
}

int Sovereign_GetSubsystemCount(void) {
    return g_initialized ? g_subsystem_count : 0;
}

int Sovereign_GetReadySubsystemCount(void) {
    if (!g_initialized) return 0;
    
    int count = 0;
    for (int i = 0; i < g_subsystem_count; i++) {
        if (g_registry[i] && g_registry[i]->state == STATE_READY) {
            count++;
        }
    }
    return count;
}

//==============================================================================
// Command Router
//==============================================================================

int Sovereign_RouteCommand(const char* command_line, char* output, size_t output_size) {
    if (!command_line || !output || output_size == 0) {
        return -1;
    }
    
    // Parse command line
    // Format: "subsystem command args..."
    char* line = _strdup(command_line);
    char* saveptr = NULL;
    char* subsystem_name = strtok_s(line, " ", &saveptr);
    
    if (!subsystem_name) {
        free(line);
        snprintf(output, output_size, "ERROR: Empty command line");
        return -2;
    }
    
    // Build argc/argv
    char* argv[64];
    int argc = 0;
    argv[argc++] = subsystem_name;
    
    char* token;
    char* token_saveptr = NULL;
    while ((token = strtok_s(NULL, " ", &saveptr)) != NULL && argc < 64) {
        argv[argc++] = token;
    }
    
    int result = Sovereign_Dispatch(subsystem_name, argc, argv, output, output_size);
    
    free(line);
    return result;
}

int Sovereign_AutoRoute(int argc, char** argv, char* output, size_t output_size) {
    if (argc < 1 || !argv || !output || output_size == 0) {
        return -1;
    }
    
    // First argument is the command
    // Try to detect subsystem from command
    const char* cmd = argv[0];
    const char* subsystem_name = nullptr;
    
    // Map commands to subsystems
    if (strcmp(cmd, "status") == 0 || strcmp(cmd, "benchmark") == 0 ||
        strcmp(cmd, "profile") == 0 || strcmp(cmd, "stress") == 0 ||
        strcmp(cmd, "validate") == 0 || strcmp(cmd, "compare") == 0 ||
        strcmp(cmd, "run") == 0 || strcmp(cmd, "measure") == 0) {
        subsystem_name = SUBSYSTEM_NAME_KERNEL;
    }
    else if (strcmp(cmd, "audit") == 0 || strcmp(cmd, "todo") == 0) {
        subsystem_name = SUBSYSTEM_NAME_AUDIT;
    }
    else if (strcmp(cmd, "roslyn") == 0 || strcmp(cmd, "compile") == 0) {
        subsystem_name = SUBSYSTEM_NAME_ROSLYN;
    }
    else if (strcmp(cmd, "java") == 0 || strcmp(cmd, "jvm") == 0) {
        subsystem_name = SUBSYSTEM_NAME_JAVA;
    }
    else if (strcmp(cmd, "codexpro") == 0 || strcmp(cmd, "reverse") == 0 ||
             strcmp(cmd, "analyze") == 0) {
        subsystem_name = SUBSYSTEM_NAME_CODEXPRO;
    }
    else if (strcmp(cmd, "sunshine") == 0 || strcmp(cmd, "game") == 0) {
        subsystem_name = SUBSYSTEM_NAME_SUNSHINE;
    }
    else if (strcmp(cmd, "titan") == 0 || strcmp(cmd, "dma") == 0) {
        subsystem_name = SUBSYSTEM_NAME_TITAN;
    }
    else if (strcmp(cmd, "vulkan") == 0 || strcmp(cmd, "gpu") == 0) {
        subsystem_name = SUBSYSTEM_NAME_VULKAN;
    }
    else if (strcmp(cmd, "memorybridge") == 0 || strcmp(cmd, "memory") == 0) {
        subsystem_name = SUBSYSTEM_NAME_MEMORYBRIDGE;
    }
    else if (strcmp(cmd, "cli") == 0 || strcmp(cmd, "command") == 0) {
        subsystem_name = SUBSYSTEM_NAME_CLI;
    }
    else if (strcmp(cmd, "gui") == 0 || strcmp(cmd, "ui") == 0) {
        subsystem_name = SUBSYSTEM_NAME_GUI;
    }
    
    if (!subsystem_name) {
        snprintf(output, output_size, "ERROR: Cannot determine subsystem for command '%s'", cmd);
        return -2;
    }
    
    return Sovereign_Dispatch(subsystem_name, argc, argv, output, output_size);
}
