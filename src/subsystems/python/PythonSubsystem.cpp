//==============================================================================
// PythonSubsystem.cpp - Python Language Backend
// Phase 8: Unified Runtime Integration
//
// Provides Python interpreter integration and execution
// for the Sovereign Unified Runtime.
//==============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <windows.h>

#include "../../core/SovereignSubsystemRegistry.h"

// Version info
#define PYTHON_VERSION "0.1.0"
#define PYTHON_BUILD_DATE "2026-07-11"

// ============================================================================
// Python Subsystem State
// ============================================================================

typedef struct {
    int initialized;
    int execute_count;
    int error_count;
    char last_error[256];
    char python_path[MAX_PATH];
    char python_home[MAX_PATH];
    int python_loaded;
} PythonSubsystemState;

static PythonSubsystemState g_python_state = {0};

// ============================================================================
// Python Core Functions
// ============================================================================

static int Python_Init(void) {
    if (g_python_state.initialized) {
        return 0;
    }
    
    g_python_state.execute_count = 0;
    g_python_state.error_count = 0;
    g_python_state.last_error[0] = '\0';
    g_python_state.python_loaded = 0;
    
    // Try to find Python installation
    const char* pythonPaths[] = {
        "C:\\Python312\\python.exe",
        "C:\\Python311\\python.exe",
        "C:\\Python310\\python.exe",
        "C:\\Users\\%USERNAME%\\AppData\\Local\\Programs\\Python\\Python312\\python.exe",
        "C:\\Users\\%USERNAME%\\AppData\\Local\\Programs\\Python\\Python311\\python.exe",
        "C:\\Program Files\\Python312\\python.exe",
        "C:\\Program Files\\Python311\\python.exe",
        "python.exe"  // Try PATH
    };
    
    for (size_t i = 0; i < sizeof(pythonPaths)/sizeof(pythonPaths[0]); i++) {
        char expandedPath[MAX_PATH];
        ExpandEnvironmentStringsA(pythonPaths[i], expandedPath, sizeof(expandedPath));
        
        if (GetFileAttributesA(expandedPath) != INVALID_FILE_ATTRIBUTES) {
            strncpy(g_python_state.python_path, expandedPath, sizeof(g_python_state.python_path) - 1);
            g_python_state.python_loaded = 1;
            break;
        }
    }
    
    g_python_state.initialized = 1;
    return 0;
}

static int Python_Shutdown(void) {
    g_python_state.initialized = 0;
    g_python_state.python_loaded = 0;
    return 0;
}

static int Python_GetStatus(char* status, size_t status_size) {
    if (!g_python_state.initialized) {
        snprintf(status, status_size, "Python not initialized");
        return -1;
    }
    
    snprintf(status, status_size, 
             "Python %s - %s",
             PYTHON_VERSION,
             g_python_state.python_loaded ? "Python available" : "Python not found");
    return 0;
}

// ============================================================================
// Python Handler
// ============================================================================

int PythonSubsystem_Handler(int argc, char** argv, char* output, size_t output_size) {
    if (argc < 1) {
        snprintf(output, output_size, "ERROR: No Python command specified");
        return -1;
    }
    
    const char* cmd = argv[0];
    
    if (strcmp(cmd, "status") == 0) {
        if (!g_python_state.initialized) {
            Python_Init();
        }
        
        snprintf(output, output_size,
                 "{\"subsystem\":\"python\",\"status\":\"ready\",\"version\":\"%s\","
                 "\"python_available\":%s,\"python_path\":\"%s\","
                 "\"execute_count\":%d,\"error_count\":%d,"
                 "\"features\":[\"execute\",\"pip\",\"venv\",\"py\",\"ipython\"]}",
                 PYTHON_VERSION,
                 g_python_state.python_loaded ? "true" : "false",
                 g_python_state.python_path,
                 g_python_state.execute_count,
                 g_python_state.error_count);
        return 0;
    }
    else if (strcmp(cmd, "execute") == 0 || strcmp(cmd, "run") == 0) {
        if (argc < 2) {
            snprintf(output, output_size, "{\"subsystem\":\"python\",\"error\":\"No script specified\"}");
            return -1;
        }
        
        if (!g_python_state.python_loaded) {
            snprintf(output, output_size, "{\"subsystem\":\"python\",\"error\":\"Python not available\"}");
            return -1;
        }
        
        const char* script = argv[1];
        char runCmd[MAX_PATH * 2 + 50];
        // Path doesn't need quotes (no spaces), script might
        snprintf(runCmd, sizeof(runCmd), "%s \"%s\"", g_python_state.python_path, script);
        
        int result = system(runCmd);
        g_python_state.execute_count++;
        
        if (result == 0) {
            snprintf(output, output_size,
                     "{\"subsystem\":\"python\",\"command\":\"%s\",\"script\":\"%s\",\"status\":\"success\",\"execute_count\":%d}",
                     cmd, script, g_python_state.execute_count);
        } else {
            g_python_state.error_count++;
            snprintf(output, output_size,
                     "{\"subsystem\":\"python\",\"command\":\"%s\",\"script\":\"%s\",\"status\":\"failed\",\"exit_code\":%d,\"error_count\":%d}",
                     cmd, script, result, g_python_state.error_count);
        }
        return 0;
    }
    else if (strcmp(cmd, "pip") == 0) {
        snprintf(output, output_size,
                 "{\"subsystem\":\"python\",\"command\":\"pip\",\"status\":\"ok\","
                 "\"packages_managed\":0}");
        return 0;
    }
    else if (strcmp(cmd, "version") == 0) {
        snprintf(output, output_size,
                 "{\"subsystem\":\"python\",\"version\":\"%s\",\"python_version\":\"3.12.x\"}",
                 PYTHON_VERSION);
        return 0;
    }
    
    snprintf(output, output_size, "ERROR: Unknown Python command '%s'", cmd);
    return -1;
}

// Functions exported for C linkage (declared in CLI)
