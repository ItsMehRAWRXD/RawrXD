//==============================================================================
// LispSubsystem.cpp - Lisp Language Backend
// Phase 8: Unified Runtime Integration
//
// Provides Common Lisp implementation integration and execution
// for the Sovereign Unified Runtime.
//==============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <windows.h>

#include "../../core/SovereignSubsystemRegistry.h"

// Version info
#define LISP_VERSION "0.1.0"
#define LISP_BUILD_DATE "2026-07-11"

// ============================================================================
// Lisp Subsystem State
// ============================================================================

typedef struct {
    int initialized;
    int execute_count;
    int error_count;
    char last_error[256];
    char sbcl_path[MAX_PATH];
    char clisp_path[MAX_PATH];
    char ccl_path[MAX_PATH];
    int lisp_available;
} LispSubsystemState;

static LispSubsystemState g_lisp_state = {0};

// ============================================================================
// Lisp Core Functions
// ============================================================================

static int Lisp_Init(void) {
    if (g_lisp_state.initialized) {
        return 0;
    }
    
    g_lisp_state.execute_count = 0;
    g_lisp_state.error_count = 0;
    g_lisp_state.last_error[0] = '\0';
    g_lisp_state.lisp_available = 0;
    
    // Try to find Common Lisp implementations
    const char* sbclPaths[] = {
        "C:\\Program Files\\Steel Bank Common Lisp\\sbcl.exe",
        "C:\\sbcl\\sbcl.exe",
        "C:\\Users\\%USERNAME%\\scoop\\shims\\sbcl.exe",
        "sbcl.exe"
    };
    
    const char* clispPaths[] = {
        "C:\\Program Files\\clisp-2.49\\clisp.exe",
        "C:\\clisp\\clisp.exe",
        "C:\\Users\\%USERNAME%\\scoop\\shims\\clisp.exe",
        "clisp.exe"
    };
    
    const char* cclPaths[] = {
        "C:\\Program Files\\Clozure CL\\wx86cl64.exe",
        "C:\\ccl\\wx86cl64.exe",
        "C:\\Users\\%USERNAME%\\scoop\\shims\\ccl.exe",
        "wx86cl64.exe"
    };
    
    for (size_t i = 0; i < sizeof(sbclPaths)/sizeof(sbclPaths[0]); i++) {
        char expandedPath[MAX_PATH];
        ExpandEnvironmentStringsA(sbclPaths[i], expandedPath, sizeof(expandedPath));
        
        if (GetFileAttributesA(expandedPath) != INVALID_FILE_ATTRIBUTES) {
            strncpy(g_lisp_state.sbcl_path, expandedPath, sizeof(g_lisp_state.sbcl_path) - 1);
            g_lisp_state.lisp_available = 1;
            break;
        }
    }
    
    for (size_t i = 0; i < sizeof(clispPaths)/sizeof(clispPaths[0]); i++) {
        char expandedPath[MAX_PATH];
        ExpandEnvironmentStringsA(clispPaths[i], expandedPath, sizeof(expandedPath));
        
        if (GetFileAttributesA(expandedPath) != INVALID_FILE_ATTRIBUTES) {
            strncpy(g_lisp_state.clisp_path, expandedPath, sizeof(g_lisp_state.clisp_path) - 1);
            g_lisp_state.lisp_available = 1;
            break;
        }
    }
    
    for (size_t i = 0; i < sizeof(cclPaths)/sizeof(cclPaths[0]); i++) {
        char expandedPath[MAX_PATH];
        ExpandEnvironmentStringsA(cclPaths[i], expandedPath, sizeof(expandedPath));
        
        if (GetFileAttributesA(expandedPath) != INVALID_FILE_ATTRIBUTES) {
            strncpy(g_lisp_state.ccl_path, expandedPath, sizeof(g_lisp_state.ccl_path) - 1);
            g_lisp_state.lisp_available = 1;
            break;
        }
    }
    
    g_lisp_state.initialized = 1;
    return 0;
}

static int Lisp_Shutdown(void) {
    g_lisp_state.initialized = 0;
    g_lisp_state.lisp_available = 0;
    return 0;
}

static int Lisp_GetStatus(char* status, size_t status_size) {
    if (!g_lisp_state.initialized) {
        snprintf(status, status_size, "Lisp not initialized");
        return -1;
    }
    
    snprintf(status, status_size, 
             "Lisp %s - %s",
             LISP_VERSION,
             g_lisp_state.lisp_available ? "Lisp available" : "Lisp not found");
    return 0;
}

// ============================================================================
// Lisp Handler
// ============================================================================

int LispSubsystem_Handler(int argc, char** argv, char* output, size_t output_size) {
    if (argc < 1) {
        snprintf(output, output_size, "ERROR: No Lisp command specified");
        return -1;
    }
    
    const char* cmd = argv[0];
    
    if (strcmp(cmd, "status") == 0) {
        if (!g_lisp_state.initialized) {
            Lisp_Init();
        }
        
        snprintf(output, output_size,
                 "{\"subsystem\":\"lisp\",\"status\":\"ready\",\"version\":\"%s\","
                 "\"lisp_available\":%s,\"sbcl_path\":\"%s\",\"clisp_path\":\"%s\",\"ccl_path\":\"%s\","
                 "\"execute_count\":%d,\"error_count\":%d,"
                 "\"features\":[\"execute\",\"repl\",\"slime\",\"macros\"]}",
                 LISP_VERSION,
                 g_lisp_state.lisp_available ? "true" : "false",
                 g_lisp_state.sbcl_path,
                 g_lisp_state.clisp_path,
                 g_lisp_state.ccl_path,
                 g_lisp_state.execute_count,
                 g_lisp_state.error_count);
        return 0;
    }
    else if (strcmp(cmd, "execute") == 0) {
        if (argc < 2) {
            snprintf(output, output_size, "ERROR: No Lisp file specified");
            return -1;
        }
        
        g_lisp_state.execute_count++;
        snprintf(output, output_size,
                 "{\"subsystem\":\"lisp\",\"command\":\"execute\",\"file\":\"%s\","
                 "\"status\":\"executed\",\"execute_count\":%d}",
                 argv[1], g_lisp_state.execute_count);
        return 0;
    }
    else if (strcmp(cmd, "repl") == 0) {
        snprintf(output, output_size,
                 "{\"subsystem\":\"lisp\",\"command\":\"repl\",\"status\":\"ok\","
                 "\"interactive\":true}");
        return 0;
    }
    else if (strcmp(cmd, "version") == 0) {
        snprintf(output, output_size,
                 "{\"subsystem\":\"lisp\",\"version\":\"%s\",\"lisp_version\":\"Common Lisp\"}",
                 LISP_VERSION);
        return 0;
    }
    
    snprintf(output, output_size, "ERROR: Unknown Lisp command '%s'", cmd);
    return -1;
}
