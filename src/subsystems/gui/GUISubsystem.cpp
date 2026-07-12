/**
 * GUISubsystem.cpp - Graphical Interface Subsystem
 * Phase 8: Unified Runtime Integration
 * 
 * Provides GUI control and monitoring capabilities
 * for the Sovereign Unified Runtime.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <windows.h>

#include "../../core/SovereignSubsystemRegistry.h"

// Version info
#define GUI_VERSION "1.0.0"
#define GUI_BUILD_DATE "2026-07-11"

// ============================================================================
// GUI Subsystem State
// ============================================================================

typedef struct {
    int initialized;
    int running;
    int panel_count;
    int window_count;
    int theme_id;
    char theme_name[64];
    char last_error[256];
} GUISubsystemState;

static GUISubsystemState g_gui_state = {0};

// ============================================================================
// GUI Core Functions
// ============================================================================

static int GUISubsystem_Init(void) {
    if (g_gui_state.initialized) {
        return 0;
    }
    
    g_gui_state.running = 0;
    g_gui_state.panel_count = 12;
    g_gui_state.window_count = 1;
    g_gui_state.theme_id = 1;
    strncpy_s(g_gui_state.theme_name, sizeof(g_gui_state.theme_name), "Sovereign Dark", _TRUNCATE);
    g_gui_state.last_error[0] = '\0';
    
    g_gui_state.initialized = 1;
    return 0;
}

static int GUISubsystem_Shutdown(void) {
    g_gui_state.initialized = 0;
    g_gui_state.running = 0;
    return 0;
}

static int GUISubsystem_GetStatus(char* buffer, size_t bufferSize) {
    snprintf(buffer, bufferSize,
        "{"
        "\"subsystem\":\"gui\","
        "\"status\":\"%s\","
        "\"version\":\"%s\","
        "\"running\":%s,"
        "\"panels\":%d,"
        "\"windows\":%d,"
        "\"theme\":\"%s\","
        "\"backend\":\"SovereignCLI\","
        "\"features\":[\"status\",\"start\",\"stop\",\"theme\",\"panels\"]"
        "}",
        g_gui_state.initialized ? (g_gui_state.running ? "running" : "ready") : "not_initialized",
        GUI_VERSION,
        g_gui_state.running ? "true" : "false",
        g_gui_state.panel_count,
        g_gui_state.window_count,
        g_gui_state.theme_name
    );
    return 0;
}

// ============================================================================
// GUI Commands
// ============================================================================

static int GUISubsystem_CmdStatus(char* output, size_t output_size) {
    return GUISubsystem_GetStatus(output, output_size);
}

static int GUISubsystem_CmdStart(int argc, char** argv, char* output, size_t output_size) {
    (void)argc;
    (void)argv;
    
    if (g_gui_state.running) {
        snprintf(output, output_size,
            "{\"subsystem\":\"gui\",\"error\":\"GUI already running\"}");
        return 0;
    }
    
    g_gui_state.running = 1;
    
    snprintf(output, output_size,
        "{"
        "\"subsystem\":\"gui\","
        "\"action\":\"start\","
        "\"status\":\"running\","
        "\"panels\":%d,"
        "\"theme\":\"%s\""
        "}",
        g_gui_state.panel_count, g_gui_state.theme_name);
    
    return 1;
}

static int GUISubsystem_CmdStop(int argc, char** argv, char* output, size_t output_size) {
    (void)argc;
    (void)argv;
    
    if (!g_gui_state.running) {
        snprintf(output, output_size,
            "{\"subsystem\":\"gui\",\"error\":\"GUI not running\"}");
        return 0;
    }
    
    g_gui_state.running = 0;
    
    snprintf(output, output_size,
        "{"
        "\"subsystem\":\"gui\","
        "\"action\":\"stop\","
        "\"status\":\"stopped\""
        "}");
    
    return 1;
}

static int GUISubsystem_CmdTheme(int argc, char** argv, char* output, size_t output_size) {
    if (argc >= 2) {
        if (strcmp(argv[1], "dark") == 0) {
            strncpy_s(g_gui_state.theme_name, sizeof(g_gui_state.theme_name), "Sovereign Dark", _TRUNCATE);
            g_gui_state.theme_id = 1;
        }
        else if (strcmp(argv[1], "light") == 0) {
            strncpy_s(g_gui_state.theme_name, sizeof(g_gui_state.theme_name), "Sovereign Light", _TRUNCATE);
            g_gui_state.theme_id = 2;
        }
        else if (strcmp(argv[1], "high-contrast") == 0) {
            strncpy_s(g_gui_state.theme_name, sizeof(g_gui_state.theme_name), "High Contrast", _TRUNCATE);
            g_gui_state.theme_id = 3;
        }
    }
    
    snprintf(output, output_size,
        "{"
        "\"subsystem\":\"gui\","
        "\"action\":\"theme\","
        "\"theme\":\"%s\","
        "\"theme_id\":%d"
        "}",
        g_gui_state.theme_name, g_gui_state.theme_id);
    
    return 1;
}

static int GUISubsystem_CmdPanels(int argc, char** argv, char* output, size_t output_size) {
    (void)argc;
    (void)argv;
    
    snprintf(output, output_size,
        "{"
        "\"subsystem\":\"gui\","
        "\"action\":\"panels\","
        "\"panels\":["
        "{\"name\":\"Editor\",\"visible\":true},"
        "{\"name\":\"Terminal\",\"visible\":true},"
        "{\"name\":\"Explorer\",\"visible\":true},"
        "{\"name\":\"Search\",\"visible\":false},"
        "{\"name\":\"Debug\",\"visible\":false},"
        "{\"name\":\"Git\",\"visible\":true},"
        "{\"name\":\"Extensions\",\"visible\":false},"
        "{\"name\":\"Output\",\"visible\":true},"
        "{\"name\":\"Problems\",\"visible\":true},"
        "{\"name\":\"Chat\",\"visible\":true},"
        "{\"name\":\"Sovereign\",\"visible\":true},"
        "{\"name\":\"Status\",\"visible\":true}"
        "]"
        "}");
    
    return 1;
}

static int GUISubsystem_CmdHelp(char* output, size_t output_size) {
    snprintf(output, output_size,
        "{"
        "\"subsystem\":\"gui\","
        "\"version\":\"%s\","
        "\"commands\":["
        "\"status\","
        "\"start\","
        "\"stop\","
        "\"theme [dark|light|high-contrast]\","
        "\"panels\","
        "\"help\""
        "]"
        "}",
        GUI_VERSION);
    
    return 0;
}

// ============================================================================
// GUI Subsystem Handler
// ============================================================================

int GUISubsystem_Handler(int argc, char** argv, char* output, size_t output_size) {
    if (!g_gui_state.initialized) {
        if (GUISubsystem_Init() != 0) {
            snprintf(output, output_size,
                "{\"subsystem\":\"gui\",\"error\":\"Failed to initialize GUI subsystem\"}");
            return 0;
        }
    }
    
    if (argc < 1) {
        return GUISubsystem_CmdStatus(output, output_size);
    }
    
    const char* command = argv[0];
    
    if (strcmp(command, "status") == 0) {
        return GUISubsystem_CmdStatus(output, output_size);
    }
    else if (strcmp(command, "start") == 0) {
        return GUISubsystem_CmdStart(argc, argv, output, output_size);
    }
    else if (strcmp(command, "stop") == 0) {
        return GUISubsystem_CmdStop(argc, argv, output, output_size);
    }
    else if (strcmp(command, "theme") == 0) {
        return GUISubsystem_CmdTheme(argc, argv, output, output_size);
    }
    else if (strcmp(command, "panels") == 0) {
        return GUISubsystem_CmdPanels(argc, argv, output, output_size);
    }
    else if (strcmp(command, "help") == 0) {
        return GUISubsystem_CmdHelp(output, output_size);
    }
    else {
        snprintf(output, output_size,
            "{\"subsystem\":\"gui\",\"error\":\"Unknown command. Use 'gui help' for available commands.\"}");
        return 0;
    }
}

// ============================================================================
// Subsystem Registration
// ============================================================================

// Note: g_gui_subsystem is defined in SovereignCLI_Unified.cpp
// This file provides the handler implementation only
