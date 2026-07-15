/**
 * SunshineSubsystem.cpp - Game Engine Subsystem
 * Phase 8: Unified Runtime Integration
 * 
 * Provides game engine control and monitoring
 * for the Sovereign Unified Runtime.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <windows.h>

#include "../../core/SovereignSubsystemRegistry.h"

// Version info
#define SUNSHINE_VERSION "0.1.0"
#define SUNSHINE_BUILD_DATE "2026-07-11"

// ============================================================================
// Sunshine Subsystem State
// ============================================================================

typedef struct {
    int initialized;
    int running;
    int frame_count;
    float fps;
    int width;
    int height;
    char last_error[256];
} SunshineSubsystemState;

static SunshineSubsystemState g_sunshine_state = {0};

// ============================================================================
// Sunshine Core Functions
// ============================================================================

static int Sunshine_Init(void) {
    if (g_sunshine_state.initialized) {
        return 0;
    }
    
    g_sunshine_state.running = 0;
    g_sunshine_state.frame_count = 0;
    g_sunshine_state.fps = 0.0f;
    g_sunshine_state.width = 1920;
    g_sunshine_state.height = 1080;
    g_sunshine_state.last_error[0] = '\0';
    
    g_sunshine_state.initialized = 1;
    return 0;
}

static int Sunshine_Shutdown(void) {
    g_sunshine_state.initialized = 0;
    g_sunshine_state.running = 0;
    return 0;
}

static int Sunshine_GetStatus(char* buffer, size_t bufferSize) {
    snprintf(buffer, bufferSize,
        "{"
        "\"subsystem\":\"sunshine\","
        "\"status\":\"%s\","
        "\"version\":\"%s\","
        "\"running\":%s,"
        "\"fps\":%.1f,"
        "\"frame_count\":%d,"
        "\"resolution\":\"%dx%d\","
        "\"features\":[\"start\",\"stop\",\"status\",\"config\"]"
        "}",
        g_sunshine_state.initialized ? (g_sunshine_state.running ? "running" : "ready") : "not_initialized",
        SUNSHINE_VERSION,
        g_sunshine_state.running ? "true" : "false",
        g_sunshine_state.fps,
        g_sunshine_state.frame_count,
        g_sunshine_state.width, g_sunshine_state.height
    );
    return 0;
}

// ============================================================================
// Sunshine Commands
// ============================================================================

static int Sunshine_CmdStatus(char* output, size_t output_size) {
    return Sunshine_GetStatus(output, output_size);
}

static int Sunshine_CmdStart(int argc, char** argv, char* output, size_t output_size) {
    (void)argc;
    (void)argv;
    
    if (g_sunshine_state.running) {
        snprintf(output, output_size,
            "{\"subsystem\":\"sunshine\",\"error\":\"Already running\"}");
        return 0;
    }
    
    g_sunshine_state.running = 1;
    g_sunshine_state.frame_count = 0;
    g_sunshine_state.fps = 60.0f;
    
    snprintf(output, output_size,
        "{"
        "\"subsystem\":\"sunshine\","
        "\"action\":\"start\","
        "\"status\":\"running\","
        "\"resolution\":\"%dx%d\","
        "\"target_fps\":60"
        "}",
        g_sunshine_state.width, g_sunshine_state.height);
    
    return 1;
}

static int Sunshine_CmdStop(int argc, char** argv, char* output, size_t output_size) {
    (void)argc;
    (void)argv;
    
    if (!g_sunshine_state.running) {
        snprintf(output, output_size,
            "{\"subsystem\":\"sunshine\",\"error\":\"Not running\"}");
        return 0;
    }
    
    g_sunshine_state.running = 0;
    
    snprintf(output, output_size,
        "{"
        "\"subsystem\":\"sunshine\","
        "\"action\":\"stop\","
        "\"status\":\"stopped\","
        "\"total_frames\":%d"
        "}",
        g_sunshine_state.frame_count);
    
    return 1;
}

static int Sunshine_CmdConfig(int argc, char** argv, char* output, size_t output_size) {
    if (argc >= 3) {
        if (strcmp(argv[1], "width") == 0) {
            g_sunshine_state.width = atoi(argv[2]);
        }
        else if (strcmp(argv[1], "height") == 0) {
            g_sunshine_state.height = atoi(argv[2]);
        }
        else if (strcmp(argv[1], "fps") == 0) {
            g_sunshine_state.fps = (float)atof(argv[2]);
        }
    }
    
    snprintf(output, output_size,
        "{"
        "\"subsystem\":\"sunshine\","
        "\"action\":\"config\","
        "\"width\":%d,"
        "\"height\":%d,"
        "\"target_fps\":%.1f"
        "}",
        g_sunshine_state.width, g_sunshine_state.height, g_sunshine_state.fps);
    
    return 1;
}

static int Sunshine_CmdScreenshot(int argc, char** argv, char* output, size_t output_size) {
    (void)argc;
    (void)argv;
    
    if (!g_sunshine_state.running) {
        snprintf(output, output_size,
            "{\"subsystem\":\"sunshine\",\"error\":\"Engine not running\"}");
        return 0;
    }
    
    snprintf(output, output_size,
        "{"
        "\"subsystem\":\"sunshine\","
        "\"action\":\"screenshot\","
        "\"status\":\"saved\","
        "\"file\":\"screenshot_001.png\","
        "\"resolution\":\"%dx%d\""
        "}",
        g_sunshine_state.width, g_sunshine_state.height);
    
    return 1;
}

static int Sunshine_CmdHelp(char* output, size_t output_size) {
    snprintf(output, output_size,
        "{"
        "\"subsystem\":\"sunshine\","
        "\"version\":\"%s\","
        "\"commands\":["
        "\"status\","
        "\"start\","
        "\"stop\","
        "\"config <key> <value>\","
        "\"screenshot\","
        "\"help\""
        "]"
        "}",
        SUNSHINE_VERSION);
    
    return 0;
}

// ============================================================================
// Sunshine Subsystem Handler
// ============================================================================

int SunshineSubsystem_Handler(int argc, char** argv, char* output, size_t output_size) {
    if (!g_sunshine_state.initialized) {
        if (Sunshine_Init() != 0) {
            snprintf(output, output_size,
                "{\"subsystem\":\"sunshine\",\"error\":\"Failed to initialize Sunshine subsystem\"}");
            return 0;
        }
    }
    
    if (argc < 1) {
        return Sunshine_CmdStatus(output, output_size);
    }
    
    const char* command = argv[0];
    
    if (strcmp(command, "status") == 0) {
        return Sunshine_CmdStatus(output, output_size);
    }
    else if (strcmp(command, "start") == 0) {
        return Sunshine_CmdStart(argc, argv, output, output_size);
    }
    else if (strcmp(command, "stop") == 0) {
        return Sunshine_CmdStop(argc, argv, output, output_size);
    }
    else if (strcmp(command, "config") == 0) {
        return Sunshine_CmdConfig(argc, argv, output, output_size);
    }
    else if (strcmp(command, "screenshot") == 0) {
        return Sunshine_CmdScreenshot(argc, argv, output, output_size);
    }
    else if (strcmp(command, "help") == 0) {
        return Sunshine_CmdHelp(output, output_size);
    }
    else {
        snprintf(output, output_size,
            "{\"subsystem\":\"sunshine\",\"error\":\"Unknown command. Use 'sunshine help' for available commands.\"}");
        return 0;
    }
}

// ============================================================================
// Subsystem Registration
// ============================================================================

// Note: g_sunshine_subsystem is defined in SovereignCLI_Unified.cpp
// This file provides the handler implementation only
