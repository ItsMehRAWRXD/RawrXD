/**
 * CLISubsystem.cpp - Command Line Interface Subsystem
 * Phase 8: Unified Runtime Integration
 * 
 * Provides CLI introspection and control capabilities
 * for the Sovereign Unified Runtime.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <windows.h>

#include "../../core/SovereignSubsystemRegistry.h"

// Version info
#define CLI_SUBSYSTEM_VERSION "1.0.0"
#define CLI_SUBSYSTEM_BUILD_DATE "2026-07-11"

// CLI version - defined in main SovereignCLI_Unified.cpp
#ifndef CLI_VERSION
#define CLI_VERSION "8.2.0"
#endif

// ============================================================================
// CLI Subsystem State
// ============================================================================

typedef struct {
    int initialized;
    int commands_executed;
    int commands_failed;
    char last_error[256];
} CLISubsystemState;

static CLISubsystemState g_cli_state = {0};

// ============================================================================
// CLI Core Functions
// ============================================================================

static int CLISubsystem_Init(void) {
    if (g_cli_state.initialized) {
        return 0;
    }
    
    g_cli_state.commands_executed = 0;
    g_cli_state.commands_failed = 0;
    g_cli_state.last_error[0] = '\0';
    
    g_cli_state.initialized = 1;
    return 0;
}

static int CLISubsystem_Shutdown(void) {
    g_cli_state.initialized = 0;
    return 0;
}

static int CLISubsystem_GetStatus(char* buffer, size_t bufferSize) {
    snprintf(buffer, bufferSize,
        "{"
        "\"subsystem\":\"cli\","
        "\"status\":\"%s\","
        "\"version\":\"%s\","
        "\"cli_version\":\"%s\","
        "\"commands_executed\":%d,"
        "\"commands_failed\":%d,"
        "\"features\":[\"status\",\"version\",\"stats\",\"help\"]"
        "}",
        g_cli_state.initialized ? "ready" : "not_initialized",
        CLI_SUBSYSTEM_VERSION,
        CLI_VERSION,
        g_cli_state.commands_executed,
        g_cli_state.commands_failed
    );
    return 0;
}

// ============================================================================
// CLI Commands
// ============================================================================

static int CLISubsystem_CmdStatus(char* output, size_t output_size) {
    return CLISubsystem_GetStatus(output, output_size);
}

static int CLISubsystem_CmdVersion(int argc, char** argv, char* output, size_t output_size) {
    (void)argc;
    (void)argv;
    
    snprintf(output, output_size,
        "{"
        "\"subsystem\":\"cli\","
        "\"action\":\"version\","
        "\"version\":\"%s\","
        "\"build_date\":\"%s\","
        "\"api_version\":\"8.2.0\","
        "\"phase\":\"8\","
        "\"subsystems\":10"
        "}",
        CLI_VERSION, CLI_SUBSYSTEM_BUILD_DATE);
    
    return 1;
}

static int CLISubsystem_CmdStats(int argc, char** argv, char* output, size_t output_size) {
    (void)argc;
    (void)argv;
    
    g_cli_state.commands_executed++;
    
    snprintf(output, output_size,
        "{"
        "\"subsystem\":\"cli\","
        "\"action\":\"stats\","
        "\"commands_executed\":%d,"
        "\"commands_failed\":%d,"
        "\"success_rate\":%.1f,"
        "\"status\":\"active\""
        "}",
        g_cli_state.commands_executed,
        g_cli_state.commands_failed,
        g_cli_state.commands_executed > 0 
            ? 100.0f * (1.0f - (float)g_cli_state.commands_failed / g_cli_state.commands_executed)
            : 100.0f);
    
    return 1;
}

static int CLISubsystem_CmdHelp(char* output, size_t output_size) {
    snprintf(output, output_size,
        "{"
        "\"subsystem\":\"cli\","
        "\"version\":\"%s\","
        "\"commands\":["
        "\"status\","
        "\"version\","
        "\"stats\","
        "\"help\""
        "]"
        "}",
        CLI_SUBSYSTEM_VERSION);
    
    return 0;
}

// ============================================================================
// CLI Subsystem Handler
// ============================================================================

int CLISubsystem_Handler(int argc, char** argv, char* output, size_t output_size) {
    if (!g_cli_state.initialized) {
        if (CLISubsystem_Init() != 0) {
            snprintf(output, output_size,
                "{\"subsystem\":\"cli\",\"error\":\"Failed to initialize CLI subsystem\"}");
            return 0;
        }
    }
    
    if (argc < 1) {
        return CLISubsystem_CmdStatus(output, output_size);
    }
    
    const char* command = argv[0];
    
    if (strcmp(command, "status") == 0) {
        return CLISubsystem_CmdStatus(output, output_size);
    }
    else if (strcmp(command, "version") == 0) {
        return CLISubsystem_CmdVersion(argc, argv, output, output_size);
    }
    else if (strcmp(command, "stats") == 0) {
        return CLISubsystem_CmdStats(argc, argv, output, output_size);
    }
    else if (strcmp(command, "help") == 0) {
        return CLISubsystem_CmdHelp(output, output_size);
    }
    else {
        snprintf(output, output_size,
            "{\"subsystem\":\"cli\",\"error\":\"Unknown command. Use 'cli help' for available commands.\"}");
        return 0;
    }
}

// ============================================================================
// Subsystem Registration
// ============================================================================

// Note: g_cli_subsystem is defined in SovereignCLI_Unified.cpp
// This file provides the handler implementation only
