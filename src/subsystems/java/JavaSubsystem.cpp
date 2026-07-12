/**
 * JavaSubsystem.cpp - MASM Java Backend Subsystem
 * Phase 8: Unified Runtime Integration
 * 
 * Provides Java bytecode compilation and JVM integration
 * for the Sovereign Unified Runtime.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <windows.h>

#include "../../core/SovereignSubsystemRegistry.h"

// ============================================================================
// Java Subsystem State
// ============================================================================

typedef struct {
    int initialized;
    int compile_count;
    int error_count;
    char last_error[256];
    char classpath[512];
    char jvm_path[MAX_PATH];
    int jvm_loaded;
} JavaSubsystemState;

static JavaSubsystemState g_java_state = {0};

// ============================================================================
// Java Core Functions
// ============================================================================

static int Java_Init(void) {
    if (g_java_state.initialized) {
        return 0; // Already initialized, success
    }
    
    g_java_state.compile_count = 0;
    g_java_state.error_count = 0;
    g_java_state.last_error[0] = '\0';
    g_java_state.classpath[0] = '\0';
    g_java_state.jvm_loaded = 0;
    
    const char* jvmPaths[] = {
        "C:\\Program Files\\Java\\jdk-21\\bin\\server\\jvm.dll",
        "C:\\Program Files\\Java\\jdk-17\\bin\\server\\jvm.dll",
        "C:\\Program Files\\Java\\jdk-11\\bin\\server\\jvm.dll",
        "C:\\Program Files\\Java\\jdk-1.8\\bin\\server\\jvm.dll",
        "C:\\Program Files\\Eclipse Adoptium\\jdk-21\\bin\\server\\jvm.dll",
        "C:\\Program Files\\Eclipse Adoptium\\jdk-17\\bin\\server\\jvm.dll",
    };
    
    for (int i = 0; i < (int)(sizeof(jvmPaths)/sizeof(jvmPaths[0])); i++) {
        if (GetFileAttributesA(jvmPaths[i]) != INVALID_FILE_ATTRIBUTES) {
            strncpy_s(g_java_state.jvm_path, sizeof(g_java_state.jvm_path), jvmPaths[i], _TRUNCATE);
            g_java_state.jvm_loaded = 1;
            break;
        }
    }
    
    g_java_state.initialized = 1;
    return 0; // Success
}

static int Java_Shutdown(void) {
    g_java_state.initialized = 0;
    g_java_state.jvm_loaded = 0;
    return 1;
}

static int Java_GetStatus(char* buffer, size_t bufferSize) {
    const char* jvmStatus = g_java_state.jvm_loaded ? "available" : "not_found";
    const char* classpath = g_java_state.classpath[0] ? g_java_state.classpath : "default";
    
    snprintf(buffer, bufferSize,
        "{"
        "\"subsystem\":\"java\","
        "\"status\":\"%s\","
        "\"jvm\":\"%s\","
        "\"jvm_path\":\"%s\","
        "\"classpath\":\"%s\","
        "\"compile_count\":%d,"
        "\"error_count\":%d,"
        "\"features\":[\"compile\",\"run\",\"javap\",\"bytecode\"]"
        "}",
        g_java_state.initialized ? "ready" : "not_initialized",
        jvmStatus,
        g_java_state.jvm_path,
        classpath,
        g_java_state.compile_count,
        g_java_state.error_count
    );
    return 1;
}

// ============================================================================
// Java Commands
// ============================================================================

static int Java_CmdStatus(char* output, size_t output_size) {
    return Java_GetStatus(output, output_size);
}

static int Java_CmdCompile(int argc, char** argv, char* output, size_t output_size) {
    if (argc < 2) {
        snprintf(output, output_size,
            "{\"subsystem\":\"java\",\"error\":\"Usage: java compile <source.java> [output.class]\"}");
        return 0;
    }
    
    const char* sourceFile = argv[1];
    
    if (GetFileAttributesA(sourceFile) == INVALID_FILE_ATTRIBUTES) {
        snprintf(output, output_size,
            "{\"subsystem\":\"java\",\"error\":\"Source file not found\"}");
        return 0;
    }
    
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "javac \"%s\"", sourceFile);
    
    int result = system(cmd);
    
    if (result == 0) {
        g_java_state.compile_count++;
        snprintf(output, output_size,
            "{\"subsystem\":\"java\",\"action\":\"compile\",\"source\":\"%s\",\"status\":\"success\"}",
            sourceFile);
    } else {
        g_java_state.error_count++;
        snprintf(output, output_size,
            "{\"subsystem\":\"java\",\"action\":\"compile\",\"source\":\"%s\",\"status\":\"failed\"}",
            sourceFile);
    }
    
    return (result == 0) ? 1 : 0;
}

static int Java_CmdRun(int argc, char** argv, char* output, size_t output_size) {
    if (argc < 2) {
        snprintf(output, output_size,
            "{\"subsystem\":\"java\",\"error\":\"Usage: java run <class> [args...]\"}");
        return 0;
    }
    
    const char* className = argv[1];
    
    char cmd[1024];
    if (g_java_state.classpath[0]) {
        snprintf(cmd, sizeof(cmd), "java -cp \"%s\" %s", g_java_state.classpath, className);
    } else {
        snprintf(cmd, sizeof(cmd), "java %s", className);
    }
    
    int result = system(cmd);
    
    if (result == 0) {
        snprintf(output, output_size,
            "{\"subsystem\":\"java\",\"action\":\"run\",\"class\":\"%s\",\"status\":\"success\"}",
            className);
    } else {
        snprintf(output, output_size,
            "{\"subsystem\":\"java\",\"action\":\"run\",\"class\":\"%s\",\"status\":\"failed\"}",
            className);
    }
    
    return (result == 0) ? 1 : 0;
}

static int Java_CmdJavap(int argc, char** argv, char* output, size_t output_size) {
    if (argc < 2) {
        snprintf(output, output_size,
            "{\"subsystem\":\"java\",\"error\":\"Usage: java javap <classfile>\"}");
        return 0;
    }
    
    const char* classFile = argv[1];
    
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "javap -c -v \"%s\"", classFile);
    
    int result = system(cmd);
    
    if (result == 0) {
        snprintf(output, output_size,
            "{\"subsystem\":\"java\",\"action\":\"javap\",\"class\":\"%s\",\"status\":\"success\"}",
            classFile);
    } else {
        snprintf(output, output_size,
            "{\"subsystem\":\"java\",\"action\":\"javap\",\"class\":\"%s\",\"status\":\"failed\"}",
            classFile);
    }
    
    return (result == 0) ? 1 : 0;
}

static int Java_CmdSetClasspath(int argc, char** argv, char* output, size_t output_size) {
    if (argc < 2) {
        snprintf(output, output_size,
            "{\"subsystem\":\"java\",\"error\":\"Usage: java setclasspath <path1;path2;...>\"}");
        return 0;
    }
    
    strncpy_s(g_java_state.classpath, sizeof(g_java_state.classpath), argv[1], _TRUNCATE);
    
    snprintf(output, output_size,
        "{\"subsystem\":\"java\",\"action\":\"setclasspath\",\"classpath\":\"%s\",\"status\":\"success\"}",
        g_java_state.classpath);
    return 1;
}

static int Java_CmdVersion(int argc, char** argv, char* output, size_t output_size) {
    (void)argc;
    (void)argv;
    
    system("java -version 2>&1");
    
    snprintf(output, output_size,
        "{\"subsystem\":\"java\",\"action\":\"version\",\"jvm_available\":%s}",
        g_java_state.jvm_loaded ? "true" : "false");
    
    return 1;
}

static int Java_CmdHelp(char* output, size_t output_size) {
    snprintf(output, output_size,
        "{"
        "\"subsystem\":\"java\","
        "\"status\":\"help\","
        "\"commands\":["
        "\"status\","
        "\"compile <source.java>\","
        "\"run <class>\","
        "\"javap <classfile>\","
        "\"setclasspath <paths>\","
        "\"version\","
        "\"help\""
        "]"
        "}");
    
    return 1;
}

// ============================================================================
// Java Subsystem Handler
// ============================================================================

int JavaSubsystem_Handler(int argc, char** argv, char* output, size_t output_size) {
    if (!g_java_state.initialized) {
        if (!Java_Init()) {
            snprintf(output, output_size,
                "{\"subsystem\":\"java\",\"error\":\"Failed to initialize Java subsystem\"}");
            return 0;
        }
    }
    
    if (argc < 1) {
        return Java_CmdStatus(output, output_size);
    }
    
    const char* command = argv[0];
    
    if (strcmp(command, "status") == 0) {
        return Java_CmdStatus(output, output_size);
    }
    else if (strcmp(command, "compile") == 0) {
        return Java_CmdCompile(argc, argv, output, output_size);
    }
    else if (strcmp(command, "run") == 0) {
        return Java_CmdRun(argc, argv, output, output_size);
    }
    else if (strcmp(command, "javap") == 0) {
        return Java_CmdJavap(argc, argv, output, output_size);
    }
    else if (strcmp(command, "setclasspath") == 0) {
        return Java_CmdSetClasspath(argc, argv, output, output_size);
    }
    else if (strcmp(command, "version") == 0) {
        return Java_CmdVersion(argc, argv, output, output_size);
    }
    else if (strcmp(command, "help") == 0) {
        return Java_CmdHelp(output, output_size);
    }
    else {
        snprintf(output, output_size,
            "{\"subsystem\":\"java\",\"error\":\"Unknown command. Use 'java help' for available commands.\"}");
        return 0;
    }
}

// ============================================================================
// Subsystem Registration
// ============================================================================

// Note: g_java_subsystem is defined in SovereignCLI_Unified.cpp
// This file provides the handler implementation only
