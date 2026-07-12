//==============================================================================
// SovereignConfig.cpp
// Configuration management implementation
//
// Phase 7C.2 Complete Integration
//==============================================================================

#include "SovereignConfig.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>

namespace sovereign {
namespace cli {

//==============================================================================
// ConfigManager Implementation
//==============================================================================

ConfigManager& ConfigManager::getInstance() {
    static ConfigManager instance;
    return instance;
}

ConfigManager::ConfigManager() {
    resetToDefaults();
}

void ConfigManager::resetToDefaults() {
    config_ = SovereignConfig{};
    loaded_ = false;
}

bool ConfigManager::loadFromFile(const char* path) {
    FILE* file = fopen(path, "r");
    if (!file) {
        printf("[Config] Could not open config file: %s\n", path);
        return false;
    }
    
    char line[512];
    while (fgets(line, sizeof(line), file)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\0') {
            continue;
        }
        
        // Parse key=value pairs
        char* key = strtok(line, "=");
        char* value = strtok(nullptr, "\n");
        
        if (!key || !value) continue;
        
        // Trim whitespace
        while (*key == ' ' || *key == '\t') key++;
        while (*value == ' ' || *value == '\t') value++;
        
        // Parse configuration options
        if (strcmp(key, "verbose") == 0) {
            config_.verbose = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "numThreads") == 0) {
            config_.numThreads = atoi(value);
        } else if (strcmp(key, "memoryLimitMB") == 0) {
            config_.memoryLimitMB = (size_t)atoi(value);
        } else if (strcmp(key, "useMASM") == 0) {
            config_.useMASM = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "useIntrinsics") == 0) {
            config_.useIntrinsics = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "useReference") == 0) {
            config_.useReference = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "batchSize") == 0) {
            config_.batchSize = (size_t)atoi(value);
        } else if (strcmp(key, "cacheSizeMB") == 0) {
            config_.cacheSizeMB = (size_t)atoi(value);
        } else if (strcmp(key, "temperature") == 0) {
            config_.temperature = (float)atof(value);
        } else if (strcmp(key, "maxTokens") == 0) {
            config_.maxTokens = atoi(value);
        } else if (strcmp(key, "modelPath") == 0) {
            strncpy(config_.modelPath, value, sizeof(config_.modelPath) - 1);
        } else if (strcmp(key, "enableFlashAttention") == 0) {
            config_.enableFlashAttention = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "enableQuantization") == 0) {
            config_.enableQuantization = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        }
    }
    
    fclose(file);
    loaded_ = true;
    printf("[Config] Loaded configuration from: %s\n", path);
    return true;
}

bool ConfigManager::saveToFile(const char* path) {
    FILE* file = fopen(path, "w");
    if (!file) {
        printf("[Config] Could not create config file: %s\n", path);
        return false;
    }
    
    fprintf(file, "# Sovereign CLI Configuration\n");
    fprintf(file, "# Phase 7C.2 Complete Integration\n\n");
    
    fprintf(file, "# General Settings\n");
    fprintf(file, "verbose=%s\n", config_.verbose ? "true" : "false");
    fprintf(file, "numThreads=%d\n", config_.numThreads);
    fprintf(file, "memoryLimitMB=%zu\n", config_.memoryLimitMB);
    fprintf(file, "\n");
    
    fprintf(file, "# Backend Selection\n");
    fprintf(file, "useMASM=%s\n", config_.useMASM ? "true" : "false");
    fprintf(file, "useIntrinsics=%s\n", config_.useIntrinsics ? "true" : "false");
    fprintf(file, "useReference=%s\n", config_.useReference ? "true" : "false");
    fprintf(file, "\n");
    
    fprintf(file, "# Performance Settings\n");
    fprintf(file, "batchSize=%zu\n", config_.batchSize);
    fprintf(file, "cacheSizeMB=%zu\n", config_.cacheSizeMB);
    fprintf(file, "\n");
    
    fprintf(file, "# Inference Settings\n");
    fprintf(file, "temperature=%.2f\n", config_.temperature);
    fprintf(file, "maxTokens=%d\n", config_.maxTokens);
    fprintf(file, "\n");
    
    fprintf(file, "# Feature Flags\n");
    fprintf(file, "enableFlashAttention=%s\n", config_.enableFlashAttention ? "true" : "false");
    fprintf(file, "enableQuantization=%s\n", config_.enableQuantization ? "true" : "false");
    
    fclose(file);
    printf("[Config] Saved configuration to: %s\n", path);
    return true;
}

bool ConfigManager::loadFromEnvironment() {
    const char* env;
    bool loadedAny = false;
    
    if ((env = getenv("SOVEREIGN_VERBOSE"))) {
        config_.verbose = (strcmp(env, "1") == 0 || strcmp(env, "true") == 0);
        loadedAny = true;
    }
    
    if ((env = getenv("SOVEREIGN_THREADS"))) {
        config_.numThreads = atoi(env);
        loadedAny = true;
    }
    
    if ((env = getenv("SOVEREIGN_MEMORY"))) {
        config_.memoryLimitMB = (size_t)atoi(env);
        loadedAny = true;
    }
    
    if ((env = getenv("SOVEREIGN_USE_MASM"))) {
        config_.useMASM = (strcmp(env, "1") == 0 || strcmp(env, "true") == 0);
        loadedAny = true;
    }
    
    if ((env = getenv("SOVEREIGN_USE_INTRINSICS"))) {
        config_.useIntrinsics = (strcmp(env, "1") == 0 || strcmp(env, "true") == 0);
        loadedAny = true;
    }
    
    return loadedAny;
}

bool ConfigManager::validate() {
    bool valid = true;
    
    // Validate thread count
    if (config_.numThreads < 0) {
        printf("[Config] Error: numThreads must be >= 0\n");
        valid = false;
    }
    
    // Validate memory limit
    if (config_.memoryLimitMB > 0 && config_.memoryLimitMB < 256) {
        printf("[Config] Warning: memoryLimitMB < 256 MB may cause issues\n");
    }
    
    // Validate at least one backend is enabled
    if (!config_.useMASM && !config_.useIntrinsics && !config_.useReference) {
        printf("[Config] Error: At least one backend must be enabled\n");
        valid = false;
    }
    
    // Validate batch size
    if (config_.batchSize == 0 || config_.batchSize > 8192) {
        printf("[Config] Error: batchSize must be between 1 and 8192\n");
        valid = false;
    }
    
    // Validate temperature
    if (config_.temperature < 0.0f || config_.temperature > 2.0f) {
        printf("[Config] Warning: temperature outside typical range (0.0-2.0)\n");
    }
    
    return valid;
}

void ConfigManager::print() const {
    printf("==============================================================================\n");
    printf("Sovereign Configuration\n");
    printf("==============================================================================\n\n");
    
    printf("General Settings:\n");
    printf("  verbose:        %s\n", config_.verbose ? "true" : "false");
    printf("  numThreads:     %d\n", config_.numThreads);
    printf("  memoryLimitMB:  %zu\n", config_.memoryLimitMB);
    printf("\n");
    
    printf("Backend Selection:\n");
    printf("  useMASM:        %s\n", config_.useMASM ? "true" : "false");
    printf("  useIntrinsics:  %s\n", config_.useIntrinsics ? "true" : "false");
    printf("  useReference:   %s\n", config_.useReference ? "true" : "false");
    printf("\n");
    
    printf("Performance Settings:\n");
    printf("  batchSize:      %zu\n", config_.batchSize);
    printf("  cacheSizeMB:    %zu\n", config_.cacheSizeMB);
    printf("\n");
    
    printf("Inference Settings:\n");
    printf("  temperature:    %.2f\n", config_.temperature);
    printf("  maxTokens:      %d\n", config_.maxTokens);
    printf("\n");
    
    printf("Feature Flags:\n");
    printf("  enableFlashAttention:  %s\n", config_.enableFlashAttention ? "true" : "false");
    printf("  enableQuantization:    %s\n", config_.enableQuantization ? "true" : "false");
    printf("  enableStreaming:       %s\n", config_.enableStreaming ? "true" : "false");
    printf("  enableTelemetry:       %s\n", config_.enableTelemetry ? "true" : "false");
    
    printf("\n==============================================================================\n");
}

} // namespace cli
} // namespace sovereign
