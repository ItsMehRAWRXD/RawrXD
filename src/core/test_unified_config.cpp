// Test harness for UnifiedConfig
// Compile: g++ -std=c++17 -O2 -Wall test_unified_config.cpp UnifiedConfig.cpp -o test_unified_config.exe -lkernel32

#include "UnifiedConfig.hpp"
#include <cstdio>
#include <cstring>

using namespace RawrXD;

int main() {
    printf("=== RawrXD UnifiedConfig Test ===\n\n");
    
    // Test 1: Load from string
    printf("Test 1: Load from JSON string...\n");
    UnifiedConfig config;
    
    const char* testJson = R"({
        "model": {
            "path": "models/qwen32b.gguf",
            "context_size": 32768,
            "gpu_layers": 33
        },
        "ui": {
            "theme": "dark",
            "font_size": 14,
            "font_family": "Consolas"
        },
        "lsp": {
            "enabled": true,
            "timeout_ms": 5000
        }
    })";
    
    if (!config.LoadFromString(testJson)) {
        printf("  FAILED: Could not load config\n");
        return 1;
    }
    printf("  PASSED: Config loaded\n");
    
    // Test 2: Get string values
    printf("\nTest 2: Get string values...\n");
    auto modelPath = config.GetString(ConfigKeys::ModelPath);
    if (modelPath == "models/qwen32b.gguf") {
        printf("  PASSED: model/path = %.*s\n", 
               static_cast<int>(modelPath.length()), modelPath.data());
    } else {
        printf("  FAILED: Expected 'models/qwen32b.gguf', got '%.*s'\n",
               static_cast<int>(modelPath.length()), modelPath.data());
    }
    
    auto theme = config.GetString(ConfigKeys::UiTheme);
    if (theme == "dark") {
        printf("  PASSED: ui/theme = %.*s\n",
               static_cast<int>(theme.length()), theme.data());
    } else {
        printf("  FAILED: Expected 'dark', got '%.*s'\n",
               static_cast<int>(theme.length()), theme.data());
    }
    
    // Test 3: Get integer values
    printf("\nTest 3: Get integer values...\n");
    auto contextSize = config.GetInt(ConfigKeys::ModelContextSize);
    if (contextSize == 32768) {
        printf("  PASSED: model/context_size = %lld\n", contextSize);
    } else {
        printf("  FAILED: Expected 32768, got %lld\n", contextSize);
    }
    
    auto fontSize = config.GetInt(ConfigKeys::UiFontSize);
    if (fontSize == 14) {
        printf("  PASSED: ui/font_size = %lld\n", fontSize);
    } else {
        printf("  FAILED: Expected 14, got %lld\n", fontSize);
    }
    
    // Test 4: Get boolean values
    printf("\nTest 4: Get boolean values...\n");
    auto lspEnabled = config.GetBool(ConfigKeys::LspEnabled);
    if (lspEnabled) {
        printf("  PASSED: lsp/enabled = true\n");
    } else {
        printf("  FAILED: Expected true\n");
    }
    
    // Test 5: Default values
    printf("\nTest 5: Default values...\n");
    auto missingBool = config.GetBool("nonexistent/key", true);
    if (missingBool) {
        printf("  PASSED: Default value returned for missing key\n");
    } else {
        printf("  FAILED: Default not applied\n");
    }
    
    auto missingInt = config.GetInt("nonexistent/key", 42);
    if (missingInt == 42) {
        printf("  PASSED: Default int value = %lld\n", missingInt);
    } else {
        printf("  FAILED: Expected 42, got %lld\n", missingInt);
    }
    
    // Test 6: HasKey check
    printf("\nTest 6: HasKey check...\n");
    if (config.HasKey("model/path") && !config.HasKey("nonexistent")) {
        printf("  PASSED: HasKey works correctly\n");
    } else {
        printf("  FAILED: HasKey check failed\n");
    }
    
    // Test 7: ConfigValue type checking
    printf("\nTest 7: ConfigValue type checking...\n");
    auto val = config.Get("model/context_size");
    if (val.IsInt() && !val.IsString() && !val.IsNull()) {
        printf("  PASSED: Type checking works\n");
    } else {
        printf("  FAILED: Type checking failed\n");
    }
    
    // Test 8: Global config
    printf("\nTest 8: Global config...\n");
    if (GetGlobalConfig() == &config) {
        printf("  PASSED: Global config set correctly\n");
    } else {
        printf("  FAILED: Global config not set\n");
    }
    
    printf("\n=== All Tests Complete ===\n");
    return 0;
}
