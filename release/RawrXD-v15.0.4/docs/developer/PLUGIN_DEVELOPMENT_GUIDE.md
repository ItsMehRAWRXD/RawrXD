# RawrXD Plugin Development Guide

## Phase Y.4/5: Developer Experience & Ecosystem Expansion

---

## Overview

This guide covers developing plugins for RawrXD using the Plugin SDK. Plugins allow you to extend RawrXD's functionality with custom tools, model backends, UI extensions, and more.

---

## Getting Started

### Prerequisites

- C++17 compatible compiler
- RawrXD SDK installed
- CMake 3.15+ (recommended)

### Quick Start

```bash
# Create a new plugin project
rawrxd-cli plugin create MyPlugin --template=basic

# Build the plugin
cd MyPlugin
mkdir build && cd build
cmake ..
cmake --build .

# Install the plugin
rawrxd-cli plugin install ./MyPlugin.dll
```

---

## Plugin Structure

### Minimum Plugin

```cpp
// MyPlugin.hpp
#pragma once
#include <rawrxd/developer/PluginSDK.hpp>

class MyPlugin : public RawrXD::Developer::IPlugin {
public:
    bool Initialize(const RawrXD::Developer::PluginContext& context) override {
        context.log_callback("INFO", "MyPlugin initialized");
        return true;
    }
    
    void Shutdown() override {
        // Cleanup
    }
    
    RawrXD::Developer::PluginManifest GetManifest() const override {
        return {
            "com.example.myplugin",
            "My Plugin",
            "1.0.0",
            "A sample plugin",
            "Your Name",
            "MIT",
            "https://example.com",
            "https://github.com/example/myplugin",
            RawrXD::Developer::PLUGIN_API_VERSION,
            {"1.0.0"},
            {RawrXD::Developer::PluginCapability::TOOL_PROVIDER}
        };
    }
    
    std::string GetStatus() const override {
        return "Running";
    }
};

RAWRXD_DEFINE_PLUGIN(MyPlugin)
```

### Plugin Manifest

The manifest defines your plugin's metadata and capabilities:

| Field | Description | Required |
|-------|-------------|----------|
| `id` | Unique identifier (reverse domain) | Yes |
| `name` | Display name | Yes |
| `version` | Semantic version | Yes |
| `description` | Short description | Yes |
| `author` | Author name | Yes |
| `license` | License identifier | Yes |
| `api_version` | Target Plugin API version | Yes |
| `capabilities` | List of capabilities | Yes |

---

## Capabilities

### Tool Provider

Create custom tools for the agent system:

```cpp
std::vector<RawrXD::Developer::ToolDefinition> GetTools() override {
    return {
        {
            "my_custom_tool",
            "Performs a custom operation",
            "Custom",
            R"({"type": "object", "properties": {"input": {"type": "string"}}})",
            R"({"type": "string"})",
            [](const std::string& input_json) -> std::string {
                // Parse input
                // Perform operation
                return "{\"result\": \"success\"}";
            },
            std::chrono::seconds(30),
            false,
            false,
            {}
        }
    };
}
```

### Model Provider

Add support for custom model backends:

```cpp
class MyModelBackend : public RawrXD::Developer::IModelBackend {
public:
    bool Initialize(const std::unordered_map<std::string, std::string>& config) override {
        // Load model
        return true;
    }
    
    void Shutdown() override {
        // Cleanup
    }
    
    std::string Generate(const std::string& prompt,
                         const std::unordered_map<std::string, std::string>& params) override {
        // Run inference
        return "Generated text";
    }
    
    void GenerateStream(const std::string& prompt,
                         const std::unordered_map<std::string, std::string>& params,
                         std::function<void(const std::string& token)> callback) override {
        // Stream tokens
        callback("token1");
        callback("token2");
    }
    
    void ClearContext() override {
        // Reset context
    }
    
    std::unordered_map<std::string, std::string> GetStats() override {
        return {{"tokens_generated", "100"}};
    }
};

std::vector<RawrXD::Developer::ModelBackendDefinition> GetModelBackends() override {
    return {
        {
            "my_backend",
            "My custom model backend",
            {"gguf"},
            true, true, true,
            [](const std::string& path) { return true; },
            [](const std::string& path) {
                return std::make_unique<MyModelBackend>();
            }
        }
    };
}
```

### UI Extension

Add custom UI elements:

```cpp
std::vector<RawrXD::Developer::UIExtensionPoint> GetUIExtensions() override {
    return {
        {
            "sidebar",
            "My Panel",
            "A custom sidebar panel",
            [](void* native_window_handle) {
                // Render UI
            },
            [](const std::string& event, const std::string& data) {
                // Handle events
            },
            300, 400, true
        }
    };
}
```

### Inference Hook

Hook into the inference pipeline:

```cpp
std::vector<RawrXD::Developer::InferenceHook> GetInferenceHooks() override {
    return {
        {
            "my_pre_processor",
            "pre_tokenize",
            [](const std::string& input, const std::unordered_map<std::string, std::string>& context) {
                // Modify input before tokenization
                return input;
            },
            100,
            true
        }
    };
}
```

---

## Building Plugins

### CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.15)
project(MyPlugin)

set(CMAKE_CXX_STANDARD 17)

# Find RawrXD SDK
find_package(RawrXD REQUIRED)

# Create plugin
add_library(MyPlugin SHARED
    src/MyPlugin.cpp
)

target_link_libraries(MyPlugin
    RawrXD::PluginSDK
)

# Set plugin properties
set_target_properties(MyPlugin PROPERTIES
    PREFIX ""
    OUTPUT_NAME "MyPlugin"
)
```

### Build Commands

```bash
# Configure
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build --config Release

# Install to RawrXD
rawrxd-cli plugin install build/MyPlugin.dll
```

---

## Debugging Plugins

### Enable Debug Logging

```cpp
void MyPlugin::Initialize(const PluginContext& context) {
    context.log_callback("DEBUG", "Initializing MyPlugin");
    // ...
}
```

### Attach Debugger

```bash
# Start RawrXD with debugging enabled
rawrxd --debug-plugins

# In another terminal, attach debugger
rawrxd-cli debug attach --plugin=MyPlugin
```

### Plugin Logs

```bash
# View plugin logs
rawrxd-cli plugin logs MyPlugin

# Follow logs
rawrxd-cli plugin logs MyPlugin --follow
```

---

## Testing Plugins

### Unit Tests

```cpp
// test_my_plugin.cpp
#include <gtest/gtest.h>
#include "MyPlugin.hpp"

TEST(MyPluginTest, Initialize) {
    MyPlugin plugin;
    RawrXD::Developer::PluginContext context;
    EXPECT_TRUE(plugin.Initialize(context));
}

TEST(MyPluginTest, GetTools) {
    MyPlugin plugin;
    auto tools = plugin.GetTools();
    EXPECT_EQ(tools.size(), 1);
    EXPECT_EQ(tools[0].name, "my_custom_tool");
}
```

### Integration Tests

```bash
# Run plugin tests
rawrxd-cli test --plugin=MyPlugin

# Run with coverage
rawrxd-cli test --plugin=MyPlugin --coverage
```

---

## Publishing Plugins

### Package Structure

```
MyPlugin-1.0.0/
├── manifest.json
├── MyPlugin.dll
├── README.md
├── LICENSE
└── resources/
    └── icon.png
```

### manifest.json

```json
{
    "id": "com.example.myplugin",
    "name": "My Plugin",
    "version": "1.0.0",
    "description": "A sample plugin",
    "author": "Your Name",
    "license": "MIT",
    "homepage": "https://example.com",
    "repository": "https://github.com/example/myplugin",
    "api_version": 1,
    "capabilities": ["TOOL_PROVIDER"],
    "files": ["MyPlugin.dll"],
    "resources": ["resources/icon.png"]
}
```

### Publish Commands

```bash
# Package plugin
rawrxd-cli plugin package ./MyPlugin-1.0.0

# Validate package
rawrxd-cli plugin validate MyPlugin-1.0.0.rawr

# Publish to registry
rawrxd-cli plugin publish MyPlugin-1.0.0.rawr --registry=https://plugins.rawrxd.io
```

---

## Best Practices

### Error Handling

```cpp
bool MyPlugin::Initialize(const PluginContext& context) {
    try {
        // Initialization code
        return true;
    } catch (const std::exception& e) {
        context.log_callback("ERROR", std::string("Initialization failed: ") + e.what());
        return false;
    }
}
```

### Resource Management

```cpp
class MyPlugin : public IPlugin {
    std::unique_ptr<MyResource> resource_;
    
public:
    bool Initialize(const PluginContext& context) override {
        resource_ = std::make_unique<MyResource>();
        return resource_->Initialize();
    }
    
    void Shutdown() override {
        resource_.reset();  // Automatic cleanup
    }
};
```

### Thread Safety

```cpp
class ThreadSafePlugin : public IPlugin {
    std::mutex mutex_;
    std::atomic<bool> running_{false};
    
public:
    std::string Generate(const std::string& prompt) {
        std::lock_guard<std::mutex> lock(mutex_);
        // Thread-safe operation
        return result;
    }
};
```

### Configuration

```cpp
bool MyPlugin::OnConfigChanged(const std::string& key, const std::string& value) {
    if (key == "myplugin.timeout") {
        timeout_ = std::stoi(value);
        return true;
    }
    return false;
}
```

---

## Troubleshooting

### Common Issues

#### Plugin Not Loading

- Check API version compatibility
- Verify all dependencies are present
- Check plugin logs for errors

#### Tool Not Appearing

- Verify tool is registered in GetTools()
- Check tool name is unique
- Ensure capability includes TOOL_PROVIDER

#### Memory Leaks

- Use smart pointers
- Implement proper Shutdown()
- Run with AddressSanitizer

### Debug Commands

```bash
# List loaded plugins
rawrxd-cli plugin list

# Get plugin info
rawrxd-cli plugin info MyPlugin

# Check plugin health
rawrxd-cli plugin health MyPlugin

# Reload plugin
rawrxd-cli plugin reload MyPlugin
```

---

## Examples

### Example 1: Calculator Tool

```cpp
class CalculatorPlugin : public IPlugin {
public:
    std::vector<ToolDefinition> GetTools() override {
        return {
            {
                "calculator",
                "Perform mathematical calculations",
                "Math",
                R"({"type": "object", "properties": {"expression": {"type": "string"}}})",
                R"({"type": "number"})",
                [](const std::string& input) {
                    // Parse and evaluate expression
                    double result = EvaluateExpression(input);
                    return std::to_string(result);
                },
                std::chrono::seconds(5),
                false, false, {}
            }
        };
    }
};
```

### Example 2: Custom Model Backend

```cpp
class ONNXBackend : public IModelBackend {
    Ort::Env env_;
    Ort::Session session_;
    
public:
    bool Initialize(const std::unordered_map<std::string, std::string>& config) override {
        env_ = Ort::Env(ORT_LOGGING_LEVEL_WARNING, "ONNX");
        Ort::SessionOptions options;
        session_ = Ort::Session(env_, config.at("model_path").c_str(), options);
        return true;
    }
    
    std::string Generate(const std::string& prompt,
                         const std::unordered_map<std::string, std::string>& params) override {
        // Run ONNX inference
        // ...
        return result;
    }
};
```

---

## API Reference

See `include/rawrxd/developer/PluginSDK.hpp` for complete API documentation.

---

*Guide Version: 1.0.0*  
*Last Updated: 2026-07-13*
