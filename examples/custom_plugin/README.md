# Custom Plugin Example

This example demonstrates how to create a custom plugin for RawrXD that provides additional tools to the agent system.

## What This Plugin Does

This plugin provides two custom tools:

1. **myplugin_echo** - Echoes back text with optional formatting
2. **myplugin_calculate** - Performs basic mathematical calculations

## Building

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

## Installing

```bash
# Install to RawrXD plugin directory
rawrxd-cli plugin install ./plugins/MyPlugin.dll

# Or copy manually
cp ./plugins/MyPlugin.dll $RAWRXD_HOME/plugins/
```

## Verifying

```bash
# List installed plugins
rawrxd-cli plugin list

# Check plugin status
rawrxd-cli plugin info MyPlugin

# Test the tools
rawrxd-cli tool test myplugin_echo --input='{"text": "Hello"}'
rawrxd-cli tool test myplugin_calculate --input='{"expression": "2 + 2"}'
```

## Plugin Structure

```
MyPlugin.hpp          # Main plugin implementation
CMakeLists.txt        # Build configuration
README.md            # This file
```

## Key Concepts

### Plugin Manifest

Every plugin must provide a manifest with metadata:

```cpp
PluginManifest GetManifest() const override {
    return {
        "com.example.myplugin",           // Unique ID
        "My Custom Plugin",               // Display name
        "1.0.0",                          // Version
        "Description...",                 // Description
        "Author Name",                    // Author
        "MIT",                            // License
        "https://example.com",            // Homepage
        "https://github.com/...",         // Repository
        PLUGIN_API_VERSION,               // API version
        {"1.0.0"},                        // Compatible RawrXD versions
        {PluginCapability::TOOL_PROVIDER} // Capabilities
    };
}
```

### Tool Definition

Tools are defined with JSON schemas:

```cpp
ToolDefinition CreateEchoTool() {
    return {
        "myplugin_echo",                    // Tool name
        "Echoes back text",                // Description
        "Utility",                          // Category
        R"({"type": "object", ...})",      // Input schema
        R"({"type": "string"})",            // Output schema
        [](const std::string& input) {     // Handler function
            // Process input and return result
            return "{\"result\": \"...\"}";
        },
        std::chrono::seconds(5),           // Timeout
        false,                              // Is async
        false,                              // Requires confirmation
        {}                                  // Required permissions
    };
}
```

### Export Macro

The plugin must be exported using the provided macro:

```cpp
RAWRXD_DEFINE_PLUGIN(MyPlugin)
```

## Next Steps

- Add more tools to the plugin
- Implement additional capabilities (e.g., MODEL_PROVIDER)
- Add configuration support
- Implement proper error handling
- Add unit tests

## Resources

- [Plugin Development Guide](../../docs/developer/PLUGIN_DEVELOPMENT_GUIDE.md)
- [RawrXD API Reference](../../docs/integration/API_REFERENCE_COMPLETE.md)
