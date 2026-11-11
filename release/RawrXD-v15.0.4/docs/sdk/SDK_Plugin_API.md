# SDK Plugin API
## Sovereign IDE SDK Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

The Plugin API enables third-party developers to extend the Sovereign IDE with custom functionality. Plugins can add new analysis modules, UI components, and integrations.

### Key Characteristics

| Attribute | Value |
|-----------|-------|
| **API Version** | 1.0.0 |
| **Language** | C++17 / Python 3.9+ |
| **Plugin Types** | 5 |
| **Max Plugins** | Unlimited |
| **Hot Reload** | Yes |

---

## Plugin Types

| Type | Description | Example |
|------|-------------|---------|
| `ANALYSIS` | Analysis module | Custom disassembler |
| `UI` | UI component | Custom panel |
| `INTEGRATION` | External integration | Git connector |
| `LANGUAGE` | Language support | New language parser |
| `TOOL` | External tool | Custom debugger |

---

## API Reference

```cpp
// Plugin lifecycle
SOVEREIGN_SDK_API PluginResult Plugin_Initialize(PluginContext* ctx);
SOVEREIGN_SDK_API PluginResult Plugin_Shutdown();
SOVEREIGN_SDK_API PluginResult Plugin_Enable();
SOVEREIGN_SDK_API PluginResult Plugin_Disable();

// Registration
SOVEREIGN_SDK_API PluginResult Plugin_RegisterCommand(
    const char* name, CommandHandler handler);
SOVEREIGN_SDK_API PluginResult Plugin_RegisterPanel(
    const char* name, PanelFactory factory);
SOVEREIGN_SDK_API PluginResult Plugin_RegisterAnalysis(
    const char* name, AnalysisProvider provider);

// Events
SOVEREIGN_SDK_API PluginResult Plugin_SubscribeEvent(
    EventType type, EventHandler handler);
SOVEREIGN_SDK_API PluginResult Plugin_UnsubscribeEvent(
    EventType type, EventHandler handler);
```

---

## Example Plugin

```cpp
// my_plugin.cpp
#include <SovereignSDK.h>

class MyAnalysisPlugin : public AnalysisPlugin {
public:
    PluginResult Initialize(PluginContext* ctx) override {
        // Register analysis provider
        Plugin_RegisterAnalysis("MyAnalysis", &MyAnalysisProvider);
        
        // Subscribe to events
        Plugin_SubscribeEvent(EVENT_BINARY_LOADED, &OnBinaryLoaded);
        
        return PLUGIN_SUCCESS;
    }
    
    AnalysisResult Analyze(BinaryHandle binary) override {
        // Perform custom analysis
        auto result = CustomAnalysis(binary);
        return result;
    }
    
private:
    static void OnBinaryLoaded(Event* event) {
        auto binary = event->GetBinary();
        LogInfo("Binary loaded: %s", binary->GetName());
    }
};

// Export plugin entry point
extern "C" SOVEREIGN_SDK_API Plugin* CreatePlugin() {
    return new MyAnalysisPlugin();
}
```

---

## Testing

```cpp
TEST(PluginAPI, RegisterCommand) {
    auto result = Plugin_RegisterCommand("TestCommand", &TestHandler);
    EXPECT_EQ(result, PLUGIN_SUCCESS);
}
```

---

## Summary

The SDK Plugin API provides:

- ✅ **5 plugin types**
- ✅ **C++ and Python support**
- ✅ **Hot reload**
- ✅ **Event system**
- ✅ **Unlimited plugins**

**Status:** ✅ Complete
