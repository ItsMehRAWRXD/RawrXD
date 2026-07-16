# Plugin Examples
## Sovereign IDE Examples Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

Example plugins demonstrating the Sovereign IDE plugin API.

---

## Example 1: Hello World Plugin

### Plugin Structure

```
HelloPlugin/
├── CMakeLists.txt
├── src/
│   └── HelloPlugin.cpp
├── include/
│   └── HelloPlugin.h
└── manifest.json
```

### Implementation

```cpp
// HelloPlugin.h
#pragma once
#include <Sovereign/Plugin.h>

class HelloPlugin : public Plugin {
public:
    void OnLoad() override;
    void OnUnload() override;
    void OnCommand(const std::string& command);
};

// HelloPlugin.cpp
#include "HelloPlugin.h"

void HelloPlugin::OnLoad() {
    // Register command
    CommandRegistry::Register("hello", [](const Args& args) {
        std::cout << "Hello from plugin!" << std::endl;
        return true;
    });
    
    // Subscribe to events
    EventManager::Subscribe(EVENT_BINARY_LOADED, [](Event* e) {
        auto binary = e->GetBinary();
        LogInfo("Binary loaded: %s", binary->GetName());
    });
}

void HelloPlugin::OnUnload() {
    LogInfo("HelloPlugin unloaded");
}

SOVEREIGN_REGISTER_PLUGIN(HelloPlugin);
```

### CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.16)
project(HelloPlugin)

find_package(SovereignSDK REQUIRED)

add_library(HelloPlugin SHARED
    src/HelloPlugin.cpp
)

target_link_libraries(HelloPlugin
    Sovereign::Plugin
)
```

---

## Example 2: Analysis Plugin

### Custom Analysis Plugin

```cpp
class CustomAnalysisPlugin : public AnalysisPlugin {
public:
    AnalysisResult Analyze(BinaryHandle binary) override {
        AnalysisResult result;
        
        // Custom analysis logic
        auto entropy = CalculateEntropy(binary);
        if (entropy > 7.0) {
            result.AddFinding("High entropy detected", SUSPICIOUS);
        }
        
        // Check for patterns
        auto patterns = FindPatterns(binary);
        for (const auto& pattern : patterns) {
            result.AddFinding(pattern.description, pattern.severity);
        }
        
        return result;
    }
    
private:
    float CalculateEntropy(BinaryHandle binary) {
        // Implementation
        return 0.0f;
    }
    
    std::vector<Pattern> FindPatterns(BinaryHandle binary) {
        // Implementation
        return {};
    }
};

SOVEREIGN_REGISTER_ANALYSIS_PLUGIN(CustomAnalysisPlugin);
```

---

## Example 3: UI Plugin

### Custom Panel Plugin

```cpp
class CustomPanelPlugin : public UIPlugin {
public:
    void OnLoad() override {
        // Create panel
        auto panel = PanelManager::CreatePanel("CustomPanel");
        panel->SetTitle("My Custom Panel");
        
        // Add content
        auto content = CreatePanelContent();
        panel->SetContent(content);
        
        // Dock panel
        PanelManager::DockPanel(panel, DockArea::Right);
    }
    
private:
    Widget* CreatePanelContent() {
        auto container = new Container();
        
        auto label = new Label("Hello from custom panel!");
        container->AddChild(label);
        
        auto button = new Button("Click Me");
        button->OnClick([]() {
            MessageBox::Show("Button clicked!");
        });
        container->AddChild(button);
        
        return container;
    }
};

SOVEREIGN_REGISTER_UI_PLUGIN(CustomPanelPlugin);
```

---

## Summary

Plugin Examples provides:

- ✅ **Hello world plugin**
- ✅ **Analysis plugin**
- ✅ **UI plugin**
- ✅ **Complete examples**
- ✅ **Build configuration**

**Status:** ✅ Complete
