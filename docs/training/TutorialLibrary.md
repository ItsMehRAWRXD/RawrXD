# Sovereign IDE - Tutorial Library
## Training Curriculum

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** ✅ Complete

---

## Table of Contents

1. [Overview](#overview)
2. [Tutorial 1: Hello SEG](#tutorial-1-hello-seg)
3. [Tutorial 2: Creating a MoE Expert](#tutorial-2-creating-a-moe-expert)
4. [Tutorial 3: Binary Analysis](#tutorial-3-binary-analysis)
5. [Tutorial 4: SDK Extension](#tutorial-4-sdk-extension)
6. [Tutorial 5: Agentic Workflow](#tutorial-5-agentic-workflow)
7. [Tutorial 6: Custom Panel](#tutorial-6-custom-panel)
8. [Advanced Tutorials](#advanced-tutorials)

---

## Overview

This library contains hands-on tutorials for learning the Sovereign IDE.

### Tutorial Levels

| Level | Description | Prerequisites |
|-------|-------------|---------------|
| **Beginner** | Basic concepts | C/C++ knowledge |
| **Intermediate** | System integration | Completed beginner |
| **Advanced** | Complex features | Completed intermediate |

---

## Tutorial 1: Hello SEG

**Level:** Beginner  
**Time:** 30 minutes  
**Goal:** Create and execute your first SEG node

### Step 1: Create Node Definition

```cpp
// tutorials/hello_seg/hello_node.h
#pragma once
#include "sovereign/seg.h"

namespace tutorials {

class HelloNode : public seg::Node {
public:
    HelloNode();
    
    // Node interface
    bool Initialize(const seg::NodeConfig& config) override;
    seg::NodeResult Execute(const seg::ExecutionContext& ctx) override;
    void Shutdown() override;
    
    // Node metadata
    static const char* GetName() { return "HelloNode"; }
    static const char* GetDescription() { return "Prints hello message"; }
    
private:
    std::string m_message;
};

} // namespace tutorials
```

### Step 2: Implement Node

```cpp
// tutorials/hello_seg/hello_node.cpp
#include "hello_node.h"
#include <iostream>

namespace tutorials {

HelloNode::HelloNode() = default;

bool HelloNode::Initialize(const seg::NodeConfig& config) {
    // Get message from config
    auto msgParam = config.GetParameter("message");
    if (msgParam) {
        m_message = msgParam->AsString();
    } else {
        m_message = "Hello from SEG!";
    }
    return true;
}

seg::NodeResult HelloNode::Execute(const seg::ExecutionContext& ctx) {
    std::cout << m_message << std::endl;
    
    // Set output
    seg::NodeResult result;
    result.SetOutput("status", "success");
    return result;
}

void HelloNode::Shutdown() {
    // Cleanup
}

} // namespace tutorials
```

### Step 3: Register Node

```cpp
// tutorials/hello_seg/register.cpp
#include "hello_node.h"
#include "sovereign/seg_registry.h"

namespace tutorials {

// Registration function
void RegisterHelloNode() {
    seg::Registry::RegisterNodeType(
        HelloNode::GetName(),
        []() -> std::unique_ptr<seg::Node> {
            return std::make_unique<HelloNode>();
        }
    );
}

} // namespace tutorials
```

### Step 4: Build and Test

```cmake
# tutorials/hello_seg/CMakeLists.txt
add_library(tutorial_hello_seg STATIC
    hello_node.cpp
    register.cpp
)

target_link_libraries(tutorial_hello_seg
    sovereign::seg
)

# Test
add_executable(test_hello_seg test_hello_seg.cpp)
target_link_libraries(test_hello_seg tutorial_hello_seg)
```

```cpp
// tutorials/hello_seg/test_hello_seg.cpp
#include "hello_node.h"
#include <cassert>

int main() {
    using namespace tutorials;
    
    // Create node
    HelloNode node;
    
    // Initialize
    seg::NodeConfig config;
    config.SetParameter("message", "Hello, World!");
    assert(node.Initialize(config));
    
    // Execute
    seg::ExecutionContext ctx;
    auto result = node.Execute(ctx);
    
    // Verify
    assert(result.GetOutput("status").AsString() == "success");
    
    // Shutdown
    node.Shutdown();
    
    std::cout << "Test passed!" << std::endl;
    return 0;
}
```

### Expected Output

```
Hello, World!
Test passed!
```

---

## Tutorial 2: Creating a MoE Expert

**Level:** Beginner  
**Time:** 45 minutes  
**Goal:** Create a custom MoE expert

### Step 1: Define Expert

```cpp
// tutorials/hello_moe/reverse_expert.h
#pragma once
#include "sovereign/moe.h"

namespace tutorials {

// Expert that reverses strings
class ReverseExpert : public moe::Expert {
public:
    ReverseExpert();
    
    // Expert interface
    bool Initialize(const moe::ExpertConfig& config) override;
    moe::ExpertResult Process(const moe::ExpertInput& input) override;
    float CalculateConfidence(const moe::ExpertInput& input) override;
    
    // Metadata
    static const char* GetName() { return "ReverseExpert"; }
    static const char* GetDomain() { return "string_manipulation"; }
    
private:
    bool CanProcess(const std::string& task);
};

} // namespace tutorials
```

### Step 2: Implement Expert

```cpp
// tutorials/hello_moe/reverse_expert.cpp
#include "reverse_expert.h"
#include <algorithm>

namespace tutorials {

ReverseExpert::ReverseExpert() = default;

bool ReverseExpert::Initialize(const moe::ExpertConfig& config) {
    return true;
}

float ReverseExpert::CalculateConfidence(const moe::ExpertInput& input) {
    auto task = input.GetTask();
    
    // High confidence for reverse-related tasks
    if (task.find("reverse") != std::string::npos ||
        task.find("backward") != std::string::npos) {
        return 0.95f;
    }
    
    // Medium confidence for string tasks
    if (task.find("string") != std::string::npos) {
        return 0.5f;
    }
    
    return 0.1f;
}

moe::ExpertResult ReverseExpert::Process(const moe::ExpertInput& input) {
    moe::ExpertResult result;
    
    auto text = input.GetParameter("text").AsString();
    
    // Reverse the string
    std::reverse(text.begin(), text.end());
    
    result.SetOutput("result", text);
    result.SetConfidence(1.0f);
    
    return result;
}

} // namespace tutorials
```

### Step 3: Register and Test

```cpp
// tutorials/hello_moe/main.cpp
#include "reverse_expert.h"
#include "sovereign/moe_router.h"
#include <iostream>

int main() {
    using namespace tutorials;
    
    // Create router
    moe::Router router;
    router.Initialize({});
    
    // Register expert
    router.RegisterExpert(std::make_unique<ReverseExpert>());
    
    // Create input
    moe::ExpertInput input;
    input.SetTask("reverse this string");
    input.SetParameter("text", "Hello, SEG!");
    
    // Route to expert
    auto result = router.Route(input);
    
    // Output result
    std::cout << "Original: Hello, SEG!" << std::endl;
    std::cout << "Reversed: " << result.GetOutput("result").AsString() << std::endl;
    
    return 0;
}
```

### Expected Output

```
Original: Hello, SEG!
Reversed: !GES ,olleH
```

---

## Tutorial 3: Binary Analysis

**Level:** Intermediate  
**Time:** 60 minutes  
**Goal:** Analyze a binary and extract information

### Step 1: Load Binary

```cpp
// tutorials/binary_analysis/analyze.cpp
#include "sovereign/binary_loader.h"
#include "sovereign/disassembler.h"
#include "sovereign/cfg.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>" << std::endl;
        return 1;
    }
    
    // Load binary
    binary::Loader loader;
    if (!loader.Load(argv[1])) {
        std::cerr << "Failed to load binary" << std::endl;
        return 1;
    }
    
    std::cout << "Binary loaded successfully" << std::endl;
    std::cout << "Architecture: " << loader.GetArchitecture() << std::endl;
    std::cout << "Entry point: 0x" << std::hex << loader.GetEntryPoint() << std::endl;
    
    // Get sections
    auto sections = loader.GetSections();
    std::cout << "Sections: " << sections.size() << std::endl;
    
    for (const auto& section : sections) {
        std::cout << "  " << section.name 
                  << " [0x" << section.virtualAddress 
                  << " - 0x" << (section.virtualAddress + section.size) 
                  << "]" << std::endl;
    }
    
    return 0;
}
```

### Step 2: Disassemble Function

```cpp
// Disassemble entry point
auto entryPoint = loader.GetEntryPoint();
auto code = loader.ReadCode(entryPoint, 100); // Read 100 bytes

// Create disassembler
disasm::Disassembler disasm;
disasm.Initialize(loader.GetArchitecture());

// Disassemble
auto instructions = disasm.Disassemble(code, entryPoint);

std::cout << "\nEntry point disassembly:" << std::endl;
for (const auto& inst : instructions) {
    std::cout << "0x" << std::hex << inst.address << ": " 
              << inst.mnemonic << " " << inst.operands << std::endl;
}
```

### Step 3: Build CFG

```cpp
// Build CFG for function
cfg::Builder cfgBuilder;
auto graph = cfgBuilder.Build(instructions);

std::cout << "\nControl Flow Graph:" << std::endl;
std::cout << "  Nodes: " << graph.GetNodeCount() << std::endl;
std::cout << "  Edges: " << graph.GetEdgeCount() << std::endl;

// Print basic blocks
for (const auto& node : graph.GetNodes()) {
    std::cout << "\nBlock 0x" << std::hex << node.startAddress << ":" << std::endl;
    for (const auto& inst : node.instructions) {
        std::cout << "    " << inst.mnemonic << " " << inst.operands << std::endl;
    }
}
```

### Step 4: Full Example

See `tutorials/binary_analysis/complete.cpp` for full implementation.

---

## Tutorial 4: SDK Extension

**Level:** Intermediate  
**Time:** 60 minutes  
**Goal:** Create a complete SDK extension

### Step 1: Extension Structure

```
my_extension/
├── CMakeLists.txt
├── extension.cpp
├── extension.h
├── commands.cpp
├── commands.h
└── README.md
```

### Step 2: Extension Header

```cpp
// my_extension/extension.h
#pragma once
#include "sovereign/sdk.h"

namespace my_extension {

class Extension {
public:
    Extension();
    ~Extension();
    
    bool Initialize(SDKHandle sdk);
    void Shutdown();
    
    // Commands
    void RegisterCommands();
    void UnregisterCommands();
    
private:
    SDKHandle m_sdk;
    bool m_initialized;
};

} // namespace my_extension
```

### Step 3: Implement Commands

```cpp
// my_extension/commands.cpp
#include "commands.h"
#include <iostream>

namespace my_extension {

void RegisterCommands(SDKHandle sdk) {
    // Register "MyExtension.Hello" command
    SDK_Command_Register(sdk, "MyExtension.Hello", 
        [](const SDKCommandContext* ctx) {
            std::cout << "Hello from MyExtension!" << std::endl;
            return SDK_SUCCESS;
        }
    );
    
    // Register "MyExtension.Analyze" command
    SDK_Command_Register(sdk, "MyExtension.Analyze",
        [](const SDKCommandContext* ctx) {
            auto target = SDK_Command_GetArgument(ctx, 0);
            std::cout << "Analyzing: " << target << std::endl;
            
            // Use SDK capabilities
            SDK_Capability_Invoke(sdk, "BinaryAnalysis.Analyze",
                { target }, nullptr);
            
            return SDK_SUCCESS;
        }
    );
}

} // namespace my_extension
```

### Step 4: Build Extension

```cmake
# my_extension/CMakeLists.txt
cmake_minimum_required(VERSION 3.25)
project(MyExtension)

find_package(SovereignSDK REQUIRED)

add_library(my_extension SHARED
    extension.cpp
    commands.cpp
)

target_link_libraries(my_extension
    Sovereign::SDK
)

# Install
install(TARGETS my_extension
    DESTINATION extensions
)
```

### Step 5: Test Extension

```cpp
// Test in Sovereign IDE
// Open command palette: Ctrl+Shift+P
// Type: MyExtension.Hello
// Expected: "Hello from MyExtension!" in output
```

---

## Tutorial 5: Agentic Workflow

**Level:** Intermediate  
**Time:** 90 minutes  
**Goal:** Create an autonomous agent workflow

### Step 1: Define Workflow

```cpp
// tutorials/agentic_workflow/analysis_workflow.h
#pragma once
#include "sovereign/agentic.h"

namespace tutorials {

// Workflow that analyzes a binary autonomously
class AnalysisWorkflow : public agentic::Workflow {
public:
    AnalysisWorkflow();
    
    bool Initialize(const agentic::WorkflowConfig& config) override;
    agentic::WorkflowResult Execute(const agentic::Goal& goal) override;
    
private:
    // Workflow steps
    agentic::ActionResult LoadBinary(const std::string& path);
    agentic::ActionResult AnalyzeStructure();
    agentic::ActionResult FindVulnerabilities();
    agentic::ActionResult GenerateReport();
    
    agentic::AgentHandle m_agent;
    SDKHandle m_sdk;
};

} // namespace tutorials
```

### Step 2: Implement Workflow

```cpp
// tutorials/agentic_workflow/analysis_workflow.cpp
#include "analysis_workflow.h"

namespace tutorials {

AnalysisWorkflow::AnalysisWorkflow() = default;

bool AnalysisWorkflow::Initialize(const agentic::WorkflowConfig& config) {
    // Create agent
    agentic::AgentConfig agentConfig;
    agentConfig.name = "AnalysisAgent";
    agentConfig.type = agentic::AgentType::Autonomous;
    agentConfig.capabilities = {
        "BinaryAnalysis.Load",
        "BinaryAnalysis.Disassemble",
        "BinaryAnalysis.CFG",
        "ExploitSurface.Map",
        "Report.Generate"
    };
    
    auto result = SDK_Agentic_RegisterAgent(m_sdk, &agentConfig, &m_agent);
    return result == SDK_SUCCESS;
}

agentic::WorkflowResult AnalysisWorkflow::Execute(const agentic::Goal& goal) {
    agentic::WorkflowResult result;
    
    // Step 1: Load binary
    auto loadResult = LoadBinary(goal.GetTarget());
    if (!loadResult.success) {
        result.SetError("Failed to load binary");
        return result;
    }
    
    // Step 2: Analyze structure
    auto structResult = AnalyzeStructure();
    if (!structResult.success) {
        result.SetError("Failed to analyze structure");
        return result;
    }
    
    // Step 3: Find vulnerabilities
    auto vulnResult = FindVulnerabilities();
    
    // Step 4: Generate report
    auto reportResult = GenerateReport();
    
    // Compile results
    result.SetOutput("vulnerabilities_found", vulnResult.count);
    result.SetOutput("report_path", reportResult.outputPath);
    result.SetSuccess(true);
    
    return result;
}

agentic::ActionResult AnalysisWorkflow::LoadBinary(const std::string& path) {
    // Invoke capability
    SDK_Agentic_InvokeCapability(m_sdk, m_agent, "BinaryAnalysis.Load",
        { path }, nullptr);
    
    return { true, "" };
}

// ... other methods

} // namespace tutorials
```

### Step 3: Run Workflow

```cpp
// tutorials/agentic_workflow/main.cpp
#include "analysis_workflow.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>" << std::endl;
        return 1;
    }
    
    // Initialize SDK
    SDKHandle sdk;
    SDK_Initialize(nullptr, &sdk);
    
    // Create and run workflow
    tutorials::AnalysisWorkflow workflow;
    workflow.Initialize({});
    
    agentic::Goal goal;
    goal.SetTarget(argv[1]);
    goal.SetDescription("Analyze binary for vulnerabilities");
    
    std::cout << "Starting analysis workflow..." << std::endl;
    auto result = workflow.Execute(goal);
    
    if (result.IsSuccess()) {
        std::cout << "Analysis complete!" << std::endl;
        std::cout << "Vulnerabilities found: " 
                  << result.GetOutput("vulnerabilities_found").AsInt() << std::endl;
        std::cout << "Report: " 
                  << result.GetOutput("report_path").AsString() << std::endl;
    } else {
        std::cerr << "Analysis failed: " << result.GetError() << std::endl;
    }
    
    SDK_Shutdown(sdk);
    return 0;
}
```

---

## Tutorial 6: Custom Panel

**Level:** Advanced  
**Time:** 90 minutes  
**Goal:** Create a custom IDE panel

### Step 1: Panel Definition

```cpp
// tutorials/custom_panel/my_panel.h
#pragma once
#include "sovereign/gui/panel.h"
#include "sovereign/sdk.h"

namespace tutorials {

class MyPanel : public gui::Panel {
public:
    MyPanel();
    ~MyPanel() override;
    
    // Panel interface
    bool Initialize(SDKHandle sdk) override;
    void Shutdown() override;
    void Render() override;
    
    // Panel metadata
    static const char* GetName() { return "MyPanel"; }
    static const char* GetTitle() { return "My Custom Panel"; }
    
private:
    void RenderToolbar();
    void RenderContent();
    void RenderStatusBar();
    
    SDKHandle m_sdk;
    std::string m_content;
    bool m_initialized;
};

} // namespace tutorials
```

### Step 2: Panel Implementation

```cpp
// tutorials/custom_panel/my_panel.cpp
#include "my_panel.h"
#include <imgui.h>

namespace tutorials {

MyPanel::MyPanel() : m_sdk(nullptr), m_initialized(false) {}

MyPanel::~MyPanel() {
    if (m_initialized) {
        Shutdown();
    }
}

bool MyPanel::Initialize(SDKHandle sdk) {
    m_sdk = sdk;
    
    // Register panel with IDE
    SDK_GUI_RegisterPanel(m_sdk, GetName(), this);
    
    m_initialized = true;
    return true;
}

void MyPanel::Shutdown() {
    if (m_sdk) {
        SDK_GUI_UnregisterPanel(m_sdk, GetName());
    }
    m_initialized = false;
}

void MyPanel::Render() {
    if (!m_initialized) return;
    
    ImGui::Begin(GetTitle());
    
    RenderToolbar();
    RenderContent();
    RenderStatusBar();
    
    ImGui::End();
}

void MyPanel::RenderToolbar() {
    if (ImGui::Button("Refresh")) {
        // Refresh content
        RefreshContent();
    }
    
    ImGui::SameLine();
    
    if (ImGui::Button("Export")) {
        // Export content
        ExportContent();
    }
}

void MyPanel::RenderContent() {
    ImGui::Text("Content:");
    ImGui::TextWrapped("%s", m_content.c_str());
}

void MyPanel::RenderStatusBar() {
    ImGui::Separator();
    ImGui::Text("Status: Ready");
}

} // namespace tutorials
```

### Step 3: Register Panel

```cpp
// tutorials/custom_panel/register.cpp
#include "my_panel.h"
#include "sovereign/gui/panel_registry.h"

extern "C" {

// Export function called by IDE
SOVEREIGN_EXPORT void RegisterPanels(SDKHandle sdk) {
    auto panel = std::make_unique<tutorials::MyPanel>();
    panel->Initialize(sdk);
    
    // Panel is now managed by IDE
    gui::PanelRegistry::Register(std::move(panel));
}

}
```

---

## Advanced Tutorials

### Tutorial 7: Custom Disassembler

Create a disassembler for a custom architecture.

**Time:** 3 hours  
**Skills:** Assembly, instruction encoding

### Tutorial 8: MoE Expert Training

Train a custom MoE expert with machine learning.

**Time:** 4 hours  
**Skills:** ML, data preparation

### Tutorial 9: Kernel Module

Create a kernel module for the Sovereign runtime.

**Time:** 4 hours  
**Skills:** MASM, kernel internals

### Tutorial 10: Distributed Analysis

Set up distributed analysis across multiple machines.

**Time:** 3 hours  
**Skills:** Networking, distributed systems

---

## Summary

Tutorial library includes:

- ✅ **6 complete tutorials** (Beginner to Advanced)
- ✅ **Step-by-step instructions**
- ✅ **Full code examples**
- ✅ **Expected outputs**
- ✅ **4 advanced tutorials** outlined

**Status:** ✅ Complete

---

*End of Tutorial Library*
