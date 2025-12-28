# MASM Component Integration Guide

## Overview
This guide explains how to integrate the ported MASM components into your existing Qt IDE.

## Components

### 1. StreamingTokenManager
Manages real-time token streaming with thinking UI support.

`cpp
StreamingTokenManager* manager = new StreamingTokenManager(parent);
manager->initialize(chatPanel, richEdit);
manager->startCall("gpt-4");
manager->onToken("response text");
manager->finishCall(true);
`

### 2. ModelRouter
Model selection with mode flags and fallback policy.

`cpp
ModelRouter* router = new ModelRouter(parent);
router->setMode(ModelRouter::MODE_MAX | ModelRouter::MODE_SEARCH_WEB);
QString model = router->selectPrimaryModel();
`

### 3. ToolRegistry
JSON-based tool calling interface.

`cpp
ToolRegistry* registry = new ToolRegistry(parent);
registry->registerBuiltInTools();
QJsonObject result = registry->executeTool("file_read", params);
`

### 4. AgenticPlanner
Multi-step planning, execution, and review engine.

`cpp
AgenticPlanner* planner = new AgenticPlanner(registry, router, parent);
planner->executeTask("Fix the bug in main.cpp");
`

### 5. CommandPalette
Cmd-K style command palette with 50+ commands.

`cpp
CommandPalette* palette = new CommandPalette(mainWindow);
palette->showPalette();  // Triggered by Ctrl+Shift+P
`

### 6. DiffViewer
Side-by-side diff viewer with accept/reject.

`cpp
DiffViewer* viewer = new DiffViewer(mainWindow);
viewer->showDiff(filePath, original, modified);
`

## Integration Manager

Use MASMIntegrationManager for one-step integration:

`cpp
MASMIntegrationManager* manager = new MASMIntegrationManager(mainWindow);
manager->initialize();

// All components are now wired up and ready to use
`

## Keyboard Shortcuts

- **Ctrl+Shift+P**: Open Command Palette
- **Ctrl+T**: Toggle Thinking UI
- **Ctrl+Enter**: Execute selected task

## Menu Integration

Components are automatically added to the "AI" menu:
- Execute Agentic Task
- Model Modes (Max, Search Web, Turbo)
- Toggle Thinking UI
- Tools

## Building

Include in your CMakeLists.txt:

`cmake
include(CMakeLists_masm_components.txt)
target_link_libraries(your_app ${MASM_LIBRARIES})
`

## Testing

Run component tests:

`powershell
.\run_masm_port_tests.bat
`

## Architecture

All components follow a Qt signal/slot pattern for loose coupling:

- StreamingTokenManager emits tokenized output
- ModelRouter emits mode changes
- ToolRegistry emits tool execution results
- AgenticPlanner emits state changes and logs
- CommandPalette emits command selection
- DiffViewer emits accept/reject decisions

## File Structure

`
src/
├── streaming_token_manager.h/cpp
├── model_router.h/cpp
├── tool_registry.h
├── simple_tool_registry.cpp
├── agentic_planner.h/cpp
├── command_palette.h/cpp
├── diff_viewer.h/cpp
├── masm_integration_manager.h/cpp
└── component_test.cpp
`
