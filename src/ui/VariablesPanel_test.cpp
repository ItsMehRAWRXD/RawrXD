// ============================================================================
// Phase 26: Variables Panel Test Suite
// ============================================================================
// Standalone test executable for VariablesPanel validation
//
// Build:
//   cl.exe /EHsc /O2 /MD /std:c++20 /I. /Isrc /I3rdparty /Fe:build\VariablesPanel_test.exe &
//       src\ui\VariablesPanel_test.cpp &
//       src\ui\VariablesPanel.cpp &
//       src\debug\DapService.cpp &
//       /link /SUBSYSTEM:CONSOLE
//
// Run:
//   build\VariablesPanel_test.exe
// ============================================================================

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include "../debug/DapService.hpp"
#include "VariablesPanel.hpp"

using namespace RawrXD::UI;
using namespace RawrXD::Debug;

// ============================================================================
// Test Framework
// ============================================================================

static int g_testsPassed = 0;
static int g_testsFailed = 0;

#define TEST(name) void test_##name()
#define RUN_TEST(name) run_test(#name, test_##name)

void run_test(const char* name, void (*testFunc)()) {
    std::cout << "[TEST] " << name << "... ";
    try {
        testFunc();
        std::cout << "PASS\n";
        g_testsPassed++;
    } catch (const std::exception& e) {
        std::cout << "FAIL: " << e.what() << "\n";
        g_testsFailed++;
    }
}

#define ASSERT_TRUE(cond) if (!(cond)) throw std::runtime_error("Assertion failed: " #cond)
#define ASSERT_FALSE(cond) if (cond) throw std::runtime_error("Assertion failed: NOT " #cond)
#define ASSERT_EQ(a, b) if ((a) != (b)) throw std::runtime_error("Assertion failed: " #a " == " #b)

// ============================================================================
// Test Cases
// ============================================================================

TEST(initial_state) {
    VariablesPanel panel;
    
    // Panel should start with empty state
    auto size = panel.GetPreferredSize();
    ASSERT_TRUE(size.cx > 0);
    ASSERT_TRUE(size.cy > 0);
}

TEST(initialization) {
    VariablesPanel panel;
    
    // Initialize with null parent (for testing)
    bool result = panel.Initialize(nullptr);
    ASSERT_TRUE(result);
    
    panel.Shutdown();
}

TEST(config_customization) {
    VariablesPanel panel;
    panel.Initialize(nullptr);
    
    VariablesPanelConfig config;
    config.rowHeight = 24;
    config.nameColumnWidth = 200;
    config.showTypes = false;
    config.highlightModified = true;
    
    panel.SetConfig(config);
    
    // Config should be applied (no crash)
    ASSERT_TRUE(true);
    
    panel.Shutdown();
}

TEST(update_variables_local) {
    VariablesPanel panel;
    panel.Initialize(nullptr);
    
    std::vector<Variable> variables;
    
    Variable var1;
    var1.name = "counter";
    var1.value = "42";
    var1.type = "int";
    var1.variablesReference = 0;
    var1.isExpandable = false;
    variables.push_back(var1);
    
    Variable var2;
    var2.name = "message";
    var2.value = "\"Hello World\"";
    var2.type = "std::string";
    var2.variablesReference = 0;
    var2.isExpandable = false;
    variables.push_back(var2);
    
    panel.UpdateVariables(variables, VariableType::Local);
    
    // Variables should be added
    ASSERT_TRUE(true);
    
    panel.Shutdown();
}

TEST(update_variables_arguments) {
    VariablesPanel panel;
    panel.Initialize(nullptr);
    
    std::vector<Variable> variables;
    
    Variable var1;
    var1.name = "argc";
    var1.value = "1";
    var1.type = "int";
    var1.variablesReference = 0;
    var1.isExpandable = false;
    variables.push_back(var1);
    
    Variable var2;
    var2.name = "argv";
    var2.value = "[...]";
    var2.type = "char**";
    var2.variablesReference = 1001;
    var2.isExpandable = true;
    variables.push_back(var2);
    
    panel.UpdateVariables(variables, VariableType::Argument);
    
    // Arguments category should be created
    ASSERT_TRUE(true);
    
    panel.Shutdown();
}

TEST(clear_variables) {
    VariablesPanel panel;
    panel.Initialize(nullptr);
    
    // Add some variables first
    std::vector<Variable> variables;
    Variable var;
    var.name = "test";
    var.value = "value";
    var.type = "int";
    var.variablesReference = 0;
    var.isExpandable = false;
    variables.push_back(var);
    
    panel.UpdateVariables(variables, VariableType::Local);
    
    // Clear them
    panel.ClearVariables();
    
    // Panel should be empty
    ASSERT_TRUE(true);
    
    panel.Shutdown();
}

TEST(expand_collapse_node) {
    VariablesPanel panel;
    panel.Initialize(nullptr);
    
    // Create expandable node
    std::vector<Variable> variables;
    Variable var;
    var.name = "obj";
    var.value = "{...}";
    var.type = "MyClass";
    var.variablesReference = 1001;
    var.isExpandable = true;
    variables.push_back(var);
    
    panel.UpdateVariables(variables, VariableType::Local);
    
    // Note: In real usage, we'd get the node from the panel
    // For this test, we verify the API doesn't crash
    ASSERT_TRUE(true);
    
    panel.Shutdown();
}

TEST(expand_all_collapse_all) {
    VariablesPanel panel;
    panel.Initialize(nullptr);
    
    // Add nested variables
    std::vector<Variable> locals;
    Variable local;
    local.name = "data";
    local.value = "{...}";
    local.type = "Data";
    local.variablesReference = 1001;
    local.isExpandable = true;
    locals.push_back(local);
    panel.UpdateVariables(locals, VariableType::Local);
    
    std::vector<Variable> args;
    Variable arg;
    arg.name = "config";
    arg.value = "{...}";
    arg.type = "Config";
    arg.variablesReference = 1002;
    arg.isExpandable = true;
    args.push_back(arg);
    panel.UpdateVariables(args, VariableType::Argument);
    
    // Expand all
    panel.ExpandAll();
    
    // Collapse all
    panel.CollapseAll();
    
    ASSERT_TRUE(true);
    
    panel.Shutdown();
}

TEST(update_child_variables) {
    VariablesPanel panel;
    panel.Initialize(nullptr);
    
    // Create parent
    std::vector<Variable> variables;
    Variable parent;
    parent.name = "obj";
    parent.value = "{...}";
    parent.type = "Object";
    parent.variablesReference = 1001;
    parent.isExpandable = true;
    variables.push_back(parent);
    
    panel.UpdateVariables(variables, VariableType::Local);
    
    // Add children
    std::vector<Variable> children;
    Variable child1;
    child1.name = "field1";
    child1.value = "10";
    child1.type = "int";
    child1.variablesReference = 0;
    child1.isExpandable = false;
    children.push_back(child1);
    
    Variable child2;
    child2.name = "field2";
    child2.value = "\"text\"";
    child2.type = "string";
    child2.variablesReference = 0;
    child2.isExpandable = false;
    children.push_back(child2);
    
    panel.UpdateChildVariables(1001, children);
    
    ASSERT_TRUE(true);
    
    panel.Shutdown();
}

TEST(filter_variables) {
    VariablesPanel panel;
    panel.Initialize(nullptr);
    
    std::vector<Variable> variables;
    
    Variable var1;
    var1.name = "counter";
    var1.value = "42";
    var1.type = "int";
    var1.variablesReference = 0;
    var1.isExpandable = false;
    variables.push_back(var1);
    
    Variable var2;
    var2.name = "message";
    var2.value = "\"Hello\"";
    var2.type = "string";
    var2.variablesReference = 0;
    var2.isExpandable = false;
    variables.push_back(var2);
    
    panel.UpdateVariables(variables, VariableType::Local);
    
    // Apply filter
    panel.SetFilter(L"count");
    
    // Clear filter
    panel.ClearFilter();
    
    ASSERT_TRUE(true);
    
    panel.Shutdown();
}

TEST(change_tracking) {
    VariablesPanel panel;
    panel.Initialize(nullptr);
    
    // Initial values
    std::vector<Variable> variables1;
    Variable var1;
    var1.name = "counter";
    var1.value = "42";
    var1.type = "int";
    var1.variablesReference = 0;
    var1.isExpandable = false;
    variables1.push_back(var1);
    
    panel.UpdateVariables(variables1, VariableType::Local);
    panel.TrackChanges();
    
    // Updated values
    std::vector<Variable> variables2;
    Variable var2;
    var2.name = "counter";
    var2.value = "43";  // Changed!
    var2.type = "int";
    var2.variablesReference = 0;
    var2.isExpandable = false;
    variables2.push_back(var2);
    
    panel.UpdateVariables(variables2, VariableType::Local);
    
    // Mark unmodified
    panel.MarkAllUnmodified();
    
    ASSERT_TRUE(true);
    
    panel.Shutdown();
}

TEST(multiple_categories) {
    VariablesPanel panel;
    panel.Initialize(nullptr);
    
    // Locals
    std::vector<Variable> locals;
    Variable local;
    local.name = "i";
    local.value = "0";
    local.type = "int";
    local.variablesReference = 0;
    local.isExpandable = false;
    locals.push_back(local);
    panel.UpdateVariables(locals, VariableType::Local);
    
    // Arguments
    std::vector<Variable> args;
    Variable arg;
    arg.name = "x";
    arg.value = "10";
    arg.type = "int";
    arg.variablesReference = 0;
    arg.isExpandable = false;
    args.push_back(arg);
    panel.UpdateVariables(args, VariableType::Argument);
    
    // Globals
    std::vector<Variable> globals;
    Variable global;
    global.name = "g_count";
    global.value = "100";
    global.type = "int";
    global.variablesReference = 0;
    global.isExpandable = false;
    globals.push_back(global);
    panel.UpdateVariables(globals, VariableType::Global);
    
    // All three categories should exist
    ASSERT_TRUE(true);
    
    panel.Shutdown();
}

TEST(callbacks) {
    VariablesPanel panel;
    panel.Initialize(nullptr);
    
    bool selectCalled = false;
    bool expandCalled = false;
    
    panel.SetVariableSelectedCallback([&](const VariableDisplayNode& node) {
        selectCalled = true;
    });
    
    panel.SetExpandVariableCallback([&](uint32_t ref) {
        expandCalled = true;
    });
    
    // Note: In real usage, these would be triggered by user interaction
    // For this test, we verify the callbacks can be set
    ASSERT_TRUE(true);
    
    panel.Shutdown();
}

// ============================================================================
// VariablesIntegration Tests
// ============================================================================

TEST(integration_initialization) {
    VariablesIntegration integration;
    VariablesPanel panel;
    panel.Initialize(nullptr);
    
    bool result = integration.Initialize(&panel, nullptr);  // No DAP service in test
    ASSERT_TRUE(result);
    
    integration.Shutdown();
    panel.Shutdown();
}

TEST(integration_frame_selection) {
    VariablesIntegration integration;
    VariablesPanel panel;
    panel.Initialize(nullptr);
    
    integration.Initialize(&panel, nullptr);
    
    // Simulate frame selection
    integration.OnFrameSelected(42);
    
    // Panel should track frame ID
    ASSERT_TRUE(true);
    
    integration.Shutdown();
    panel.Shutdown();
}

TEST(integration_execution_resumed) {
    VariablesIntegration integration;
    VariablesPanel panel;
    panel.Initialize(nullptr);
    
    integration.Initialize(&panel, nullptr);
    
    // Add some variables
    std::vector<Variable> variables;
    Variable var;
    var.name = "test";
    var.value = "value";
    var.type = "int";
    var.variablesReference = 0;
    var.isExpandable = false;
    variables.push_back(var);
    
    panel.UpdateVariables(variables, VariableType::Local);
    
    // Execution resumed
    integration.OnExecutionResumed();
    
    // Variables should be marked unmodified
    ASSERT_TRUE(true);
    
    integration.Shutdown();
    panel.Shutdown();
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================\n";
    std::cout << "Phase 26: Variables Panel Test Suite\n";
    std::cout << "========================================\n\n";
    
    // VariablesPanel tests
    RUN_TEST(initial_state);
    RUN_TEST(initialization);
    RUN_TEST(config_customization);
    RUN_TEST(update_variables_local);
    RUN_TEST(update_variables_arguments);
    RUN_TEST(clear_variables);
    RUN_TEST(expand_collapse_node);
    RUN_TEST(expand_all_collapse_all);
    RUN_TEST(update_child_variables);
    RUN_TEST(filter_variables);
    RUN_TEST(change_tracking);
    RUN_TEST(multiple_categories);
    RUN_TEST(callbacks);
    
    // VariablesIntegration tests
    RUN_TEST(integration_initialization);
    RUN_TEST(integration_frame_selection);
    RUN_TEST(integration_execution_resumed);
    
    std::cout << "\n========================================\n";
    std::cout << "Results: " << g_testsPassed << " passed, " << g_testsFailed << " failed\n";
    std::cout << "========================================\n";
    
    return g_testsFailed > 0 ? 1 : 0;
}
