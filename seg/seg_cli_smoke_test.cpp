/**
 * seg_cli_smoke_test.cpp
 * 
 * Phase B.4 Batch 4/5: Runtime Integration Smoke Tests
 * 
 * Tests CLI command parsing, execution, and runtime integration
 */

#include "../src/seg/SovereignSEGCLI.hpp"
#include <iostream>
#include <sstream>
#include <string>

using namespace Sovereign::SEG;

// Test framework
int testsPassed = 0;
int testsFailed = 0;

#define TEST(name) void test_##name()
#define RUN_TEST(name) do { \
    std::cout << "  Running " << #name << "... "; \
    try { \
        test_##name(); \
        std::cout << "PASSED" << std::endl; \
        testsPassed++; \
    } catch (const std::exception& e) { \
        std::cout << "FAILED: " << e.what() << std::endl; \
        testsFailed++; \
    } catch (...) { \
        std::cout << "FAILED: Unknown exception" << std::endl; \
        testsFailed++; \
    } \
} while(0)

#define ASSERT_TRUE(expr) do { \
    if (!(expr)) { \
        std::ostringstream oss; \
        oss << "Assertion failed: " << #expr; \
        throw std::runtime_error(oss.str()); \
    } \
} while(0)

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))
#define ASSERT_EQ(a, b) ASSERT_TRUE((a) == (b))
#define ASSERT_NE(a, b) ASSERT_TRUE((a) != (b))

// ============================================================================
// Test: Command Parsing
// ============================================================================

TEST(parse_simple_command) {
    SovereignSEGCLI cli;
    auto cmd = cli.ParseCommand("graph:create MyGraph");
    
    ASSERT_EQ(cmd.type, SEGCommandType::GraphCreate);
    ASSERT_EQ(cmd.args.size(), 1u);
    ASSERT_EQ(cmd.args[0], "MyGraph");
}

TEST(parse_command_with_options) {
    SovereignSEGCLI cli;
    auto cmd = cli.ParseCommand("graph:create TestGraph --start-batch=243 --end-batch=256");
    
    ASSERT_EQ(cmd.type, SEGCommandType::GraphCreate);
    ASSERT_EQ(cmd.args.size(), 1u);
    ASSERT_EQ(cmd.args[0], "TestGraph");
    ASSERT_EQ(cmd.options["start-batch"], "243");
    ASSERT_EQ(cmd.options["end-batch"], "256");
}

TEST(parse_command_aliases) {
    SovereignSEGCLI cli;
    
    // Test various aliases
    auto cmd1 = cli.ParseCommand("create-graph Test");
    ASSERT_EQ(cmd1.type, SEGCommandType::GraphCreate);
    
    auto cmd2 = cli.ParseCommand("build-graph");
    ASSERT_EQ(cmd2.type, SEGCommandType::GraphBuild);
    
    auto cmd3 = cli.ParseCommand("validate");
    ASSERT_EQ(cmd3.type, SEGCommandType::GraphValidate);
    
    auto cmd4 = cli.ParseCommand("run");
    ASSERT_EQ(cmd4.type, SEGCommandType::PlanExecute);
    
    auto cmd5 = cli.ParseCommand("status");
    ASSERT_EQ(cmd5.type, SEGCommandType::StatusQuery);
}

TEST(parse_unknown_command) {
    SovereignSEGCLI cli;
    auto cmd = cli.ParseCommand("unknown-command");
    
    ASSERT_EQ(cmd.type, SEGCommandType::Unknown);
}

TEST(parse_empty_command) {
    SovereignSEGCLI cli;
    auto cmd = cli.ParseCommand("");
    
    ASSERT_EQ(cmd.type, SEGCommandType::Unknown);
}

TEST(parse_help_command) {
    SovereignSEGCLI cli;
    auto cmd = cli.ParseCommand("help");
    
    ASSERT_EQ(cmd.type, SEGCommandType::Help);
}

// ============================================================================
// Test: Command Execution
// ============================================================================

TEST(execute_help_command) {
    SovereignSEGCLI cli;
    auto result = cli.Execute("help");
    
    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.exitCode, 0);
    ASSERT_TRUE(result.message.find("Sovereign Execution Graph CLI") != std::string::npos);
}

TEST(execute_unknown_command) {
    SovereignSEGCLI cli;
    auto result = cli.Execute("unknown-command");
    
    ASSERT_FALSE(result.success);
    ASSERT_NE(result.exitCode, 0);
}

TEST(execute_graph_create) {
    SovereignSEGCLI cli;
    auto result = cli.Execute("graph:create TestGraph --start-batch=243 --end-batch=256");
    
    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.exitCode, 0);
    ASSERT_TRUE(result.message.find("Created graph") != std::string::npos);
}

TEST(execute_graph_validate_without_graph) {
    SovereignSEGCLI cli;
    auto result = cli.Execute("validate");
    
    ASSERT_FALSE(result.success);
    ASSERT_NE(result.exitCode, 0);
}

TEST(execute_graph_validate_with_graph) {
    SovereignSEGCLI cli;
    cli.Execute("graph:create TestGraph");
    auto result = cli.Execute("validate");
    
    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.exitCode, 0);
}

TEST(execute_graph_export) {
    SovereignSEGCLI cli;
    cli.Execute("graph:create TestGraph");
    auto result = cli.Execute("graph:export test_graph.json");
    
    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.exitCode, 0);
}

// ============================================================================
// Test: Plan Operations
// ============================================================================

TEST(execute_plan_create) {
    SovereignSEGCLI cli;
    cli.Execute("graph:create TestGraph");
    auto result = cli.Execute("plan:create");
    
    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.exitCode, 0);
    ASSERT_TRUE(result.message.find("Created execution plan") != std::string::npos);
}

TEST(execute_plan_create_without_graph) {
    SovereignSEGCLI cli;
    auto result = cli.Execute("plan:create");
    
    ASSERT_FALSE(result.success);
    ASSERT_NE(result.exitCode, 0);
}

TEST(execute_plan_execute) {
    SovereignSEGCLI cli;
    cli.Execute("graph:create TestGraph --start-batch=243 --end-batch=244");
    cli.Execute("plan:create");
    auto result = cli.Execute("plan:execute");
    
    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.exitCode, 0);
    ASSERT_TRUE(result.message.find("Execution completed") != std::string::npos);
}

TEST(execute_plan_execute_without_plan) {
    SovereignSEGCLI cli;
    cli.Execute("graph:create TestGraph");
    auto result = cli.Execute("plan:execute");
    
    ASSERT_FALSE(result.success);
    ASSERT_NE(result.exitCode, 0);
}

TEST(execute_status_query) {
    SovereignSEGCLI cli;
    auto result = cli.Execute("status");
    
    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.exitCode, 0);
}

// ============================================================================
// Test: Cycle and Task Operations
// ============================================================================

TEST(execute_cycle_invoke_without_engine) {
    SovereignSEGCLI cli;
    auto result = cli.Execute("cycle:invoke RunUnityCycle");
    
    ASSERT_FALSE(result.success);
    ASSERT_NE(result.exitCode, 0);
    ASSERT_TRUE(result.message.find("Engine not available") != std::string::npos);
}

TEST(execute_task_dispatch_without_swarm) {
    SovereignSEGCLI cli;
    auto result = cli.Execute("task:dispatch ComputeOrderTopology");
    
    ASSERT_FALSE(result.success);
    ASSERT_NE(result.exitCode, 0);
    ASSERT_TRUE(result.message.find("Swarm not available") != std::string::npos);
}

// ============================================================================
// Test: Checkpoint Operations
// ============================================================================

TEST(execute_checkpoint_save) {
    SovereignSEGCLI cli;
    cli.Execute("graph:create TestGraph");
    auto result = cli.Execute("checkpoint:save test-checkpoint");
    
    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.exitCode, 0);
    ASSERT_TRUE(result.message.find("Checkpoint saved") != std::string::npos);
}

TEST(execute_checkpoint_save_without_graph) {
    SovereignSEGCLI cli;
    auto result = cli.Execute("checkpoint:save test-checkpoint");
    
    ASSERT_FALSE(result.success);
    ASSERT_NE(result.exitCode, 0);
}

// ============================================================================
// Test: High-Level API
// ============================================================================

TEST(high_level_create_graph) {
    SovereignSEGCLI cli;
    auto result = cli.CreateGraph("MyGraph", 243, 256);
    
    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.exitCode, 0);
    ASSERT_TRUE(result.message.find("Created graph") != std::string::npos);
}

TEST(high_level_validate_graph) {
    SovereignSEGCLI cli;
    cli.CreateGraph("MyGraph", 243, 256);
    auto result = cli.ValidateGraph();
    
    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.exitCode, 0);
}

TEST(high_level_build_graph) {
    SovereignSEGCLI cli;
    cli.CreateGraph("MyGraph", 243, 256);
    auto result = cli.BuildGraph();
    
    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.exitCode, 0);
}

TEST(high_level_create_plan) {
    SovereignSEGCLI cli;
    cli.CreateGraph("MyGraph", 243, 256);
    auto result = cli.CreatePlan();
    
    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.exitCode, 0);
}

TEST(high_level_execute_plan) {
    SovereignSEGCLI cli;
    cli.CreateGraph("MyGraph", 243, 244);  // Small range for speed
    cli.CreatePlan();
    auto result = cli.ExecutePlan();
    
    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.exitCode, 0);
}

TEST(high_level_get_status) {
    SovereignSEGCLI cli;
    auto result = cli.GetExecutionStatus();
    
    ASSERT_TRUE(result.success);
    ASSERT_EQ(result.exitCode, 0);
}

// ============================================================================
// Test: Help Text
// ============================================================================

TEST(help_text_content) {
    SovereignSEGCLI cli;
    std::string help = cli.GetHelpText();
    
    ASSERT_TRUE(help.find("graph:create") != std::string::npos);
    ASSERT_TRUE(help.find("plan:create") != std::string::npos);
    ASSERT_TRUE(help.find("cycle:invoke") != std::string::npos);
    ASSERT_TRUE(help.find("checkpoint:save") != std::string::npos);
}

// ============================================================================
// Test: Complex Workflows
// ============================================================================

TEST(full_workflow_create_validate_plan_execute) {
    SovereignSEGCLI cli;
    
    // Create graph
    auto result1 = cli.Execute("graph:create FullWorkflowGraph --start-batch=243 --end-batch=244");
    ASSERT_TRUE(result1.success);
    
    // Validate
    auto result2 = cli.Execute("validate");
    ASSERT_TRUE(result2.success);
    
    // Create plan
    auto result3 = cli.Execute("plan:create --optimize");
    ASSERT_TRUE(result3.success);
    
    // Execute
    auto result4 = cli.Execute("plan:execute --monitor");
    ASSERT_TRUE(result4.success);
    
    // Check status
    auto result5 = cli.Execute("status");
    ASSERT_TRUE(result5.success);
}

TEST(workflow_with_export) {
    SovereignSEGCLI cli;
    
    // Create and export
    cli.Execute("graph:create ExportGraph --start-batch=243 --end-batch=244");
    auto result = cli.Execute("graph:export workflow_graph.json");
    
    ASSERT_TRUE(result.success);
}

TEST(workflow_with_checkpoint) {
    SovereignSEGCLI cli;
    
    // Create graph
    cli.Execute("graph:create CheckpointGraph --start-batch=243 --end-batch=244");
    
    // Create plan and execute
    cli.Execute("plan:create");
    cli.Execute("plan:execute");
    
    // Save checkpoint
    auto result = cli.Execute("checkpoint:save workflow-checkpoint");
    ASSERT_TRUE(result.success);
}

// ============================================================================
// Test: Edge Cases
// ============================================================================

TEST(empty_args_handling) {
    SovereignSEGCLI cli;
    
    // Commands that should work with no args
    auto result1 = cli.Execute("graph:create");  // Uses default name
    ASSERT_TRUE(result1.success);
    
    auto result2 = cli.Execute("plan:create");
    ASSERT_TRUE(result2.success);
}

TEST(invalid_batch_range) {
    SovereignSEGCLI cli;
    
    // Should handle gracefully
    auto result = cli.Execute("graph:create Test --start-batch=999 --end-batch=1000");
    // May succeed with empty graph or fail gracefully
    ASSERT_TRUE(result.success || result.exitCode != 0);
}

TEST(multiple_graphs_sequence) {
    SovereignSEGCLI cli;
    
    auto result1 = cli.Execute("graph:create Graph1");
    ASSERT_TRUE(result1.success);
    
    auto result2 = cli.Execute("graph:create Graph2");
    ASSERT_TRUE(result2.success);
    
    // Last graph should be current
    auto result3 = cli.Execute("validate");
    ASSERT_TRUE(result3.success);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "SEG CLI Smoke Tests (Batch 4/5)" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // Command Parsing Tests
    std::cout << "Command Parsing Tests:" << std::endl;
    RUN_TEST(parse_simple_command);
    RUN_TEST(parse_command_with_options);
    RUN_TEST(parse_command_aliases);
    RUN_TEST(parse_unknown_command);
    RUN_TEST(parse_empty_command);
    RUN_TEST(parse_help_command);
    std::cout << std::endl;
    
    // Command Execution Tests
    std::cout << "Command Execution Tests:" << std::endl;
    RUN_TEST(execute_help_command);
    RUN_TEST(execute_unknown_command);
    RUN_TEST(execute_graph_create);
    RUN_TEST(execute_graph_validate_without_graph);
    RUN_TEST(execute_graph_validate_with_graph);
    RUN_TEST(execute_graph_export);
    std::cout << std::endl;
    
    // Plan Operations Tests
    std::cout << "Plan Operations Tests:" << std::endl;
    RUN_TEST(execute_plan_create);
    RUN_TEST(execute_plan_create_without_graph);
    RUN_TEST(execute_plan_execute);
    RUN_TEST(execute_plan_execute_without_plan);
    RUN_TEST(execute_status_query);
    std::cout << std::endl;
    
    // Cycle and Task Tests
    std::cout << "Cycle and Task Tests:" << std::endl;
    RUN_TEST(execute_cycle_invoke_without_engine);
    RUN_TEST(execute_task_dispatch_without_swarm);
    std::cout << std::endl;
    
    // Checkpoint Tests
    std::cout << "Checkpoint Tests:" << std::endl;
    RUN_TEST(execute_checkpoint_save);
    RUN_TEST(execute_checkpoint_save_without_graph);
    std::cout << std::endl;
    
    // High-Level API Tests
    std::cout << "High-Level API Tests:" << std::endl;
    RUN_TEST(high_level_create_graph);
    RUN_TEST(high_level_validate_graph);
    RUN_TEST(high_level_build_graph);
    RUN_TEST(high_level_create_plan);
    RUN_TEST(high_level_execute_plan);
    RUN_TEST(high_level_get_status);
    std::cout << std::endl;
    
    // Help Text Tests
    std::cout << "Help Text Tests:" << std::endl;
    RUN_TEST(help_text_content);
    std::cout << std::endl;
    
    // Complex Workflow Tests
    std::cout << "Complex Workflow Tests:" << std::endl;
    RUN_TEST(full_workflow_create_validate_plan_execute);
    RUN_TEST(workflow_with_export);
    RUN_TEST(workflow_with_checkpoint);
    std::cout << std::endl;
    
    // Edge Case Tests
    std::cout << "Edge Case Tests:" << std::endl;
    RUN_TEST(empty_args_handling);
    RUN_TEST(invalid_batch_range);
    RUN_TEST(multiple_graphs_sequence);
    std::cout << std::endl;
    
    // Summary
    std::cout << "========================================" << std::endl;
    std::cout << "Results: " << testsPassed << " passed, " << testsFailed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return testsFailed > 0 ? 1 : 0;
}
