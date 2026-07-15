// Core Runtime Test - Task Graph
// Minimal test for task graph functionality

#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include "core_runtime/task_graph.h"
#include <cstdio>

bool test_task_graph() {
    printf("[TEST] Task Graph...\n");
    RawrXD::Core::TaskGraph graph;
    bool result = graph.AddTask("test_task");
    printf("[PASS] Task Graph\n");
    return result;
}
