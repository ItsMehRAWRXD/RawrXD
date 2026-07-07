// ============================================================================
// agentic_executor_mock.h — Minimal Mock for Test Compilation
// ============================================================================
// Lightweight replacement for the full agentic_executor.h to satisfy
// dependencies without requiring the full agentic stack.
// This mock is ONLY for test compilation - production code uses the real header.
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <memory>

// Minimal AgenticExecutor mock for testing ModelOperationsBridge
class AgenticExecutor {
public:
    AgenticExecutor() = default;
    ~AgenticExecutor() = default;

    // Stub methods - not implemented for test
    bool initialize() { return true; }
    void shutdown() {}
};