// ============================================================================
// AgentBudget.hpp — Per-Run Tool & Turn Budget System
// ============================================================================
// Replaces the global static g_extendedToolCallLimit with a first-class,
// per-run budget that tracks consumption, supports dynamic extensions,
// and enforces a hard ceiling.
//
// Architecture:
//   AgentRun
//    ├── ToolBudget  (per-response tool-call accounting)
//    └── TurnBudget  (model→tool→model cycle accounting)
//
// Extension policy:
//   initial budget       25
//   extension size       25
//   maximum extensions   10
//   absolute hard cap    500
//
// The model can request extensions, but the runtime policy controller
// approves/denies/clamps them. The hard cap cannot be overridden.
//
// Pattern: PatchResult-style, no exceptions, thread-safe.
// Rule:    NO SOURCE FILE IS TO BE SIMPLIFIED.
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <atomic>
#include <chrono>

namespace RawrXD {
namespace Agent {

// ============================================================================
// Budget extension request result
// ============================================================================
enum class BudgetExtensionResult {
    Approved,       // Full amount granted
    Partial,        // Granted less than requested (clamped)
    Denied,         // Policy rejected the request
    HardCapReached, // Already at absolute ceiling
    MaxExtensionsReached // Too many extensions already
};

// ============================================================================
// ToolBudget — tracks individual tool invocations
// ============================================================================
struct ToolBudget {
    // Config (set at AgentRun creation)
    uint32_t initialLimit       = 25;
    uint32_t extensionSize      = 25;
    uint32_t maxExtensions      = 10;
    uint32_t hardCap            = 500;

    // Mutable state (atomic for thread-safe concurrent dispatch)
    std::atomic<uint32_t> remaining{25};
    std::atomic<uint32_t> consumed{0};
    std::atomic<uint32_t> extensionCount{0};

    ToolBudget() = default;
    ToolBudget(uint32_t init, uint32_t extSize, uint32_t maxExt, uint32_t cap)
        : initialLimit(init), extensionSize(extSize), maxExtensions(maxExt), hardCap(cap),
          remaining(init), consumed(0), extensionCount(0) {}

    // ---- Queries ----
    bool canCall() const { return remaining.load() > 0; }
    uint32_t getRemaining() const { return remaining.load(); }
    uint32_t getConsumed() const { return consumed.load(); }
    uint32_t getExtensionCount() const { return extensionCount.load(); }

    // ---- Consumption ----
    // Returns true if the call was allowed and consumed.
    // Returns false if budget exhausted.
    bool consume(uint32_t count = 1) {
        uint32_t current = remaining.load();
        while (current >= count) {
            if (remaining.compare_exchange_weak(current, current - count)) {
                consumed.fetch_add(count);
                return true;
            }
        }
        return false; // Not enough budget
    }

    // ---- Extension ----
    // Request an extension. Returns result and actual amount granted.
    BudgetExtensionResult extend(uint32_t requested, uint32_t& grantedOut) {
        grantedOut = 0;

        uint32_t extCount = extensionCount.load();
        if (extCount >= maxExtensions) {
            return BudgetExtensionResult::MaxExtensionsReached;
        }

        uint32_t currentRemaining = remaining.load();
        uint32_t currentConsumed  = consumed.load();
        uint32_t totalUsed = currentRemaining + currentConsumed;

        if (totalUsed >= hardCap) {
            return BudgetExtensionResult::HardCapReached;
        }

        // Clamp to extension size and hard cap
        uint32_t maxAllowed = hardCap - totalUsed;
        uint32_t clamped = std::min(requested, extensionSize);
        clamped = std::min(clamped, maxAllowed);

        if (clamped == 0) {
            return BudgetExtensionResult::HardCapReached;
        }

        remaining.fetch_add(clamped);
        extensionCount.fetch_add(1);
        grantedOut = clamped;

        return (grantedOut == requested)
            ? BudgetExtensionResult::Approved
            : BudgetExtensionResult::Partial;
    }

    // ---- Reset ----
    void reset() {
        remaining.store(initialLimit);
        consumed.store(0);
        extensionCount.store(0);
    }

    // ---- Serialization ----
    std::string toString() const {
        return "ToolBudget{limit=" + std::to_string(initialLimit)
            + ", consumed=" + std::to_string(consumed.load())
            + ", remaining=" + std::to_string(remaining.load())
            + ", extensions=" + std::to_string(extensionCount.load())
            + "/" + std::to_string(maxExtensions)
            + ", hardCap=" + std::to_string(hardCap) + "}";
    }
};

// ============================================================================
// TurnBudget — tracks model→tool→model cycles
// ============================================================================
struct TurnBudget {
    uint32_t initialLimit = 100;
    uint32_t hardCap      = 500;

    std::atomic<uint32_t> remaining{100};
    std::atomic<uint32_t> consumed{0};

    TurnBudget() = default;
    TurnBudget(uint32_t init, uint32_t cap)
        : initialLimit(init), hardCap(cap), remaining(init), consumed(0) {}

    bool canTurn() const { return remaining.load() > 0; }
    uint32_t getRemaining() const { return remaining.load(); }
    uint32_t getConsumed() const { return consumed.load(); }

    bool consume(uint32_t count = 1) {
        uint32_t current = remaining.load();
        while (current >= count) {
            if (remaining.compare_exchange_weak(current, current - count)) {
                consumed.fetch_add(count);
                return true;
            }
        }
        return false;
    }

    void reset() {
        remaining.store(initialLimit);
        consumed.store(0);
    }

    std::string toString() const {
        return "TurnBudget{limit=" + std::to_string(initialLimit)
            + ", consumed=" + std::to_string(consumed.load())
            + ", remaining=" + std::to_string(remaining.load())
            + ", hardCap=" + std::to_string(hardCap) + "}";
    }
};

// ============================================================================
// Adaptive budget sizing based on task classification
// ============================================================================
enum class TaskComplexity {
    Simple,       // 25 tool calls
    Normal,       // 50
    Large,        // 100
    Repository,   // 250
    DeepAutonomous // 500
};

inline void ApplyAdaptiveBudget(TaskComplexity complexity,
                                 ToolBudget& toolBudget,
                                 TurnBudget& turnBudget) {
    switch (complexity) {
        case TaskComplexity::Simple:
            toolBudget.initialLimit = 25;  toolBudget.hardCap = 50;
            turnBudget.initialLimit = 50;  turnBudget.hardCap = 100;
            break;
        case TaskComplexity::Normal:
            toolBudget.initialLimit = 50;  toolBudget.hardCap = 100;
            turnBudget.initialLimit = 100; turnBudget.hardCap = 200;
            break;
        case TaskComplexity::Large:
            toolBudget.initialLimit = 100; toolBudget.hardCap = 200;
            turnBudget.initialLimit = 200; turnBudget.hardCap = 400;
            break;
        case TaskComplexity::Repository:
            toolBudget.initialLimit = 250; toolBudget.hardCap = 500;
            turnBudget.initialLimit = 400; turnBudget.hardCap = 800;
            break;
        case TaskComplexity::DeepAutonomous:
            toolBudget.initialLimit = 500; toolBudget.hardCap = 1000;
            turnBudget.initialLimit = 800; turnBudget.hardCap = 1600;
            break;
    }
    toolBudget.remaining.store(toolBudget.initialLimit);
    toolBudget.consumed.store(0);
    toolBudget.extensionCount.store(0);
    turnBudget.remaining.store(turnBudget.initialLimit);
    turnBudget.consumed.store(0);
}

} // namespace Agent
} // namespace RawrXD
