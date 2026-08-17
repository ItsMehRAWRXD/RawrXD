// ============================================================================
// RawrXD_TriggerTest.h — Test Trigger System Interface
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <functional>
#include <vector>
#include <chrono>

namespace RawrXD {

// Forward declarations
struct TriggerContext;
struct TestTrigger;

// Trigger callback type
using TriggerCallback = std::function<void(const TriggerContext&)>;

// Context passed to trigger callbacks
struct TriggerContext {
    uint32_t triggerId;
    std::string triggerName;
    std::string source;
    std::string data;
    std::chrono::steady_clock::time_point timestamp;
    
    TriggerContext() 
        : triggerId(0)
        , timestamp(std::chrono::steady_clock::now()) {}
};

// Test trigger definition
struct TestTrigger {
    uint32_t id;
    std::string name;
    std::string condition;
    TriggerCallback callback;
    uint64_t fireCount;
    std::chrono::steady_clock::time_point lastFired;
    bool enabled;
    
    TestTrigger()
        : id(0)
        , fireCount(0)
        , enabled(true) {}
};

// Initialize trigger system
bool InitializeTriggerSystem();

// Shutdown trigger system
void ShutdownTriggerSystem();

// Register a test trigger
bool RegisterTrigger(const TestTrigger& trigger);

// Unregister a trigger by ID
bool UnregisterTrigger(uint32_t triggerId);

// Fire a trigger by ID
bool FireTrigger(uint32_t triggerId, const TriggerContext& context);

// Fire all triggers matching a condition
size_t FireMatchingTriggers(const std::string& condition, const TriggerContext& context);

// Get trigger count
uint64_t GetTriggerCount();

// Get trigger info by ID
bool GetTriggerInfo(uint32_t triggerId, TestTrigger& outTrigger);

// List all triggers
std::vector<TestTrigger> ListTriggers();

// Reset all trigger fire counts
void ResetTriggerCounts();

// Check if trigger system is active
bool IsTriggerSystemActive();

} // namespace RawrXD
