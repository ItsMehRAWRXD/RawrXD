// ============================================================================
// RawrXD_TriggerTest.cpp — Test Trigger System Implementation
// ============================================================================
#include "RawrXD_TriggerTest.h"
#include <windows.h>
#include <vector>
#include <string>
#include <mutex>
#include <atomic>
#include <chrono>
#include <thread>

namespace RawrXD {

// Thread-safe trigger registry
static std::mutex g_triggerMutex;
static std::vector<TestTrigger> g_triggers;
static std::atomic<bool> g_triggerSystemActive{false};
static std::atomic<uint64_t> g_triggerCount{0};

// Initialize trigger system
bool InitializeTriggerSystem() {
    std::lock_guard<std::mutex> lock(g_triggerMutex);
    if (g_triggerSystemActive.load()) {
        return true; // Already initialized
    }
    
    g_triggers.clear();
    g_triggerCount.store(0);
    g_triggerSystemActive.store(true);
    
    return true;
}

// Shutdown trigger system
void ShutdownTriggerSystem() {
    std::lock_guard<std::mutex> lock(g_triggerMutex);
    g_triggerSystemActive.store(false);
    g_triggers.clear();
}

// Register a test trigger
bool RegisterTrigger(const TestTrigger& trigger) {
    if (!g_triggerSystemActive.load()) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(g_triggerMutex);
    
    // Check for duplicate IDs
    for (const auto& existing : g_triggers) {
        if (existing.id == trigger.id) {
            return false; // Duplicate ID
        }
    }
    
    g_triggers.push_back(trigger);
    g_triggerCount.fetch_add(1);
    
    return true;
}

// Unregister a trigger by ID
bool UnregisterTrigger(uint32_t triggerId) {
    std::lock_guard<std::mutex> lock(g_triggerMutex);
    
    auto it = std::remove_if(g_triggers.begin(), g_triggers.end(),
        [triggerId](const TestTrigger& t) { return t.id == triggerId; });
    
    if (it != g_triggers.end()) {
        g_triggers.erase(it, g_triggers.end());
        g_triggerCount.fetch_sub(1);
        return true;
    }
    
    return false;
}

// Fire a trigger by ID
bool FireTrigger(uint32_t triggerId, const TriggerContext& context) {
    if (!g_triggerSystemActive.load()) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(g_triggerMutex);
    
    for (auto& trigger : g_triggers) {
        if (trigger.id == triggerId) {
            if (trigger.callback) {
                trigger.callback(context);
            }
            trigger.fireCount++;
            trigger.lastFired = std::chrono::steady_clock::now();
            return true;
        }
    }
    
    return false;
}

// Fire all triggers matching a condition
size_t FireMatchingTriggers(const std::string& condition, const TriggerContext& context) {
    if (!g_triggerSystemActive.load()) {
        return 0;
    }
    
    std::lock_guard<std::mutex> lock(g_triggerMutex);
    size_t firedCount = 0;
    
    for (auto& trigger : g_triggers) {
        if (trigger.condition == condition) {
            if (trigger.callback) {
                trigger.callback(context);
            }
            trigger.fireCount++;
            trigger.lastFired = std::chrono::steady_clock::now();
            firedCount++;
        }
    }
    
    return firedCount;
}

// Get trigger count
uint64_t GetTriggerCount() {
    return g_triggerCount.load();
}

// Get trigger info by ID
bool GetTriggerInfo(uint32_t triggerId, TestTrigger& outTrigger) {
    std::lock_guard<std::mutex> lock(g_triggerMutex);
    
    for (const auto& trigger : g_triggers) {
        if (trigger.id == triggerId) {
            outTrigger = trigger;
            return true;
        }
    }
    
    return false;
}

// List all triggers
std::vector<TestTrigger> ListTriggers() {
    std::lock_guard<std::mutex> lock(g_triggerMutex);
    return g_triggers;
}

// Reset all trigger fire counts
void ResetTriggerCounts() {
    std::lock_guard<std::mutex> lock(g_triggerMutex);
    for (auto& trigger : g_triggers) {
        trigger.fireCount = 0;
    }
}

// Check if trigger system is active
bool IsTriggerSystemActive() {
    return g_triggerSystemActive.load();
}

} // namespace RawrXD
