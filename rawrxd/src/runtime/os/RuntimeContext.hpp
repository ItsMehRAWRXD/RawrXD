// ============================================================================
// RuntimeContext.hpp — Execution context passed to every capability phase
// Provides access to the kernel, registry, evidence, and shared state.
// ============================================================================
#pragma once
#include <string>
#include <string_view>
#include <unordered_map>
#include <chrono>
#include <cstdint>

namespace rawrxd::runtime {

class RuntimeKernel;
class RuntimeRegistry;

struct CapabilityContext {
    RuntimeKernel* kernel = nullptr;
    RuntimeRegistry* registry = nullptr;

    // Per-execution correlation ID
    std::string requestId;

    // Monotonic clock for this context
    std::chrono::steady_clock::time_point startTime;

    // Sparse key-value bag for capability-specific data
    std::unordered_map<std::string, std::string> properties;

    void setProperty(std::string_view key, std::string_view value) {
        properties[std::string(key)] = std::string(value);
    }

    const std::string& getProperty(std::string_view key, const std::string& fallback = "") const {
        auto it = properties.find(std::string(key));
        return (it != properties.end()) ? it->second : fallback;
    }

    // Elapsed microseconds since context creation
    uint64_t elapsedUs() const {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - startTime).count());
    }
};

} // namespace rawrxd::runtime