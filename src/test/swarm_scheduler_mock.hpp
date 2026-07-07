// ============================================================================
// swarm_scheduler_mock.hpp — Minimal Mock for Test Compilation
// ============================================================================
// Lightweight replacement for the full swarm_scheduler.hpp to satisfy
// dependencies without requiring C++23 std::expected support.
// This mock is ONLY for test compilation - production code uses the real header.
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace RawrXD {
namespace Swarm {

// Minimal stub for ISwarmScheduler interface
class ISwarmScheduler {
public:
    virtual ~ISwarmScheduler() = default;
    // Stub methods - not implemented for test
};

// Minimal stub for SwarmMemoryBackend
class ISwarmMemoryBackend {
public:
    virtual ~ISwarmMemoryBackend() = default;
    // Stub methods - not implemented for test
};

// Minimal stub for EvictionPolicy
class IEvictionPolicy {
public:
    virtual ~IEvictionPolicy() = default;
    // Stub methods - not implemented for test
};

// Minimal stub for PrefetchQueue
class IPrefetchQueue {
public:
    virtual ~IPrefetchQueue() = default;
    // Stub methods - not implemented for test
};

} // namespace Swarm
} // namespace RawrXD