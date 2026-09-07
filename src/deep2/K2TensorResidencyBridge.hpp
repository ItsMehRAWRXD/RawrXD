// K2TensorResidencyBridge.hpp — thin bridge between MLA_Gemv and RawRamXDFabric
// NOT a generic library. Only owns the hot path K2 needs.
#pragma once
#include "RawRamXD.hpp"
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>

namespace Deep2 {

// ---------------------------------------------------------------------------
// Bridge counters (exposed for certification)
// ---------------------------------------------------------------------------
struct K2FabricCounters {
    uint64_t acquireCalls = 0;
    uint64_t vramHits = 0;
    uint64_t vramMisses = 0;
    uint64_t migrationsStarted = 0;
    uint64_t migrationsCompleted = 0;
    uint64_t migrationsFailed = 0;
    uint64_t deviceAddressZero = 0;
    uint64_t leaseEarlyRelease = 0;
    uint64_t fallbackToLegacy = 0;
};

// ---------------------------------------------------------------------------
// K2TensorResidencyBridge
//
// Usage from MLA_Gemv:
//   uint64_t devAddr = 0;
//   if (K2Fabric_TryGetDeviceAddress(name, bytes, devAddr)) {
//       // use devAddr directly in Vulkan GEMV
//   } else {
//       // fall back to K2GpuStreamCopy / legacy path
//   }
// ---------------------------------------------------------------------------

// Initialize the bridge with a fabric instance. Must be called once.
// If fabric is nullptr, bridge is disabled and all calls return false.
void K2Fabric_Init(std::shared_ptr<rawramxd::RawRamXDFabric> fabric);

// Register a weight tensor into the fabric (NVMe backing).
// Returns tensor handle ID (>0) on success, 0 on failure.
uint64_t K2Fabric_RegisterWeight(const char* name, size_t bytes,
                                  const void* initialData);

// Try to get a device address for a registered weight in VRAM.
// If not resident, optionally trigger migration (when triggerMigrate=true).
// Returns true if devAddr is valid and the weight is VRAM-resident.
// The caller must call K2Fabric_ReleaseLease() when GPU work is done.
bool K2Fabric_TryGetDeviceAddress(const char* name, size_t bytes,
                                   uint64_t& devAddr,
                                   bool triggerMigrate = true);

// Release the last acquired lease for this weight.
void K2Fabric_ReleaseLease(const char* name);

// Reset all counters.
void K2Fabric_ResetCounters();

// Get current counters.
K2FabricCounters K2Fabric_GetCounters();

// Emit counters to FILE* (or stdout if f==nullptr).
void K2Fabric_EmitCounters(FILE* f);

// Check if bridge is initialized.
bool K2Fabric_Available();

// Shutdown: release all leases, unregister weights.
void K2Fabric_Shutdown();

} // namespace Deep2
