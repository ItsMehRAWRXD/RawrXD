// =============================================================================
// RawRamXD Phase 7B: Fabric Core (C Interface)
// Minimum Invariant - Two Primitives
// =============================================================================
//
// PRIMITIVE 1: Virtual address → tier → migrate → coherent state
// PRIMITIVE 2: Every byte has owner + version + temperature
//
// Everything else expands from these two primitives.
//
// =============================================================================

#ifndef RAWRXD_FABRIC_CORE_H
#define RAWRXD_FABRIC_CORE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Core Types (The Universal Memory Truth)
// =============================================================================

typedef enum {
    TIER_VRAM_FAST = 0,      // RX 7800 XT GDDR6 (600 GB/s)
    TIER_UNIFIED = 1,        // APU shared DDR5 (100 GB/s)
    TIER_SYSTEM = 2,         // CPU system RAM (50 GB/s)
    TIER_NVME = 3,           // NVMe storage (7 GB/s)
    TIER_COUNT = 4
} FabricTier;

typedef enum {
    STATE_INVALID = 0,       // No valid copy
    STATE_SHARED = 1,        // Read-only copy exists
    STATE_EXCLUSIVE = 2,   // Only copy, writeable
    STATE_MODIFIED = 3,    // Writeable, dirty
    STATE_PREFETCH = 4     // In-flight
} CoherenceState;

// FabricPage - 64 bytes, the unit of coherence
// Every byte in the fabric has these three properties:
typedef struct {
    // Identity
    uint64_t virtualAddr;       // Global virtual address
    uint64_t physicalAddr;      // Physical in owner tier
    uint64_t size;              // Page size (4KB)
    
    // The Three Universal Properties
    uint32_t ownerTier;         // CURRENT OWNER (primitive 2)
    uint32_t homeTier;          // Home for writeback
    uint64_t version;           // VERSION (primitive 2)
    uint32_t temperature;       // TEMPERATURE (primitive 2) [0-100 fixed point]
    
    // Access tracking
    uint32_t accessCount;
    uint64_t lastAccess;
    
    // Coherence
    uint8_t state;              // CoherenceState
    uint8_t dirty;
    uint8_t migrating;
    uint8_t reserved[5];
} FabricPage;

// =============================================================================
// PRIMITIVE 1: Virtual address → tier → migrate → coherent state
// =============================================================================

// Resolve virtual address to current tier and state
// Input:  vaddr
// Output: *tier (current owner), *state (coherence state)
bool Fabric_Resolve(uint64_t vaddr, FabricTier* tier, CoherenceState* state);

// Migrate page to target tier if needed
// Input:  vaddr, targetTier
// Output: true if page is now in target tier (may have migrated or already there)
bool Fabric_Migrate(uint64_t vaddr, FabricTier targetTier);

// Acquire access with automatic coherence
// Input:  vaddr, requestingTier, writeAccess
// Output: physical address or NULL
void* Fabric_Acquire(uint64_t vaddr, FabricTier tier, bool write);

// Release access
void Fabric_Release(uint64_t vaddr, FabricTier tier, bool write);

// =============================================================================
// PRIMITIVE 2: Every byte has owner + version + temperature
// =============================================================================

// Get the three universal properties
FabricTier Fabric_GetOwner(uint64_t vaddr);
uint64_t Fabric_GetVersion(uint64_t vaddr);
float Fabric_GetTemperature(uint64_t vaddr);  // Returns 0.0-1.0

// Update temperature based on access
void Fabric_Touch(uint64_t vaddr, bool write);

// Bump version (after modification)
void Fabric_BumpVersion(uint64_t vaddr);

// Check if version is current in tier
bool Fabric_IsCurrent(uint64_t vaddr, FabricTier tier);

// =============================================================================
// Lifecycle
// =============================================================================

bool Fabric_Initialize(uint64_t virtualBase, uint64_t totalPages);
void Fabric_Shutdown(void);

// Allocate page in fabric
uint64_t Fabric_Allocate(uint64_t size, FabricTier homeTier);

// Free page
void Fabric_Free(uint64_t vaddr);

// =============================================================================
// Policy (Expands from primitives)
// =============================================================================

// Should this page be promoted to faster tier?
bool Fabric_ShouldPromote(uint64_t vaddr);

// Should this page be demoted to slower tier?
bool Fabric_ShouldDemote(uint64_t vaddr);

// Execute promotion/demotion
bool Fabric_Promote(uint64_t vaddr);
bool Fabric_Demote(uint64_t vaddr);

// =============================================================================
// Statistics
// =============================================================================

typedef struct {
    uint64_t totalPages;
    uint64_t migrations;
    uint64_t invalidations;
    uint64_t syncs;
    uint64_t hotPages;
    uint64_t coldPages;
} FabricStats;

void Fabric_GetStats(FabricStats* stats);
void Fabric_PrintStatus(void);

// =============================================================================
// Integration Helpers
// =============================================================================

// Map tensor to fabric pages
uint64_t Fabric_MapTensor(const char* name, uint64_t size, FabricTier preferredTier);

// Get hot pages for promotion
uint32_t Fabric_GetHotPages(uint64_t* pages, uint32_t maxCount);

// Get cold pages for demotion
uint32_t Fabric_GetColdPages(uint64_t* pages, uint32_t maxCount);

// Emergency eviction under pressure
void Fabric_EmergencyEvict(FabricTier tier, uint64_t bytesNeeded);

#ifdef __cplusplus
}
#endif

#endif // RAWRXD_FABRIC_CORE_H
