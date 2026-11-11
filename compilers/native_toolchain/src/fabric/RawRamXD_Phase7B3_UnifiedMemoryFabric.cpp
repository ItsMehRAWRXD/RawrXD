// =============================================================================
// RawRamXD Phase 7B.3: Unified Memory Fabric
// Tiered Virtual Address Space with Bandwidth/Latency Weighting
// =============================================================================

#include <iostream>
#include <vector>
#include <memory>
#include <mutex>
#include <queue>
#include <functional>
#include <unordered_map>
#include <atomic>
#include <cstring>
#include <cmath>
#include <algorithm>

// Windows headers
#include <windows.h>
#include <d3d12.h>
#include <dxgi1_6.h>
#include <wrl/client.h>

#pragma comment(lib, "d3d12.lib")
#pragma comment(lib, "dxgi.lib")

using Microsoft::WRL::ComPtr;

namespace RawRamXD {

// =============================================================================
// Memory Tier Classification
// =============================================================================

enum class MemoryTier {
    VRAM_FAST = 0,        // Discrete GPU GDDR6 (highest bandwidth)
    UNIFIED_SHARED = 1,   // APU/iGPU shared memory
    SYSTEM_PAGED = 2,     // CPU system RAM
    NVME_MAPPED = 3,    // NVMe storage mapped memory
    TIER_COUNT = 4
};

enum class MigrationPath {
    P2P_DIRECT = 0,
    P2P_BRIDGE = 1,
    BRIDGE_RAM = 2,
    NETWORK = 3
};

const char* MemoryTierToString(MemoryTier tier) {
    switch (tier) {
        case MemoryTier::VRAM_FAST: return "VRAM_FAST";
        case MemoryTier::UNIFIED_SHARED: return "UNIFIED_SHARED";
        case MemoryTier::SYSTEM_PAGED: return "SYSTEM_PAGED";
        case MemoryTier::NVME_MAPPED: return "NVME_MAPPED";
        default: return "UNKNOWN";
    }
}

// =============================================================================
// Memory Tier Capabilities
// =============================================================================

struct TierCapabilities {
    uint64_t bandwidthBytesPerSec;
    uint64_t latencyNs;
    uint64_t capacityBytes;
    uint64_t availableBytes;
    uint64_t allocatedBytes;
    
    // Compute capabilities (for unified memory devices)
    bool computeCapable;
    float computeScore;
    
    // Access patterns this tier is optimized for
    bool optimalForWeights;      // Model weights (read-heavy)
    bool optimalForKVCache;      // KV cache (read-write)
    bool optimalForActivations;  // Temporary tensors
    bool optimalForStaging;      // Prefetch/staging
};

// =============================================================================
// Virtual Memory Block
// =============================================================================

struct VirtualMemoryBlock {
    uint64_t virtualAddress;
    uint64_t physicalAddress;
    size_t size;
    MemoryTier tier;
    uint32_t deviceId;
    bool resident;
    uint64_t lastAccessTime;
    uint64_t accessCount;
    
    // Migration tracking
    bool migrating;
    MemoryTier targetTier;
    uint64_t migrationStartTime;
};

// =============================================================================
// Memory Tier Manager
// =============================================================================

class MemoryTierManager {
public:
    bool Initialize();
    void Shutdown();
    
    // Tier information
    TierCapabilities GetTierCapabilities(MemoryTier tier) const;
    uint64_t GetTierCapacity(MemoryTier tier) const;
    uint64_t GetTierAvailable(MemoryTier tier) const;
    
    // Allocation
    uint64_t AllocateInTier(MemoryTier tier, size_t size);
    void FreeInTier(MemoryTier tier, uint64_t handle);
    
    // Migration
    bool MigrateBlock(uint64_t virtualAddr, MemoryTier targetTier);
    MigrationPath GetMigrationPath(MemoryTier src, MemoryTier dst);
    uint64_t EstimateMigrationCost(MemoryTier src, MemoryTier dst, size_t size);
    
    // Optimization
    MemoryTier SelectOptimalTier(size_t size, uint32_t accessPattern);
    std::vector<VirtualMemoryBlock*> GetBlocksForPromotion();
    std::vector<VirtualMemoryBlock*> GetBlocksForDemotion();
    
    // Stats
    void PrintTierStats() const;
    
private:
    std::unordered_map<MemoryTier, TierCapabilities> tierCaps_;
    std::unordered_map<uint64_t, VirtualMemoryBlock> blocks_;
    mutable std::mutex blocksMutex_;
    uint64_t nextVirtualAddr_ = 0x100000000ULL;
    bool initialized_ = false;
};

// =============================================================================
// Unified Memory Fabric
// =============================================================================

class UnifiedMemoryFabric {
public:
    static UnifiedMemoryFabric& Instance();
    
    bool Initialize();
    void Shutdown();
    
    // Unified allocation
    uint64_t Allocate(size_t size, MemoryTier preferredTier = MemoryTier::VRAM_FAST);
    void Free(uint64_t virtualAddr);
    
    // Tier management
    bool Promote(uint64_t virtualAddr);  // Move to faster tier
    bool Demote(uint64_t virtualAddr);    // Move to slower tier
    bool MigrateToTier(uint64_t virtualAddr, MemoryTier targetTier);
    
    // Access
    void* Access(uint64_t virtualAddr, bool write = false);
    void ReleaseAccess(uint64_t virtualAddr);
    
    // Query
    MemoryTier GetCurrentTier(uint64_t virtualAddr);
    uint64_t GetPhysicalAddress(uint64_t virtualAddr);
    bool IsResident(uint64_t virtualAddr);
    
    // Optimization
    void RunOptimizationPass();
    void SetAccessPattern(uint64_t virtualAddr, uint32_t pattern);
    
    // Stats
    void PrintFabricStats() const;
    uint64_t GetTotalCapacity() const;
    uint64_t GetTotalAllocated() const;
    
private:
    UnifiedMemoryFabric() = default;
    ~UnifiedMemoryFabric() = default;
    UnifiedMemoryFabric(const UnifiedMemoryFabric&) = delete;
    UnifiedMemoryFabric& operator=(const UnifiedMemoryFabric&) = delete;
    
    std::unique_ptr<MemoryTierManager> tierManager_;
    bool initialized_ = false;
};

// =============================================================================
// Implementation: Memory Tier Manager
// =============================================================================

bool MemoryTierManager::Initialize() {
    std::cout << "\n========================================\n";
    std::cout << "RawRamXD Phase 7B.3: Unified Memory Fabric\n";
    std::cout << "Tiered Virtual Address Space\n";
    std::cout << "========================================\n\n";
    
    // Initialize VRAM_FAST tier (RX 7800 XT)
    TierCapabilities vramFast;
    vramFast.bandwidthBytesPerSec = 600ULL * 1024 * 1024 * 1024;  // 600 GB/s GDDR6
    vramFast.latencyNs = 50;
    vramFast.capacityBytes = 16ULL * 1024 * 1024 * 1024;  // 16 GB
    vramFast.availableBytes = vramFast.capacityBytes;
    vramFast.allocatedBytes = 0;
    vramFast.computeCapable = true;
    vramFast.computeScore = 100.0f;
    vramFast.optimalForWeights = true;
    vramFast.optimalForKVCache = true;
    vramFast.optimalForActivations = true;
    vramFast.optimalForStaging = false;
    tierCaps_[MemoryTier::VRAM_FAST] = vramFast;
    
    // Initialize UNIFIED_SHARED tier (APU/iGPU)
    TierCapabilities unified;
    unified.bandwidthBytesPerSec = 100ULL * 1024 * 1024 * 1024;  // 100 GB/s DDR5
    unified.latencyNs = 100;
    unified.capacityBytes = 4ULL * 1024 * 1024 * 1024;  // 4 GB (configurable)
    unified.availableBytes = unified.capacityBytes;
    unified.allocatedBytes = 0;
    unified.computeCapable = true;
    unified.computeScore = 20.0f;  // iGPU compute
    unified.optimalForWeights = false;
    unified.optimalForKVCache = true;  // Good for KV cache overflow
    unified.optimalForActivations = false;
    unified.optimalForStaging = true;  // Perfect for staging
    tierCaps_[MemoryTier::UNIFIED_SHARED] = unified;
    
    // Initialize SYSTEM_PAGED tier (CPU RAM)
    TierCapabilities system;
    system.bandwidthBytesPerSec = 50ULL * 1024 * 1024 * 1024;  // 50 GB/s DDR5
    system.latencyNs = 200;
    system.capacityBytes = 128ULL * 1024 * 1024 * 1024;  // 128 GB
    system.availableBytes = system.capacityBytes;
    system.allocatedBytes = 0;
    system.computeCapable = false;  // CPU only
    system.computeScore = 0.0f;
    system.optimalForWeights = true;  // Weights can live here
    system.optimalForKVCache = true;  // KV cache spill
    system.optimalForActivations = false;
    system.optimalForStaging = true;
    tierCaps_[MemoryTier::SYSTEM_PAGED] = system;
    
    // Initialize NVME_MAPPED tier (Storage)
    TierCapabilities nvme;
    nvme.bandwidthBytesPerSec = 7ULL * 1024 * 1024 * 1024;  // 7 GB/s Gen4 NVMe
    nvme.latencyNs = 10000;  // 10 us
    nvme.capacityBytes = 2048ULL * 1024 * 1024 * 1024;  // 2 TB
    nvme.availableBytes = nvme.capacityBytes;
    nvme.allocatedBytes = 0;
    nvme.computeCapable = false;
    nvme.computeScore = 0.0f;
    nvme.optimalForWeights = true;  // Cold weights
    nvme.optimalForKVCache = false;
    nvme.optimalForActivations = false;
    nvme.optimalForStaging = false;
    tierCaps_[MemoryTier::NVME_MAPPED] = nvme;
    
    initialized_ = true;
    
    std::cout << "[+] Memory tiers initialized:\n";
    PrintTierStats();
    
    return true;
}

void MemoryTierManager::Shutdown() {
    std::lock_guard<std::mutex> lock(blocksMutex_);
    blocks_.clear();
    initialized_ = false;
}

TierCapabilities MemoryTierManager::GetTierCapabilities(MemoryTier tier) const {
    auto it = tierCaps_.find(tier);
    if (it != tierCaps_.end()) return it->second;
    return TierCapabilities{};
}

uint64_t MemoryTierManager::GetTierCapacity(MemoryTier tier) const {
    auto it = tierCaps_.find(tier);
    return (it != tierCaps_.end()) ? it->second.capacityBytes : 0;
}

uint64_t MemoryTierManager::GetTierAvailable(MemoryTier tier) const {
    auto it = tierCaps_.find(tier);
    return (it != tierCaps_.end()) ? it->second.availableBytes : 0;
}

uint64_t MemoryTierManager::AllocateInTier(MemoryTier tier, size_t size) {
    std::lock_guard<std::mutex> lock(blocksMutex_);
    
    auto it = tierCaps_.find(tier);
    if (it == tierCaps_.end() || it->second.availableBytes < size) {
        return 0;  // Allocation failed
    }
    
    // Allocate virtual address
    uint64_t vaddr = nextVirtualAddr_;
    nextVirtualAddr_ += ((size + 4095) / 4096) * 4096;  // 4KB aligned
    
    // Create block
    VirtualMemoryBlock block;
    block.virtualAddress = vaddr;
    block.physicalAddress = 0;  // Would be actual GPU/CPU address
    block.size = size;
    block.tier = tier;
    block.deviceId = (tier == MemoryTier::VRAM_FAST) ? 0 : 
                     (tier == MemoryTier::UNIFIED_SHARED) ? 1 : 0xFF;
    block.resident = true;
    block.lastAccessTime = GetTickCount64();
    block.accessCount = 0;
    block.migrating = false;
    
    blocks_[vaddr] = block;
    
    // Update tier stats
    it->second.availableBytes -= size;
    it->second.allocatedBytes += size;
    
    return vaddr;
}

void MemoryTierManager::FreeInTier(MemoryTier tier, uint64_t handle) {
    std::lock_guard<std::mutex> lock(blocksMutex_);
    
    auto it = blocks_.find(handle);
    if (it == blocks_.end()) return;
    
    size_t size = it->second.size;
    blocks_.erase(it);
    
    // Update tier stats
    auto tierIt = tierCaps_.find(tier);
    if (tierIt != tierCaps_.end()) {
        tierIt->second.availableBytes += size;
        tierIt->second.allocatedBytes -= size;
    }
}

bool MemoryTierManager::MigrateBlock(uint64_t virtualAddr, MemoryTier targetTier) {
    std::lock_guard<std::mutex> lock(blocksMutex_);
    
    auto it = blocks_.find(virtualAddr);
    if (it == blocks_.end()) return false;
    
    VirtualMemoryBlock& block = it->second;
    MemoryTier srcTier = block.tier;
    
    if (srcTier == targetTier) return true;  // Already there
    
    // Check target tier capacity
    auto targetIt = tierCaps_.find(targetTier);
    if (targetIt == tierCaps_.end() || targetIt->second.availableBytes < block.size) {
        return false;  // No space
    }
    
    // Perform migration
    block.migrating = true;
    block.targetTier = targetTier;
    block.migrationStartTime = GetTickCount64();
    
    // Update source tier
    auto srcIt = tierCaps_.find(srcTier);
    if (srcIt != tierCaps_.end()) {
        srcIt->second.availableBytes += block.size;
        srcIt->second.allocatedBytes -= block.size;
    }
    
    // Update target tier
    targetIt->second.availableBytes -= block.size;
    targetIt->second.allocatedBytes += block.size;
    
    // Update block
    block.tier = targetTier;
    block.deviceId = (targetTier == MemoryTier::VRAM_FAST) ? 0 :
                     (targetTier == MemoryTier::UNIFIED_SHARED) ? 1 : 0xFF;
    block.migrating = false;
    
    uint64_t migrationTime = GetTickCount64() - block.migrationStartTime;
    std::cout << "[RawRamXD] Migrated " << (block.size / (1024*1024)) << " MB "
              << MemoryTierToString(srcTier) << " -> " << MemoryTierToString(targetTier)
              << " in " << migrationTime << " ms\n";
    
    return true;
}

MigrationPath MemoryTierManager::GetMigrationPath(MemoryTier src, MemoryTier dst) {
    // Define migration paths between tiers
    if (src == dst) return MigrationPath::P2P_DIRECT;
    
    // VRAM <-> UNIFIED: Direct via PCIe/DMA
    if ((src == MemoryTier::VRAM_FAST && dst == MemoryTier::UNIFIED_SHARED) ||
        (src == MemoryTier::UNIFIED_SHARED && dst == MemoryTier::VRAM_FAST)) {
        return MigrationPath::P2P_DIRECT;
    }
    
    // VRAM <-> SYSTEM: Via bridge/RAM
    if ((src == MemoryTier::VRAM_FAST && dst == MemoryTier::SYSTEM_PAGED) ||
        (src == MemoryTier::SYSTEM_PAGED && dst == MemoryTier::VRAM_FAST)) {
        return MigrationPath::BRIDGE_RAM;
    }
    
    // UNIFIED <-> SYSTEM: Direct (same physical memory)
    if ((src == MemoryTier::UNIFIED_SHARED && dst == MemoryTier::SYSTEM_PAGED) ||
        (src == MemoryTier::SYSTEM_PAGED && dst == MemoryTier::UNIFIED_SHARED)) {
        return MigrationPath::P2P_DIRECT;
    }
    
    // Anything involving NVME: Slow
    return MigrationPath::BRIDGE_RAM;
}

uint64_t MemoryTierManager::EstimateMigrationCost(MemoryTier src, MemoryTier dst, size_t size) {
    auto srcCap = GetTierCapabilities(src);
    auto dstCap = GetTierCapabilities(dst);
    
    // Estimate time = latency + size / bandwidth
    uint64_t latency = srcCap.latencyNs + dstCap.latencyNs;
    uint64_t bandwidth = std::min(srcCap.bandwidthBytesPerSec, dstCap.bandwidthBytesPerSec);
    
    if (bandwidth == 0) return UINT64_MAX;
    
    uint64_t transferTime = (size * 1000000000ULL) / bandwidth;  // ns
    return latency + transferTime;
}

MemoryTier MemoryTierManager::SelectOptimalTier(size_t size, uint32_t accessPattern) {
    // accessPattern bits:
    // bit 0: read-heavy (weights)
    // bit 1: write-heavy (KV cache)
    // bit 2: temporary (activations)
    // bit 3: staging
    
    bool readHeavy = accessPattern & 1;
    bool writeHeavy = accessPattern & 2;
    bool temporary = accessPattern & 4;
    bool staging = accessPattern & 8;
    
    // Try VRAM first for compute-heavy workloads
    if (!staging && GetTierAvailable(MemoryTier::VRAM_FAST) >= size) {
        return MemoryTier::VRAM_FAST;
    }
    
    // Use unified memory for KV cache overflow or staging
    if ((writeHeavy || staging) && GetTierAvailable(MemoryTier::UNIFIED_SHARED) >= size) {
        return MemoryTier::UNIFIED_SHARED;
    }
    
    // Fall back to system RAM
    if (GetTierAvailable(MemoryTier::SYSTEM_PAGED) >= size) {
        return MemoryTier::SYSTEM_PAGED;
    }
    
    // Last resort: NVMe
    return MemoryTier::NVME_MAPPED;
}

std::vector<VirtualMemoryBlock*> MemoryTierManager::GetBlocksForPromotion() {
    std::vector<VirtualMemoryBlock*> candidates;
    std::lock_guard<std::mutex> lock(blocksMutex_);
    
    uint64_t currentTime = GetTickCount64();
    
    for (auto& [vaddr, block] : blocks_) {
        // Promote if:
        // 1. Currently in slower tier
        // 2. High access count
        // 3. Recently accessed
        if (block.tier != MemoryTier::VRAM_FAST && 
            block.accessCount > 100 &&
            (currentTime - block.lastAccessTime) < 1000) {  // Active in last second
            candidates.push_back(&block);
        }
    }
    
    // Sort by access count (highest first)
    std::sort(candidates.begin(), candidates.end(),
              [](VirtualMemoryBlock* a, VirtualMemoryBlock* b) {
                  return a->accessCount > b->accessCount;
              });
    
    return candidates;
}

std::vector<VirtualMemoryBlock*> MemoryTierManager::GetBlocksForDemotion() {
    std::vector<VirtualMemoryBlock*> candidates;
    std::lock_guard<std::mutex> lock(blocksMutex_);
    
    uint64_t currentTime = GetTickCount64();
    
    for (auto& [vaddr, block] : blocks_) {
        // Demote if:
        // 1. Currently in VRAM (expensive)
        // 2. Low access count
        // 3. Not accessed recently
        if (block.tier == MemoryTier::VRAM_FAST && 
            block.accessCount < 10 &&
            (currentTime - block.lastAccessTime) > 5000) {  // Idle for 5 seconds
            candidates.push_back(&block);
        }
    }
    
    return candidates;
}

void MemoryTierManager::PrintTierStats() const {
    for (int i = 0; i < static_cast<int>(MemoryTier::TIER_COUNT); i++) {
        MemoryTier tier = static_cast<MemoryTier>(i);
        auto cap = GetTierCapabilities(tier);
        
        std::cout << "  " << MemoryTierToString(tier) << ":\n";
        std::cout << "    Capacity: " << (cap.capacityBytes / (1024ULL*1024*1024)) << " GB\n";
        std::cout << "    Available: " << (cap.availableBytes / (1024ULL*1024*1024)) << " GB\n";
        std::cout << "    Bandwidth: " << (cap.bandwidthBytesPerSec / (1024ULL*1024*1024)) << " GB/s\n";
        std::cout << "    Latency: " << cap.latencyNs << " ns\n";
        if (cap.computeCapable) {
            std::cout << "    Compute: " << cap.computeScore << "\n";
        }
        std::cout << "\n";
    }
}

// =============================================================================
// Implementation: Unified Memory Fabric
// =============================================================================

UnifiedMemoryFabric& UnifiedMemoryFabric::Instance() {
    static UnifiedMemoryFabric instance;
    return instance;
}

bool UnifiedMemoryFabric::Initialize() {
    if (initialized_) return true;
    
    tierManager_ = std::make_unique<MemoryTierManager>();
    if (!tierManager_->Initialize()) {
        return false;
    }
    
    initialized_ = true;
    return true;
}

void UnifiedMemoryFabric::Shutdown() {
    if (tierManager_) tierManager_->Shutdown();
    initialized_ = false;
}

uint64_t UnifiedMemoryFabric::Allocate(size_t size, MemoryTier preferredTier) {
    if (!tierManager_) return 0;
    
    // Try preferred tier first
    uint64_t addr = tierManager_->AllocateInTier(preferredTier, size);
    if (addr) return addr;
    
    // Fall back to automatic tier selection
    MemoryTier optimal = tierManager_->SelectOptimalTier(size, 0);
    return tierManager_->AllocateInTier(optimal, size);
}

void UnifiedMemoryFabric::Free(uint64_t virtualAddr) {
    if (!tierManager_) return;
    
    // Get current tier and free there
    MemoryTier tier = GetCurrentTier(virtualAddr);
    tierManager_->FreeInTier(tier, virtualAddr);
}

bool UnifiedMemoryFabric::Promote(uint64_t virtualAddr) {
    MemoryTier current = GetCurrentTier(virtualAddr);
    if (current == MemoryTier::VRAM_FAST) return true;  // Already at top
    
    // Promote to next faster tier
    MemoryTier target = current;
    switch (current) {
        case MemoryTier::NVME_MAPPED: target = MemoryTier::SYSTEM_PAGED; break;
        case MemoryTier::SYSTEM_PAGED: target = MemoryTier::UNIFIED_SHARED; break;
        case MemoryTier::UNIFIED_SHARED: target = MemoryTier::VRAM_FAST; break;
        default: return false;
    }
    
    return tierManager_->MigrateBlock(virtualAddr, target);
}

bool UnifiedMemoryFabric::Demote(uint64_t virtualAddr) {
    MemoryTier current = GetCurrentTier(virtualAddr);
    if (current == MemoryTier::NVME_MAPPED) return true;  // Already at bottom
    
    // Demote to next slower tier
    MemoryTier target = current;
    switch (current) {
        case MemoryTier::VRAM_FAST: target = MemoryTier::UNIFIED_SHARED; break;
        case MemoryTier::UNIFIED_SHARED: target = MemoryTier::SYSTEM_PAGED; break;
        case MemoryTier::SYSTEM_PAGED: target = MemoryTier::NVME_MAPPED; break;
        default: return false;
    }
    
    return tierManager_->MigrateBlock(virtualAddr, target);
}

bool UnifiedMemoryFabric::MigrateToTier(uint64_t virtualAddr, MemoryTier targetTier) {
    if (!tierManager_) return false;
    return tierManager_->MigrateBlock(virtualAddr, targetTier);
}

void* UnifiedMemoryFabric::Access(uint64_t virtualAddr, bool write) {
    // In real implementation: map virtual to physical and return pointer
    // For now, just update access stats
    return reinterpret_cast<void*>(virtualAddr);
}

void UnifiedMemoryFabric::ReleaseAccess(uint64_t virtualAddr) {
    // Release mapping
}

MemoryTier UnifiedMemoryFabric::GetCurrentTier(uint64_t virtualAddr) {
    // Would look up in block map
    return MemoryTier::VRAM_FAST;  // Simplified
}

uint64_t UnifiedMemoryFabric::GetPhysicalAddress(uint64_t virtualAddr) {
    // Would translate virtual to physical
    return virtualAddr;
}

bool UnifiedMemoryFabric::IsResident(uint64_t virtualAddr) {
    return true;  // Simplified
}

void UnifiedMemoryFabric::RunOptimizationPass() {
    if (!tierManager_) return;
    
    std::cout << "\n[RawRamXD] Running optimization pass...\n";
    
    // Promote hot blocks to VRAM
    auto promote = tierManager_->GetBlocksForPromotion();
    int promoted = 0;
    for (auto* block : promote) {
        if (promoted >= 10) break;  // Limit per pass
        if (MigrateToTier(block->virtualAddress, MemoryTier::VRAM_FAST)) {
            promoted++;
        }
    }
    
    // Demote cold blocks from VRAM
    auto demote = tierManager_->GetBlocksForDemotion();
    int demoted = 0;
    for (auto* block : demote) {
        if (demoted >= 10) break;
        if (Demote(block->virtualAddress)) {
            demoted++;
        }
    }
    
    std::cout << "  Promoted: " << promoted << " blocks to VRAM\n";
    std::cout << "  Demoted: " << demoted << " blocks from VRAM\n";
}

void UnifiedMemoryFabric::SetAccessPattern(uint64_t virtualAddr, uint32_t pattern) {
    // Store pattern for future allocation decisions
}

void UnifiedMemoryFabric::PrintFabricStats() const {
    if (tierManager_) tierManager_->PrintTierStats();
}

uint64_t UnifiedMemoryFabric::GetTotalCapacity() const {
    if (!tierManager_) return 0;
    uint64_t total = 0;
    for (int i = 0; i < static_cast<int>(MemoryTier::TIER_COUNT); i++) {
        total += tierManager_->GetTierCapacity(static_cast<MemoryTier>(i));
    }
    return total;
}

uint64_t UnifiedMemoryFabric::GetTotalAllocated() const {
    if (!tierManager_) return 0;
    uint64_t total = 0;
    for (int i = 0; i < static_cast<int>(MemoryTier::TIER_COUNT); i++) {
        auto cap = tierManager_->GetTierCapabilities(static_cast<MemoryTier>(i));
        total += cap.allocatedBytes;
    }
    return total;
}

// =============================================================================
// C API
// =============================================================================

extern "C" {

bool RawRamXD_UnifiedFabric_Initialize() {
    return UnifiedMemoryFabric::Instance().Initialize();
}

void RawRamXD_UnifiedFabric_Shutdown() {
    UnifiedMemoryFabric::Instance().Shutdown();
}

uint64_t RawRamXD_Unified_Allocate(size_t size, int preferredTier) {
    return UnifiedMemoryFabric::Instance().Allocate(size, static_cast<MemoryTier>(preferredTier));
}

void RawRamXD_Unified_Free(uint64_t handle) {
    UnifiedMemoryFabric::Instance().Free(handle);
}

bool RawRamXD_Unified_Migrate(uint64_t handle, int targetTier) {
    return UnifiedMemoryFabric::Instance().MigrateToTier(handle, static_cast<MemoryTier>(targetTier));
}

bool RawRamXD_Unified_Promote(uint64_t handle) {
    return UnifiedMemoryFabric::Instance().Promote(handle);
}

bool RawRamXD_Unified_Demote(uint64_t handle) {
    return UnifiedMemoryFabric::Instance().Demote(handle);
}

void RawRamXD_Unified_RunOptimization() {
    UnifiedMemoryFabric::Instance().RunOptimizationPass();
}

uint64_t RawRamXD_Unified_GetTotalCapacity() {
    return UnifiedMemoryFabric::Instance().GetTotalCapacity();
}

uint64_t RawRamXD_Unified_GetTotalAllocated() {
    return UnifiedMemoryFabric::Instance().GetTotalAllocated();
}

} // extern "C"

} // namespace RawRamXD

// =============================================================================
// Main Test
// =============================================================================

int main() {
    using namespace RawRamXD;
    
    std::cout << "========================================\n";
    std::cout << "RawRamXD Phase 7B.3: Unified Memory Fabric\n";
    std::cout << "Tiered Virtual Address Space Test\n";
    std::cout << "========================================\n\n";
    
    if (!RawRamXD_UnifiedFabric_Initialize()) {
        std::cerr << "[!] Failed to initialize unified fabric\n";
        return 1;
    }
    
    auto& fabric = UnifiedMemoryFabric::Instance();
    
    std::cout << "\n[+] Total Fabric Capacity: " 
              << (fabric.GetTotalCapacity() / (1024ULL * 1024 * 1024)) << " GB\n\n";
    
    // Test allocations in different tiers
    std::cout << "[+] Testing tiered allocations...\n";
    
    // Allocate model weights in VRAM
    size_t weightsSize = 1024 * 1024 * 1024;  // 1 GB
    uint64_t weights = RawRamXD_Unified_Allocate(weightsSize, 
                                                  static_cast<int>(MemoryTier::VRAM_FAST));
    std::cout << "  Weights (1 GB): VRAM_FAST @ " << weights << "\n";
    
    // Allocate KV cache in unified memory
    size_t kvSize = 512 * 1024 * 1024;  // 512 MB
    uint64_t kvCache = RawRamXD_Unified_Allocate(kvSize,
                                                  static_cast<int>(MemoryTier::UNIFIED_SHARED));
    std::cout << "  KV Cache (512 MB): UNIFIED_SHARED @ " << kvCache << "\n";
    
    // Allocate staging buffer in unified memory
    size_t stagingSize = 256 * 1024 * 1024;  // 256 MB
    uint64_t staging = RawRamXD_Unified_Allocate(stagingSize,
                                                    static_cast<int>(MemoryTier::UNIFIED_SHARED));
    std::cout << "  Staging (256 MB): UNIFIED_SHARED @ " << staging << "\n";
    
    // Allocate cold weights in system RAM
    size_t coldSize = 2048ULL * 1024 * 1024;  // 2 GB
    uint64_t coldWeights = RawRamXD_Unified_Allocate(coldSize,
                                                      static_cast<int>(MemoryTier::SYSTEM_PAGED));
    std::cout << "  Cold Weights (2 GB): SYSTEM_PAGED @ " << coldWeights << "\n";
    
    std::cout << "\n[+] Total Allocated: " 
              << (RawRamXD_Unified_GetTotalAllocated() / (1024ULL * 1024 * 1024)) << " GB\n";
    
    // Test migration
    std::cout << "\n[+] Testing tier migration...\n";
    RawRamXD_Unified_Migrate(kvCache, static_cast<int>(MemoryTier::VRAM_FAST));
    
    // Run optimization
    std::cout << "\n";
    RawRamXD_Unified_RunOptimization();
    
    // Cleanup
    std::cout << "\n[+] Freeing allocations...\n";
    RawRamXD_Unified_Free(weights);
    RawRamXD_Unified_Free(kvCache);
    RawRamXD_Unified_Free(staging);
    RawRamXD_Unified_Free(coldWeights);
    
    std::cout << "\n[+] Shutting down...\n";
    RawRamXD_UnifiedFabric_Shutdown();
    
    std::cout << "\n========================================\n";
    std::cout << "Phase 7B.3 Complete\n";
    std::cout << "========================================\n";
    
    return 0;
}
