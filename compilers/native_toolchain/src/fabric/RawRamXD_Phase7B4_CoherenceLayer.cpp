// =============================================================================
// RawRamXD Phase 7B.4: Fabric Coherence Layer
// Ownership, Version Tracking, and Multi-Tier Consistency
// =============================================================================

#include <iostream>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <atomic>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <queue>

#include <windows.h>

namespace RawRamXD {

// =============================================================================
// Coherence States
// =============================================================================

enum class CoherenceState {
    INVALID = 0,      // Data not present or stale
    SHARED = 1,       // Read-only copy exists
    EXCLUSIVE = 2,    // Only copy, writeable
    MODIFIED = 3,     // Writeable, dirty (needs writeback)
    PREFETCH = 4      // Being fetched, not ready
};

const char* CoherenceStateToString(CoherenceState state) {
    switch (state) {
        case CoherenceState::INVALID: return "INVALID";
        case CoherenceState::SHARED: return "SHARED";
        case CoherenceState::EXCLUSIVE: return "EXCLUSIVE";
        case CoherenceState::MODIFIED: return "MODIFIED";
        case CoherenceState::PREFETCH: return "PREFETCH";
        default: return "UNKNOWN";
    }
}

// =============================================================================
// Fabric Page - The Unit of Coherence
// =============================================================================

struct FabricPage {
    uint64_t virtualAddress;      // Global virtual address
    uint64_t version;             // Monotonic version counter
    uint32_t ownerTier;           // Which tier owns the EXCLUSIVE/MODIFIED copy
    uint32_t homeTier;            // Home tier (where it "belongs")
    
    // Coherence tracking per tier
    struct TierState {
        CoherenceState state;
        uint64_t physicalAddress;   // Physical address in this tier
        uint64_t lastAccess;        // Timestamp
        uint32_t accessCount;       // Access frequency
        uint64_t version;           // Version at last sync
        bool dirty;                 // Modified since last sync
    };
    std::unordered_map<uint32_t, TierState> tierStates;
    
    // Global metadata
    uint64_t size;
    uint32_t totalCopies;         // How many tiers have a copy
    std::atomic<uint32_t> lock{0}; // Spinlock for page
    
    // Access pattern tracking
    uint64_t readCount;
    uint64_t writeCount;
    uint64_t migrationCount;
    double temperature;           // Hot/cold score (0.0 - 1.0)
};

// =============================================================================
// Coherence Manager
// =============================================================================

class CoherenceManager {
public:
    static CoherenceManager& Instance();
    
    bool Initialize();
    void Shutdown();
    
    // Page lifecycle
    uint64_t AllocatePage(uint64_t vaddr, uint64_t size, uint32_t homeTier);
    void FreePage(uint64_t vaddr);
    
    // Coherence operations
    bool AcquireRead(uint64_t vaddr, uint32_t tier);
    bool AcquireWrite(uint64_t vaddr, uint32_t tier);
    void ReleaseRead(uint64_t vaddr, uint32_t tier);
    void ReleaseWrite(uint64_t vaddr, uint32_t tier);
    
    // Version management
    uint64_t GetVersion(uint64_t vaddr);
    void BumpVersion(uint64_t vaddr);
    bool IsUpToDate(uint64_t vaddr, uint32_t tier);
    
    // Coherence actions
    bool InvalidateCopies(uint64_t vaddr, uint32_t exceptTier);
    bool DowngradeToShared(uint64_t vaddr, uint32_t tier);
    bool PromoteToExclusive(uint64_t vaddr, uint32_t tier);
    
    // Synchronization
    bool SyncToHome(uint64_t vaddr);
    bool SyncFromHome(uint64_t vaddr, uint32_t targetTier);
    
    // Query
    CoherenceState GetPageState(uint64_t vaddr, uint32_t tier);
    uint32_t GetOwnerTier(uint64_t vaddr);
    bool IsDirty(uint64_t vaddr);
    void PrintPageStatus(uint64_t vaddr);
    void PrintGlobalStats();
    
    // Temperature tracking
    void UpdateTemperature(uint64_t vaddr);
    double GetTemperature(uint64_t vaddr);
    std::vector<uint64_t> GetHotPages(uint32_t count);
    std::vector<uint64_t> GetColdPages(uint32_t count);
    
private:
    CoherenceManager() = default;
    ~CoherenceManager() = default;
    CoherenceManager(const CoherenceManager&) = delete;
    CoherenceManager& operator=(const CoherenceManager&) = delete;
    
    std::unordered_map<uint64_t, std::unique_ptr<FabricPage>> pages_;
    mutable std::mutex pagesMutex_;
    
    std::atomic<uint64_t> globalVersion_{1};
    std::atomic<uint32_t> totalPages_{0};
    std::atomic<uint32_t> totalInvalidations_{0};
    std::atomic<uint32_t> totalSyncs_{0};
    
    bool initialized_ = false;
    
    // Helper
    FabricPage* FindPage(uint64_t vaddr);
    void LockPage(FabricPage* page);
    void UnlockPage(FabricPage* page);
};

// =============================================================================
// Implementation
// =============================================================================

CoherenceManager& CoherenceManager::Instance() {
    static CoherenceManager instance;
    return instance;
}

bool CoherenceManager::Initialize() {
    std::cout << "\n========================================\n";
    std::cout << "RawRamXD Phase 7B.4: Fabric Coherence Layer\n";
    std::cout << "Ownership, Version Tracking, Consistency\n";
    std::cout << "========================================\n\n";
    
    initialized_ = true;
    std::cout << "[+] Coherence manager initialized\n";
    std::cout << "    Protocol: MESI-inspired (Modified/Exclusive/Shared/Invalid)\n";
    std::cout << "    Granularity: Page-level (4KB default)\n\n";
    
    return true;
}

void CoherenceManager::Shutdown() {
    std::lock_guard<std::mutex> lock(pagesMutex_);
    pages_.clear();
    initialized_ = false;
}

uint64_t CoherenceManager::AllocatePage(uint64_t vaddr, uint64_t size, uint32_t homeTier) {
    std::lock_guard<std::mutex> lock(pagesMutex_);
    
    auto page = std::make_unique<FabricPage>();
    page->virtualAddress = vaddr;
    page->version = globalVersion_.fetch_add(1);
    page->ownerTier = homeTier;
    page->homeTier = homeTier;
    page->size = size;
    page->totalCopies = 1;
    page->readCount = 0;
    page->writeCount = 0;
    page->migrationCount = 0;
    page->temperature = 0.5;
    
    // Initialize home tier state
    FabricPage::TierState homeState;
    homeState.state = CoherenceState::EXCLUSIVE;
    homeState.physicalAddress = 0;  // Would be actual allocation
    homeState.lastAccess = GetTickCount64();
    homeState.accessCount = 0;
    homeState.dirty = false;
    page->tierStates[homeTier] = homeState;
    
    pages_[vaddr] = std::move(page);
    totalPages_++;
    
    return vaddr;
}

void CoherenceManager::FreePage(uint64_t vaddr) {
    std::lock_guard<std::mutex> lock(pagesMutex_);
    
    auto it = pages_.find(vaddr);
    if (it != pages_.end()) {
        pages_.erase(it);
        totalPages_--;
    }
}

FabricPage* CoherenceManager::FindPage(uint64_t vaddr) {
    auto it = pages_.find(vaddr);
    return (it != pages_.end()) ? it->second.get() : nullptr;
}

void CoherenceManager::LockPage(FabricPage* page) {
    while (page->lock.exchange(1, std::memory_order_acquire)) {
        // Spin
    }
}

void CoherenceManager::UnlockPage(FabricPage* page) {
    page->lock.store(0, std::memory_order_release);
}

bool CoherenceManager::AcquireRead(uint64_t vaddr, uint32_t tier) {
    FabricPage* page = FindPage(vaddr);
    if (!page) return false;
    
    LockPage(page);
    
    auto& tierState = page->tierStates[tier];
    
    // Check if we have valid data
    if (tierState.state == CoherenceState::INVALID ||
        tierState.state == CoherenceState::PREFETCH) {
        // Need to sync from owner
        uint32_t owner = page->ownerTier;
        if (owner != tier) {
            // In real implementation: copy data from owner tier
            tierState.state = CoherenceState::SHARED;
            totalSyncs_++;
        } else {
            tierState.state = CoherenceState::EXCLUSIVE;
        }
    }
    
    // Downgrade owner if needed
    if (page->ownerTier != tier && page->tierStates[page->ownerTier].state == CoherenceState::EXCLUSIVE) {
        page->tierStates[page->ownerTier].state = CoherenceState::SHARED;
    }
    
    tierState.lastAccess = GetTickCount64();
    tierState.accessCount++;
    page->readCount++;
    
    UnlockPage(page);
    return true;
}

bool CoherenceManager::AcquireWrite(uint64_t vaddr, uint32_t tier) {
    FabricPage* page = FindPage(vaddr);
    if (!page) return false;
    
    LockPage(page);
    
    auto& tierState = page->tierStates[tier];
    
    // Invalidate all other copies
    if (page->ownerTier != tier) {
        for (auto& [t, state] : page->tierStates) {
            if (t != tier && state.state != CoherenceState::INVALID) {
                state.state = CoherenceState::INVALID;
                totalInvalidations_++;
            }
        }
    }
    
    // Take ownership
    page->ownerTier = tier;
    tierState.state = CoherenceState::MODIFIED;
    tierState.dirty = true;
    tierState.lastAccess = GetTickCount64();
    tierState.accessCount++;
    page->writeCount++;
    page->version++;
    
    UnlockPage(page);
    return true;
}

void CoherenceManager::ReleaseRead(uint64_t vaddr, uint32_t tier) {
    // In MESI, read release is typically a no-op
    // But we could track active readers here
}

void CoherenceManager::ReleaseWrite(uint64_t vaddr, uint32_t tier) {
    FabricPage* page = FindPage(vaddr);
    if (!page) return;
    
    LockPage(page);
    
    auto& tierState = page->tierStates[tier];
    if (tierState.state == CoherenceState::MODIFIED) {
        // Keep as MODIFIED (lazy writeback)
        // Or could downgrade to EXCLUSIVE here
    }
    
    UnlockPage(page);
}

uint64_t CoherenceManager::GetVersion(uint64_t vaddr) {
    FabricPage* page = FindPage(vaddr);
    return page ? page->version : 0;
}

void CoherenceManager::BumpVersion(uint64_t vaddr) {
    FabricPage* page = FindPage(vaddr);
    if (page) {
        page->version++;
    }
}

bool CoherenceManager::IsUpToDate(uint64_t vaddr, uint32_t tier) {
    FabricPage* page = FindPage(vaddr);
    if (!page) return false;
    
    auto it = page->tierStates.find(tier);
    if (it == page->tierStates.end()) return false;
    
    return it->second.state != CoherenceState::INVALID;
}

bool CoherenceManager::InvalidateCopies(uint64_t vaddr, uint32_t exceptTier) {
    FabricPage* page = FindPage(vaddr);
    if (!page) return false;
    
    LockPage(page);
    
    for (auto& [tier, state] : page->tierStates) {
        if (tier != exceptTier && state.state != CoherenceState::INVALID) {
            state.state = CoherenceState::INVALID;
            totalInvalidations_++;
        }
    }
    
    UnlockPage(page);
    return true;
}

bool CoherenceManager::DowngradeToShared(uint64_t vaddr, uint32_t tier) {
    FabricPage* page = FindPage(vaddr);
    if (!page) return false;
    
    LockPage(page);
    
    auto it = page->tierStates.find(tier);
    if (it != page->tierStates.end()) {
        if (it->second.state == CoherenceState::EXCLUSIVE ||
            it->second.state == CoherenceState::MODIFIED) {
            it->second.state = CoherenceState::SHARED;
        }
    }
    
    UnlockPage(page);
    return true;
}

bool CoherenceManager::PromoteToExclusive(uint64_t vaddr, uint32_t tier) {
    FabricPage* page = FindPage(vaddr);
    if (!page) return false;
    
    LockPage(page);
    
    // Invalidate others first
    for (auto& [t, state] : page->tierStates) {
        if (t != tier) {
            state.state = CoherenceState::INVALID;
        }
    }
    
    auto it = page->tierStates.find(tier);
    if (it != page->tierStates.end()) {
        it->second.state = CoherenceState::EXCLUSIVE;
        page->ownerTier = tier;
    }
    
    UnlockPage(page);
    return true;
}

bool CoherenceManager::SyncToHome(uint64_t vaddr) {
    FabricPage* page = FindPage(vaddr);
    if (!page) return false;
    
    if (page->ownerTier == page->homeTier) return true;  // Already home
    
    // In real implementation: copy data back to home tier
    totalSyncs_++;
    return true;
}

bool CoherenceManager::SyncFromHome(uint64_t vaddr, uint32_t targetTier) {
    FabricPage* page = FindPage(vaddr);
    if (!page) return false;
    
    auto homeIt = page->tierStates.find(page->homeTier);
    if (homeIt == page->tierStates.end()) return false;
    
    // In real implementation: copy from home to target
    auto& targetState = page->tierStates[targetTier];
    targetState.state = CoherenceState::SHARED;
    targetState.version = page->version;
    totalSyncs_++;
    
    return true;
}

CoherenceState CoherenceManager::GetPageState(uint64_t vaddr, uint32_t tier) {
    FabricPage* page = FindPage(vaddr);
    if (!page) return CoherenceState::INVALID;
    
    auto it = page->tierStates.find(tier);
    return (it != page->tierStates.end()) ? it->second.state : CoherenceState::INVALID;
}

uint32_t CoherenceManager::GetOwnerTier(uint64_t vaddr) {
    FabricPage* page = FindPage(vaddr);
    return page ? page->ownerTier : 0xFFFFFFFF;
}

bool CoherenceManager::IsDirty(uint64_t vaddr) {
    FabricPage* page = FindPage(vaddr);
    if (!page) return false;
    
    auto it = page->tierStates.find(page->ownerTier);
    return (it != page->tierStates.end()) ? it->second.dirty : false;
}

void CoherenceManager::PrintPageStatus(uint64_t vaddr) {
    FabricPage* page = FindPage(vaddr);
    if (!page) {
        std::cout << "Page " << vaddr << " not found\n";
        return;
    }
    
    std::cout << "\nPage Status: " << vaddr << "\n";
    std::cout << "  Version: " << page->version << "\n";
    std::cout << "  Owner Tier: " << page->ownerTier << "\n";
    std::cout << "  Home Tier: " << page->homeTier << "\n";
    std::cout << "  Size: " << (page->size / 1024) << " KB\n";
    std::cout << "  Temperature: " << (page->temperature * 100.0) << "%\n";
    std::cout << "  Reads: " << page->readCount << ", Writes: " << page->writeCount << "\n";
    std::cout << "  Tier States:\n";
    
    for (const auto& [tier, state] : page->tierStates) {
        std::cout << "    Tier " << tier << ": " << CoherenceStateToString(state.state);
        if (state.dirty) std::cout << " [DIRTY]";
        std::cout << " (accesses: " << state.accessCount << ")\n";
    }
}

void CoherenceManager::PrintGlobalStats() {
    std::cout << "\nGlobal Coherence Stats:\n";
    std::cout << "  Total Pages: " << totalPages_.load() << "\n";
    std::cout << "  Total Invalidations: " << totalInvalidations_.load() << "\n";
    std::cout << "  Total Syncs: " << totalSyncs_.load() << "\n";
    std::cout << "  Current Version: " << globalVersion_.load() << "\n";
}

void CoherenceManager::UpdateTemperature(uint64_t vaddr) {
    FabricPage* page = FindPage(vaddr);
    if (!page) return;
    
    // Simple temperature calculation based on access frequency
    uint64_t totalAccesses = page->readCount + page->writeCount;
    if (totalAccesses == 0) {
        page->temperature = 0.0;
    } else {
        // Exponential moving average
        double newTemp = std::min(1.0, static_cast<double>(totalAccesses) / 1000.0);
        page->temperature = 0.7 * page->temperature + 0.3 * newTemp;
    }
}

double CoherenceManager::GetTemperature(uint64_t vaddr) {
    FabricPage* page = FindPage(vaddr);
    return page ? page->temperature : 0.0;
}

std::vector<uint64_t> CoherenceManager::GetHotPages(uint32_t count) {
    std::vector<std::pair<uint64_t, double>> temps;
    
    std::lock_guard<std::mutex> lock(pagesMutex_);
    for (const auto& [vaddr, page] : pages_) {
        UpdateTemperature(vaddr);
        temps.push_back({vaddr, page->temperature});
    }
    
    // Sort by temperature (descending)
    std::sort(temps.begin(), temps.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    std::vector<uint64_t> result;
    for (uint32_t i = 0; i < std::min(count, static_cast<uint32_t>(temps.size())); i++) {
        result.push_back(temps[i].first);
    }
    
    return result;
}

std::vector<uint64_t> CoherenceManager::GetColdPages(uint32_t count) {
    std::vector<std::pair<uint64_t, double>> temps;
    
    std::lock_guard<std::mutex> lock(pagesMutex_);
    for (const auto& [vaddr, page] : pages_) {
        UpdateTemperature(vaddr);
        temps.push_back({vaddr, page->temperature});
    }
    
    // Sort by temperature (ascending)
    std::sort(temps.begin(), temps.end(),
              [](const auto& a, const auto& b) { return a.second < b.second; });
    
    std::vector<uint64_t> result;
    for (uint32_t i = 0; i < std::min(count, static_cast<uint32_t>(temps.size())); i++) {
        result.push_back(temps[i].first);
    }
    
    return result;
}

// =============================================================================
// C API
// =============================================================================

extern "C" {

bool RawRamXD_Coherence_Initialize() {
    return CoherenceManager::Instance().Initialize();
}

void RawRamXD_Coherence_Shutdown() {
    CoherenceManager::Instance().Shutdown();
}

uint64_t RawRamXD_Page_Allocate(uint64_t vaddr, uint64_t size, uint32_t homeTier) {
    return CoherenceManager::Instance().AllocatePage(vaddr, size, homeTier);
}

void RawRamXD_Page_Free(uint64_t vaddr) {
    CoherenceManager::Instance().FreePage(vaddr);
}

bool RawRamXD_Page_AcquireRead(uint64_t vaddr, uint32_t tier) {
    return CoherenceManager::Instance().AcquireRead(vaddr, tier);
}

bool RawRamXD_Page_AcquireWrite(uint64_t vaddr, uint32_t tier) {
    return CoherenceManager::Instance().AcquireWrite(vaddr, tier);
}

void RawRamXD_Page_ReleaseRead(uint64_t vaddr, uint32_t tier) {
    CoherenceManager::Instance().ReleaseRead(vaddr, tier);
}

void RawRamXD_Page_ReleaseWrite(uint64_t vaddr, uint32_t tier) {
    CoherenceManager::Instance().ReleaseWrite(vaddr, tier);
}

bool RawRamXD_Page_InvalidateOthers(uint64_t vaddr, uint32_t exceptTier) {
    return CoherenceManager::Instance().InvalidateCopies(vaddr, exceptTier);
}

uint64_t RawRamXD_Page_GetVersion(uint64_t vaddr) {
    return CoherenceManager::Instance().GetVersion(vaddr);
}

bool RawRamXD_Page_IsDirty(uint64_t vaddr) {
    return CoherenceManager::Instance().IsDirty(vaddr);
}

void RawRamXD_Coherence_PrintStats() {
    CoherenceManager::Instance().PrintGlobalStats();
}

void RawRamXD_Coherence_PrintPage(uint64_t vaddr) {
    CoherenceManager::Instance().PrintPageStatus(vaddr);
}

} // extern "C"

} // namespace RawRamXD

// =============================================================================
// Main Test
// =============================================================================

int main() {
    using namespace RawRamXD;
    
    std::cout << "========================================\n";
    std::cout << "RawRamXD Phase 7B.4: Coherence Layer Test\n";
    std::cout << "========================================\n\n";
    
    if (!RawRamXD_Coherence_Initialize()) {
        std::cerr << "[!] Failed to initialize coherence layer\n";
        return 1;
    }
    
    auto& cm = CoherenceManager::Instance();
    
    // Test 1: Allocate pages in different tiers
    std::cout << "[+] Test 1: Page allocation\n";
    uint64_t page1 = cm.AllocatePage(0x100000000ULL, 4096, 0);  // Tier 0 (VRAM)
    uint64_t page2 = cm.AllocatePage(0x100001000ULL, 4096, 1);  // Tier 1 (Unified)
    uint64_t page3 = cm.AllocatePage(0x100002000ULL, 4096, 2);  // Tier 2 (System)
    
    std::cout << "    Page 1: " << page1 << " (home tier 0)\n";
    std::cout << "    Page 2: " << page2 << " (home tier 1)\n";
    std::cout << "    Page 3: " << page3 << " (home tier 2)\n\n";
    
    // Test 2: Read sharing
    std::cout << "[+] Test 2: Read sharing\n";
    cm.AcquireRead(page1, 0);  // Tier 0 reads
    cm.AcquireRead(page1, 1);  // Tier 1 reads (shared)
    cm.AcquireRead(page1, 2);  // Tier 2 reads (shared)
    
    cm.PrintPageStatus(page1);
    
    // Test 3: Write invalidation
    std::cout << "\n[+] Test 3: Write invalidation\n";
    cm.AcquireWrite(page1, 1);  // Tier 1 writes (invalidates others)
    
    cm.PrintPageStatus(page1);
    
    // Test 4: Temperature tracking
    std::cout << "\n[+] Test 4: Temperature tracking\n";
    for (int i = 0; i < 100; i++) {
        cm.AcquireRead(page2, 0);
    }
    for (int i = 0; i < 10; i++) {
        cm.AcquireRead(page3, 0);
    }
    
    cm.UpdateTemperature(page2);
    cm.UpdateTemperature(page3);
    
    std::cout << "    Page 2 temperature: " << (cm.GetTemperature(page2) * 100.0) << "%\n";
    std::cout << "    Page 3 temperature: " << (cm.GetTemperature(page3) * 100.0) << "%\n";
    
    auto hotPages = cm.GetHotPages(5);
    std::cout << "    Hot pages: " << hotPages.size() << "\n";
    
    // Print stats
    std::cout << "\n";
    cm.PrintGlobalStats();
    
    // Cleanup
    std::cout << "\n[+] Cleaning up...\n";
    cm.FreePage(page1);
    cm.FreePage(page2);
    cm.FreePage(page3);
    
    RawRamXD_Coherence_Shutdown();
    
    std::cout << "\n========================================\n";
    std::cout << "Phase 7B.4 Complete\n";
    std::cout << "========================================\n";
    
    return 0;
}
