#pragma once

#include <cstdint>
#include "Win32IDE_ExecutionGraph.h"

namespace RawrXD {
namespace OS {

// ============================================================================
// PHASE 2B: KV-Cache Memory OS (Attention State Virtualization)
// ============================================================================

enum class TPD_STATE : uint8_t {
    PAGED    = 0,  // Resides in NVME_MAPPED (Cold)
    RESIDENT = 1,  // In System RAM (Standby)
    LOCKED   = 2   // Pinned in HOT_KV_CACHE (L1/L3/Active)
};

// Tensor Page Descriptor (TPD)
// Maps abstract attention layers to physical/mapped memory
struct KV_PAGE_DESCRIPTOR {
    TPD_STATE flags;
    uint64_t phys_addr;      // Pointer to physical RAM if RESIDENT/LOCKED
    uint64_t file_off;       // Offset in NVME_MAPPED boundary
    uint64_t bytes;          // Page/Tile size
    uint64_t last_access_ns; // LRU Timestamp governed by scheduler tick
};

class KVCacheManager {
private:
    static const uint32_t MAX_PAGES = 4096;
    KV_PAGE_DESCRIPTOR m_registry[MAX_PAGES];

    uint32_t m_hot_page_count;
    uint32_t m_max_hot_pages;
    
    uint64_t m_nvme_base_addr;
    uint64_t m_hot_base_addr;

public:
    void Init(uint64_t nvme_base, uint64_t hot_base, uint32_t max_hot_pages, uint64_t page_size) {
        m_nvme_base_addr = nvme_base;
        m_hot_base_addr = hot_base;
        m_max_hot_pages = max_hot_pages;
        m_hot_page_count = 0;
        
        // Initialize TPD registry
        for (uint32_t i = 0; i < MAX_PAGES; i++) {
            m_registry[i].flags = TPD_STATE::PAGED;
            m_registry[i].phys_addr = 0;
            m_registry[i].file_off = i * page_size;
            m_registry[i].bytes = page_size;
            m_registry[i].last_access_ns = 0;
        }
    }

    // Ensures the required attention context is in the 'HOT' zone before compute
    void PinState(uint32_t layer_idx, uint64_t current_time_ns) {
        if (layer_idx >= MAX_PAGES) return;

        auto& tpd = m_registry[layer_idx];
        tpd.last_access_ns = current_time_ns;

        if (tpd.flags == TPD_STATE::PAGED) {
            FaultIn(tpd);
        } else {
            // Already resident, promote to LOCKED
            tpd.flags = TPD_STATE::LOCKED;
        }
    }

    bool IsResident(uint32_t layer_idx) const {
        if (layer_idx >= MAX_PAGES) return false;
        return m_registry[layer_idx].flags != TPD_STATE::PAGED;
    }

    uint64_t GetPhysAddr(uint32_t layer_idx) const {
        if (layer_idx >= MAX_PAGES) return 0;
        return m_registry[layer_idx].phys_addr;
    }

    // Unpin state after inference step, making it eligible for eviction
    void UnpinState(uint32_t layer_idx) {
        if (layer_idx >= MAX_PAGES) return;
        if (m_registry[layer_idx].flags == TPD_STATE::LOCKED) {
            m_registry[layer_idx].flags = TPD_STATE::RESIDENT;
        }
    }

private:
    void FaultIn(KV_PAGE_DESCRIPTOR& tpd) {
        // Enforce physical memory footprint bounds
        if (m_hot_page_count >= m_max_hot_pages) {
            EvictLeastRecent();
        }

        // Logic: VirtualLock / NtReadFile binding
        // Here we map the offset from NVME_MAPPED to the HOT_KV_CACHE physical region
        // ... System/Syscall implementation bridging goes here ...
        
        tpd.phys_addr = m_hot_base_addr + (m_hot_page_count * tpd.bytes); 
        tpd.flags = TPD_STATE::LOCKED;
        m_hot_page_count++;
    }

    void EvictLeastRecent() {
        uint64_t oldest_ts = UINT64_MAX;
        uint32_t oldest_idx = 0;
        
        for (uint32_t i = 0; i < MAX_PAGES; i++) {
            // Only purely RESIDENT (unpinned) pages can be evicted
            if (m_registry[i].flags == TPD_STATE::RESIDENT) {
                if (m_registry[i].last_access_ns < oldest_ts) {
                    oldest_ts = m_registry[i].last_access_ns;
                    oldest_idx = i;
                }
            }
        }
        
        if (oldest_ts != UINT64_MAX) {
            auto& tpd = m_registry[oldest_idx];
            tpd.flags = TPD_STATE::PAGED;
            tpd.phys_addr = 0;
            m_hot_page_count--;
            
            // Logic: NtWriteFile / Map flush if dirty block
        }
    }
};

} // namespace OS
} // namespace RawrXD