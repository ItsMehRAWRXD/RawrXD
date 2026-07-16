# Sovereign Memory Model
## Core Runtime Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

The Sovereign Memory Model defines how memory is managed, allocated, and accessed within the Sovereign IDE runtime. It provides efficient memory management for large-scale binary analysis.

### Key Characteristics

| Attribute | Value |
|-----------|-------|
| **Memory Model** | Unified Virtual Memory |
| **Allocation Strategy** | Region-based |
| **Garbage Collection** | Incremental |
| **Max Address Space** | 128 TB |
| **Page Size** | 4 KB / 2 MB / 1 GB |

---

## Memory Regions

| Region | Purpose | Size |
|--------|---------|------|
| Code | Executable code | Variable |
| Data | Global data | Variable |
| Heap | Dynamic allocation | Up to 64 TB |
| Stack | Call stack | 8 MB per thread |
| Analysis | Analysis results | Up to 32 TB |
| Cache | Cached data | Up to 16 TB |

---

## API Reference

```cpp
// Memory management
SOVEREIGN_API void* Sovereign_Allocate(size_t size);
SOVEREIGN_API void* Sovereign_AllocateAligned(size_t size, size_t alignment);
SOVEREIGN_API void Sovereign_Free(void* ptr);
SOVEREIGN_API void* Sovereign_Reallocate(void* ptr, size_t newSize);

// Region management
SOVEREIGN_API MemoryRegion* Sovereign_CreateRegion(const char* name,
                                                    size_t size);
SOVEREIGN_API void Sovereign_DestroyRegion(MemoryRegion* region);
SOVEREIGN_API void* Sovereign_RegionAlloc(MemoryRegion* region, size_t size);

// Analysis memory
SOVEREIGN_API void* Sovereign_AllocAnalysisMemory(size_t size);
SOVEREIGN_API void Sovereign_FreeAnalysisMemory(void* ptr);
```

---

## Implementation Details

### Region-Based Allocator

```cpp
class RegionAllocator {
public:
    MemoryRegion* CreateRegion(const std::string& name, size_t size) {
        auto region = std::make_unique<MemoryRegion>();
        region->name = name;
        region->base = AllocateVirtualMemory(size);
        region->size = size;
        region->used = 0;
        
        // Initialize free list
        region->freeList.push_back({0, size});
        
        auto* ptr = region.get();
        m_regions[name] = std::move(region);
        return ptr;
    }
    
    void* Allocate(MemoryRegion* region, size_t size) {
        // Align size
        size = AlignUp(size, ALLOC_ALIGNMENT);
        
        // Find suitable free block
        for (auto& block : region->freeList) {
            if (block.size >= size) {
                void* ptr = region->base + block.offset;
                
                // Split block if necessary
                if (block.size > size) {
                    block.offset += size;
                    block.size -= size;
                } else {
                    // Remove block from free list
                    block = region->freeList.back();
                    region->freeList.pop_back();
                }
                
                region->used += size;
                return ptr;
            }
        }
        
        return nullptr;  // Out of memory
    }
    
    void Free(MemoryRegion* region, void* ptr, size_t size) {
        size = AlignUp(size, ALLOC_ALIGNMENT);
        
        size_t offset = (uint8_t*)ptr - region->base;
        region->freeList.push_back({offset, size});
        region->used -= size;
        
        // Coalesce adjacent free blocks
        CoalesceFreeBlocks(region);
    }
    
private:
    void CoalesceFreeBlocks(MemoryRegion* region) {
        // Sort by offset
        std::sort(region->freeList.begin(), region->freeList.end(),
                  [](const auto& a, const auto& b) {
                      return a.offset < b.offset;
                  });
        
        // Merge adjacent blocks
        for (size_t i = 0; i < region->freeList.size() - 1; ) {
            auto& current = region->freeList[i];
            auto& next = region->freeList[i + 1];
            
            if (current.offset + current.size == next.offset) {
                current.size += next.size;
                region->freeList.erase(region->freeList.begin() + i + 1);
            } else {
                ++i;
            }
        }
    }
    
    std::unordered_map<std::string, std::unique_ptr<MemoryRegion>> m_regions;
};
```

---

## Testing

```cpp
TEST(MemoryModel, RegionAllocation) {
    auto region = Sovereign_CreateRegion("TestRegion", 1024 * 1024);
    EXPECT_NE(region, nullptr);
    
    void* ptr1 = Sovereign_RegionAlloc(region, 1024);
    EXPECT_NE(ptr1, nullptr);
    
    void* ptr2 = Sovereign_RegionAlloc(region, 2048);
    EXPECT_NE(ptr2, nullptr);
    
    Sovereign_DestroyRegion(region);
}

TEST(MemoryModel, AnalysisMemory) {
    void* ptr = Sovereign_AllocAnalysisMemory(1024 * 1024);
    EXPECT_NE(ptr, nullptr);
    
    // Write and read
    memset(ptr, 0xAB, 1024 * 1024);
    EXPECT_EQ(((uint8_t*)ptr)[0], 0xAB);
    
    Sovereign_FreeAnalysisMemory(ptr);
}
```

---

## Summary

The Sovereign Memory Model provides:

- ✅ **Region-based allocation**
- ✅ **128 TB address space**
- ✅ **Incremental GC**
- ✅ **Analysis-optimized**
- ✅ **Multi-page size support**

**Status:** ✅ Complete
