#pragma once
/**
 * @file arena.h
 * @brief Zero-Syscall Arena Allocator for SlotLattice
 * 
 * Strategy: "Bulk Offshoring"
 * - One VirtualAlloc at startup (MEM_RESERVE | MEM_COMMIT)
 * - Zero syscalls in hot path - Acquire() is pure pointer arithmetic
 * - Eliminates ~82ms tax from per-slot ::operator new / VirtualAlloc calls
 * 
 * Usage:
 *   FastArena arena;
 *   arena.Init(256, 105 * 1024 * 1024);  // 256 slots, 105MB each
 *   void* slot0 = arena.Acquire(0);       // Pure arithmetic, no syscalls
 */

#include <cstdint>
#include <cstddef>

extern "C" {
    /**
     * Reserve virtual address space for the entire arena.
     * Does NOT commit physical pages - those are committed on first Acquire.
     * @param slots Number of slots
     * @param slot_size Size per slot in bytes (will be aligned to 64 bytes)
     * @return Base address of reserved arena, or nullptr on failure
     */
    void* Arena_Reserve_All(size_t slots, size_t slot_size);
    
    /**
     * Commit physical pages for a specific slot. Called once per slot on first use.
     * @param base Base address from Arena_Reserve_All
     * @param index Slot index (0-based)
     * @param slot_size Aligned slot size (must match Arena_Reserve_All)
     * @return Pointer to committed slot, or nullptr on failure
     */
    void* Arena_Commit_Slot(void* base, size_t index, size_t slot_size);
    
    /**
     * Pure arithmetic - zero syscalls. Use after slot is committed.
     * @param base Base address from Arena_Reserve_All
     * @param index Slot index (0-based)
     * @param slot_size Aligned slot size (must match Arena_Reserve_All)
     * @return Direct memory pointer to the slot
     */
    void* Arena_Get_Ptr(void* base, size_t index, size_t slot_size);
    
    /**
     * Release the entire arena.
     * @param base Base address from Arena_Reserve_All
     * @return true on success, false on failure
     */
    bool Arena_Release(void* base);
}

/**
 * @class FastArena
 * @brief RAII wrapper for zero-syscall arena allocation
 * 
 * Strategy: Reserve virtual address space at Init().
 * Commit physical pages on first Acquire() per slot.
 * Subsequent Acquire() calls use pure pointer arithmetic (zero syscalls).
 */
class FastArena {
public:
    FastArena() : base_(nullptr), aligned_size_(0), slot_count_(0) {}
    
    ~FastArena() {
        if (base_) {
            Arena_Release(base_);
            base_ = nullptr;
        }
    }
    
    /**
     * Reserve virtual address space for the arena.
     * Physical pages are committed on-demand per slot.
     * @param slots Number of slots
     * @param slot_size Size per slot in bytes (will be aligned to 64 bytes)
     * @return true on success, false on failure
     */
    bool Init(size_t slots, size_t slot_size) {
        aligned_size_ = (slot_size + 63) & ~size_t(63);
        slot_count_ = slots;
        base_ = Arena_Reserve_All(slots, aligned_size_);
        return base_ != nullptr;
    }
    
    /**
     * Acquire a slot by index. Commits physical pages on first access.
     * Subsequent calls for the same index use pure pointer arithmetic.
     * @param index Slot index (0-based)
     * @return Pointer to slot memory
     */
    inline void* Acquire(size_t index) {
        return Arena_Commit_Slot(base_, index, aligned_size_);
    }
    
    /**
     * Get pointer to a slot using pure arithmetic (zero syscalls).
     * Only valid after the slot has been committed via Acquire().
     * @param index Slot index (0-based)
     * @return Direct memory pointer to the slot
     */
    inline void* GetPtr(size_t index) {
        return Arena_Get_Ptr(base_, index, aligned_size_);
    }
    
    /**
     * Get the base address of the arena.
     */
    void* Base() const { return base_; }
    
    /**
     * Get the aligned slot size.
     */
    size_t SlotSize() const { return aligned_size_; }
    
    /**
     * Get the number of slots.
     */
    size_t SlotCount() const { return slot_count_; }
    
    /**
     * Calculate the address of a slot without function call overhead.
     */
    inline void* AddressOf(size_t index) const {
        return static_cast<char*>(base_) + (index * aligned_size_);
    }
    
private:
    void* base_;
    size_t aligned_size_;
    size_t slot_count_;
    
    FastArena(const FastArena&) = delete;
    FastArena& operator=(const FastArena&) = delete;
};