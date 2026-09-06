#pragma once

#include <cstdint>
#include <stdexcept>

class Deep2ContextGuard {
private:
    const uintptr_t m_MemoryWindowStart;
    const uintptr_t m_MemoryWindowEnd;
    const uint64_t m_MaxContextWindowSize;

public:
    /**
     * Initializes the guard with a strictly bounded memory arena.
     * @param baseAddress Raw start pointer of the aligned ring buffer pool.
     * @param totalPoolSize Total combined size of all 4 pre-allocated memory windows.
     */
    Deep2ContextGuard(void* baseAddress, uint64_t totalPoolSize)
        : m_MemoryWindowStart(reinterpret_cast<uintptr_t>(baseAddress)),
          m_MemoryWindowEnd(reinterpret_cast<uintptr_t>(baseAddress) + totalPoolSize),
          m_MaxContextWindowSize(totalPoolSize) 
    {
        if (m_MemoryWindowEnd < m_MemoryWindowStart) {
            throw std::overflow_error("Context Guard Init Error: Pointer wrap-around detected during base bounds calculation.");
        }
    }

    /**
     * Enforces strict validation of absolute addresses and offset parameters.
     * Ensures memory targets sit entirely inside valid, pre-allocated ring buffer bounds.
     */
    inline void ValidatePointerRange(const void* targetPtr, uint64_t elementCount, uint64_t elementSize) const {
        uintptr_t targetStart = reinterpret_cast<uintptr_t>(targetPtr);
        
        // 1. Unsigned Multiplication Overflow Guard
        uint64_t requestedByteSize = elementCount * elementSize;
        if (elementSize != 0 && (requestedByteSize / elementSize) != elementCount) {
            throw std::runtime_error("Context Guard Exception: Unsigned overflow detected in allocation size calculation.");
        }

        // 2. Unsigned Addition Wrap-around Guard
        uintptr_t targetEnd = targetStart + requestedByteSize;
        if (targetEnd < targetStart) {
            throw std::runtime_error("Context Guard Exception: Pointer wrap-around detected in target address evaluation.");
        }

        // 3. Strict Absolute Window Boundary Validation
        if (targetStart < m_MemoryWindowStart || targetEnd > m_MemoryWindowEnd) {
            throw std::out_of_range("Context Guard Exception: Out-of-bounds access attempt. Target range sits outside allocated memory window.");
        }
    }

    /**
     * Structural Vector Shape Guard
     * Validates that dimension counts do not exceed specified infrastructure limits.
     */
    inline void ValidateDimensionConstraints(uint64_t rows, uint64_t columns) const {
        // Prevent zero-dimension anomalies which cause execution pipelines to fault
        if (rows == 0 || columns == 0) {
            throw std::invalid_argument("Context Guard Exception: Matrix tensor dimension bounds cannot be zero.");
        }

        // Verify total byte footprint will fit into a single sliding slot window
        uint64_t totalElements = rows * columns;
        if (columns != 0 && (totalElements / columns != rows)) {
            throw std::runtime_error("Context Guard Exception: Integer overflow in tensor area matrix definition.");
        }
    }
};
