#pragma once

#include <cstdint>
#include <cstddef>

// Ensure 32-byte alignment for AVX2/AVX-512
#ifdef _WIN32
#define LORA_ALIGN __declspec(align(32))
#else
#define LORA_ALIGN __attribute__((aligned(32)))
#endif

namespace RawrXD::MASM {

/**
 * @brief Memory-mapped context for MASM LoRA forward pass
 * 
 * Phase 18C.2: Fixed-layout struct for beacon-based MASM integration.
 * This struct is shared between C++ (manager) and MASM (compute).
 * 
 * Memory Layout (32-byte aligned):
 *   [0-3]:    alpha (float) - scaling factor
 *   [4-7]:    rank (int32) - LoRA rank r
 *   [8-11]:   input_dim (int32) - d (typically 384)
 *   [12-15]:  flags (uint32) - status/control bits
 *   [16-23]:  matrix_A_ptr (uint64) - pointer to A matrix (d × r)
 *   [24-31]:  matrix_B_ptr (uint64) - pointer to B matrix (r × d)
 *   [32-39]:  active (uint64) - non-zero if adapter is ready
 *   [40-47]:  reserved (uint64) - padding/cache line alignment
 * 
 * Total: 48 bytes (fits in single cache line on x64)
 */
struct LORA_ALIGN LoRAContext {
    // Scalar parameters
    float alpha;           // Scaling factor (typically 16.0)
    int32_t rank;          // r (typically 4-16)
    int32_t input_dim;     // d (typically 384)
    uint32_t flags;        // Status bits (see below)
    
    // Matrix pointers (64-bit for x64)
    const float* matrix_A; // Points to A matrix (d × r) in adapter
    const float* matrix_B; // Points to B matrix (r × d) in adapter
    
    // Control
    volatile uint64_t active; // Non-zero when adapter is valid
    uint64_t reserved;          // Padding
    uint64_t reserved2;         // Padding to reach 64 bytes
    
    // Flag definitions
    static constexpr uint32_t FLAG_READY = 0x00000001;      // Adapter loaded
    static constexpr uint32_t FLAG_AVX512 = 0x00000002;     // Use AVX-512 path
    static constexpr uint32_t FLAG_FMA3 = 0x00000004;     // Use FMA3
    static constexpr uint32_t FLAG_VALID = 0x80000000;    // Context valid
};

// Verify size and alignment
static_assert(sizeof(LoRAContext) == 64, "LoRAContext must be 64 bytes");
static_assert(alignof(LoRAContext) >= 32, "LoRAContext must be 32-byte aligned");

/**
 * @brief Global beacon pointer for MASM access
 * 
 * This volatile pointer is read by the MASM beacon to locate
 * the active LoRA context. Updated atomically by C++ when
 * adapters are swapped.
 */
extern "C" {
    // Global beacon - MASM reads this to find LoRA context
    extern volatile LoRAContext* g_loraContextBeacon;
    
    // MASM entry points
    extern "C" void ApplyLoRA_FMA3(float* output, const float* input, int64_t dim);
    extern "C" void ApplyLoRA_AVX512(float* output, const float* input, int64_t dim);
}

/**
 * @brief C++ interface to update the LoRA beacon
 * 
 * Thread-safe: Updates beacon pointer atomically
 */
class LoRABeaconManager {
public:
    static LoRABeaconManager& instance();
    
    /**
     * @brief Update beacon with new adapter context
     * @param context Pointer to LoRAContext (must remain valid)
     * @return true if beacon updated
     * 
     * Sets active=1 after validating context
     */
    bool updateBeacon(LoRAContext* context);
    
    /**
     * @brief Clear beacon (disable LoRA)
     */
    void clearBeacon();
    
    /**
     * @brief Check if beacon is active
     */
    bool isActive() const;
    
    /**
     * @brief Get current context (for debugging)
     */
    const LoRAContext* getContext() const;

private:
    LoRABeaconManager() = default;
};

} // namespace RawrXD::MASM
