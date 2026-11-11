#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <unordered_map>
#include <filesystem>
#include <mutex>
#include <atomic>
#include <xmmintrin.h>
#include <intrin.h>

// ============================================================================
// Beacon-Compatible LoRA Interface
// ============================================================================
// This header defines the memory layout shared between C++ (data provider)
// and MASM (execution engine). All structures are designed for:
// - 32-byte alignment (AVX-512 compatible)
// - C-compatible layout (no vtables, no exceptions)
// - Direct memory polling by assembly beacons

#ifdef __cplusplus
extern "C" {
#endif

// Alignment macros
#define LORA_ALIGN_32 __declspec(align(32))
#define LORA_ALIGN_64 __declspec(align(64))

// Maximum dimensions for static allocation
#define LORA_MAX_RANK 64
#define LORA_MAX_HIDDEN_DIM 768

// Beacon status codes
enum LoRABeaconStatus {
    LORA_BEACON_INACTIVE = 0,      // No adapter loaded
    LORA_BEACON_ACTIVE = 1,        // Adapter ready for use
    LORA_BEACON_UPDATING = 2,      // Weights being modified (lock out)
    LORA_BEACON_COMPOSITE = 3      // Multiple adapters chained
};

// ============================================================================
// Aligned Weight Buffers
// ============================================================================
// These structures ensure SIMD-friendly memory layout for MASM FMA operations

typedef struct LORA_ALIGN_32 {
    float data[LORA_MAX_RANK * LORA_MAX_HIDDEN_DIM];
} LoRAMatrixA;  // Shape: [rank, hidden_dim]

typedef struct LORA_ALIGN_32 {
    float data[LORA_MAX_HIDDEN_DIM * LORA_MAX_RANK];
} LoRAMatrixB;  // Shape: [hidden_dim, rank]

// Intermediate buffer for A*x computation
typedef struct LORA_ALIGN_32 {
    float data[LORA_MAX_RANK];
} LoRATempBuffer;

// Output buffer for LoRA delta (B*A*x)
typedef struct LORA_ALIGN_32 {
    float data[LORA_MAX_HIDDEN_DIM];
} LoRADeltaBuffer;

// ============================================================================
// Beacon State Structure (Memory-Mapped)
// ============================================================================
// This is the primary coordination point. MASM polls this struct directly.
// Layout is fixed and versioned for binary compatibility.

// ============================================================================
// Beacon State Structure (Memory-Mapped) - Must be exactly 64 bytes
// ============================================================================
// This is the primary coordination point. MASM polls this struct directly.
// Layout is fixed and versioned for binary compatibility.

#pragma pack(push, 8)
struct __declspec(align(64)) LoRABeaconState {
    // Header (8 bytes) - Version and status
    uint32_t version;              // Format version (currently 1)
    uint32_t status;               // LoRABeaconStatus enum value
    
    // Dimensions (8 bytes)
    uint32_t rank;                 // Actual rank (<= LORA_MAX_RANK)
    uint32_t hidden_dim;           // Actual hidden dim (<= LORA_MAX_HIDDEN_DIM)
    
    // Pointers (16 bytes) - MASM reads these directly
    float* ptr_A;                  // Aligned pointer to matrix A
    float* ptr_B;                  // Aligned pointer to matrix B
    
    // Scaling (8 bytes)
    float scale_factor;            // Alpha scaling (typically 1.0)
    float reserved;                // Padding to maintain alignment
    
    // Composite chain (16 bytes) - For Phase 18D
    LoRABeaconState* next_adapter;  // Linked list for chaining
    float composite_weight;         // Weight in composite blend
    
    // Padding to reach exactly 64 bytes
    uint32_t extra_padding[4];      // 16 bytes padding
};
#pragma pack(pop)

// Static assertion for size (should be exactly 64 bytes)
// static_assert(sizeof(LoRABeaconState) == 64, "LoRABeaconState must be 64 bytes");

// ============================================================================
// Beacon Chain Structure (Phase 18D) - Must be exactly 64 bytes
// ============================================================================
// For multi-adapter composition: W = W_0 + sum(alpha_i * B_i * A_i)

#pragma pack(push, 8)
struct __declspec(align(64)) LoRABeaconChain {
    uint32_t adapter_count;        // Number of adapters in chain
    uint32_t active_count;         // Currently active (for atomic updates)

    LoRABeaconState* head;         // First adapter in chain (8 bytes)
    LoRABeaconState* tail;         // Last adapter in chain (8 bytes)

    // Pre-computed aggregate for fast path
    float aggregate_scale;         // Sum of all scale factors
    uint32_t flags;                // Chain behavior flags

    // Padding to reach exactly 64 bytes
    // Current: 8 + 16 + 8 = 32 bytes, need 32 more
    uint32_t chain_padding[8];     // 32 bytes padding to reach 64 bytes
};
#pragma pack(pop)

static_assert(sizeof(LoRABeaconChain) == 64, "LoRABeaconChain must be 64 bytes");

// ============================================================================
// Global Beacon State (for MASM EXTERNDEF access)
// ============================================================================
extern LoRABeaconState g_beacon_state;
extern LoRABeaconChain g_beacon_chain;

// ============================================================================
// C++ Provider Interface
// ============================================================================
// These functions are called by C++ to populate beacon state

// Get the singleton beacon state pointer (for MASM polling)
LoRABeaconState* lora_get_beacon(void);

// Get the beacon chain pointer (Phase 18D)
LoRABeaconChain* lora_get_beacon_chain(void);

// Update beacon with new adapter (thread-safe)
// Returns 0 on success, non-zero on error
int lora_update_beacon(
    const float* A_data,           // Source A matrix [rank x hidden]
    const float* B_data,           // Source B matrix [hidden x rank]
    uint32_t rank,
    uint32_t hidden_dim,
    float scale_factor
);

// Clear beacon (deactivate LoRA)
void lora_clear_beacon(void);

// Set beacon status atomically
void lora_set_beacon_status(uint32_t status);

// Get current beacon status
uint32_t lora_get_beacon_status(void);

// ============================================================================
// MASM Entry Points (Called from Assembly)
// ============================================================================
// These are implemented in MASM and called via function pointer

typedef void (*LoRAApplyFunc)(
    const float* base_output,      // W_0 * x result
    float* result,                 // Output buffer
    uint64_t token_count,          // Number of tokens
    const LoRABeaconState* beacon  // Active beacon
);

// Global function pointer (set by MASM initialization)
extern LoRAApplyFunc g_lora_apply_asm;

// ============================================================================
// Memory Allocation Helpers
// ============================================================================

// Allocate aligned memory for matrices
void* lora_aligned_alloc(size_t size, size_t alignment);
void lora_aligned_free(void* ptr);

// Check if pointer is properly aligned for AVX-512
int lora_is_aligned_avx512(const void* ptr);

// Prefetch hints for MASM
#define LORA_PREFETCH_T0(addr) _mm_prefetch((const char*)(addr), _MM_HINT_T0)
#define LORA_PREFETCH_T1(addr) _mm_prefetch((const char*)(addr), _MM_HINT_T1)

#ifdef __cplusplus
} // extern "C"

namespace RawrXD {

// ============================================================================
// C++ Wrapper Classes (for IDE integration)
// ============================================================================

// Aligned buffer wrapper with RAII
template<size_t Alignment = 32>
class AlignedBuffer {
public:
    AlignedBuffer() = default;  // Default constructor for unordered_map
    AlignedBuffer(size_t num_floats);
    ~AlignedBuffer();
    
    // Non-copyable
    AlignedBuffer(const AlignedBuffer&) = delete;
    AlignedBuffer& operator=(const AlignedBuffer&) = delete;
    
    // Movable
    AlignedBuffer(AlignedBuffer&& other) noexcept;
    AlignedBuffer& operator=(AlignedBuffer&& other) noexcept;
    
    float* data() { return m_data; }
    const float* data() const { return m_data; }
    size_t size() const { return m_size; }
    bool is_aligned() const;
    
private:
    float* m_data = nullptr;
    void* m_original = nullptr;
    size_t m_size = 0;
};

// Beacon manager for C++ integration
class BeaconAdapterManager {
public:
    static BeaconAdapterManager& instance();
    
    // Load adapter from file into aligned buffers
    bool load_adapter(const std::string& name);
    void unload_adapter(const std::string& name);
    
    // Activate adapter (updates beacon atomically)
    bool activate_adapter(const std::string& name);
    void deactivate_adapter();
    
    // Get current beacon state (for monitoring)
    const LoRABeaconState* get_beacon() const { return m_beacon; }
    
    // Check if beacon is active
    bool is_active() const;
    
    // Get adapter cache directory
    std::filesystem::path get_cache_dir() const;

private:
    BeaconAdapterManager();
    ~BeaconAdapterManager();
    
    // Parse .lora file into aligned buffers
    bool parse_lora_file(const std::filesystem::path& path);
    
    LoRABeaconState* m_beacon = nullptr;  // Memory-mapped beacon
    std::unordered_map<std::string, std::pair<
        AlignedBuffer<32>,  // A matrix
        AlignedBuffer<32>   // B matrix
    >> m_adapter_buffers;
    
    std::string m_active_adapter;
    std::filesystem::path m_cache_dir;
    mutable std::mutex m_mutex;
};

} // namespace RawrXD

#endif // __cplusplus
