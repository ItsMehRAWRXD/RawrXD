// ==============================================================================
// SwarmV29_Kernel.h
// PHASE-29: C++ Interface to MASM PQC Kernels
// Target: 70B @ 150TPS via AVX-512 Vectorized NTT
// ------------------------------------------------------------------------------
// Zero-dependency standard C++17/20 header. Maps assembly procedures to C++
// types using extern "C" linkage for ABI compatibility.
//
// CRITICAL: All buffers MUST be 64-byte aligned (use _aligned_malloc or
// equivalent). vmovdqa64 will #GP fault on unaligned addresses.
// ==============================================================================

#pragma once
#include <cstdint>
#include <cstdlib>

#ifdef __cplusplus
extern "C" {
#endif

// -- PQC Primitives --

/// Bit-Reversal Permutation (Required for Cooley-Tukey NTT)
/// Reorders polynomial coefficients into bit-reversed index order.
/// @param array   64-byte aligned coefficient buffer (in-place)
/// @param N       Size of array (must be power of 2)
/// @param log2N   Precomputed log2(N)
void SwarmV29_BitReverse(uint64_t* array, uint64_t N, uint64_t log2N);

/// Full NTT Transform (Cooley-Tukey Stage Loop)
/// Executes iterative in-place NTT using AVX-512 butterflies.
/// @param array        64-byte aligned coefficient buffer (Input/Output)
/// @param N            Size of transform (power of 2, e.g. 256)
/// @param twiddleTable 64-byte aligned precomputed twiddle factors
/// @param Q            Modulus (e.g. 3329 for Kyber, 8380417 for Dilithium)
/// @param Q_inv        Montgomery constant (-1/Q mod 2^32)
void SwarmV29_NTT_Transform(
    uint64_t* array,
    uint64_t N,
    uint64_t* twiddleTable,
    uint64_t Q,
    uint64_t Q_inv
);

/// Montgomery Multiplication (AVX-512, 8 lanes)
/// Computes (A * B * R^-1) mod Q for 8 coefficients simultaneously.
/// @param A      64-byte aligned input vector A
/// @param B      64-byte aligned input vector B
/// @param out    64-byte aligned output buffer
/// @param Q      Modulus
/// @param Q_inv  Montgomery constant
void SwarmV29_Montgomery_Mul_AVX512(
    uint64_t* A,
    uint64_t* B,
    uint64_t* out,
    uint64_t Q,
    uint64_t Q_inv
);

// -- Loop-Unrolled Butterflies (Phase-29d Throughput Optimization) --

/// NTT Butterfly 2x Unrolled (Interleaved)
/// Processes TWO independent butterflies in parallel to saturate AVX-512 ports.
/// Hides vpmullq latency (~3-5 cycles) by interleaving operations.
/// @param A1_ptr   64-byte aligned A1 coefficients (8 lanes)
/// @param B1_ptr   64-byte aligned B1 coefficients (8 lanes)
/// @param A2_ptr   64-byte aligned A2 coefficients (8 lanes)
/// @param B2_ptr   64-byte aligned B2 coefficients (8 lanes)
/// @param W1_ptr   64-byte aligned W1 twiddle factors (8 lanes)
/// @param W2_ptr   64-byte aligned W2 twiddle factors (8 lanes)
/// NOTE: ZMM15 (Q) and ZMM16 (Q_INV) must be pre-loaded by caller.
void SwarmV29_NTT_Butterfly_2x(
    uint64_t* A1_ptr,
    uint64_t* B1_ptr,
    uint64_t* A2_ptr,
    uint64_t* B2_ptr,
    uint64_t* W1_ptr,
    uint64_t* W2_ptr
);

/// NTT Butterfly 4x Unrolled (Maximum Throughput)
/// Processes FOUR independent butterflies in parallel to maximize AVX-512
/// execution port saturation. Uses upper ZMM registers (ZMM17-ZMM31) to
/// avoid stack spills.
/// @param A_ptr    64-byte aligned A coefficients array (4 x 8 lanes = 256 bytes)
/// @param B_ptr    64-byte aligned B coefficients array (4 x 8 lanes = 256 bytes)
/// @param W_ptr    64-byte aligned W twiddle factors array (4 x 8 lanes = 256 bytes)
/// NOTE: ZMM15 (Q) and ZMM16 (Q_INV) must be pre-loaded by caller.
void SwarmV29_NTT_Butterfly_4x(
    uint64_t* A_ptr,
    uint64_t* B_ptr,
    uint64_t* W_ptr
);

// -- Quantum Sovereignty Primitives (Enhancements 130-136) --

/// Kyber-1024 PQC Encapsulation
/// Full KEM encapsulation using AVX-512 NTT pipeline.
/// @param publicKey     1184-byte public key
/// @param ciphertext    1568-byte output ciphertext
/// @param sharedSecret  32-byte output shared secret
/// @return 0 on success, non-zero on failure
uint64_t SwarmV29_Kyber_1024_PQC_Encapsulate(
    uint8_t* publicKey,
    uint8_t* ciphertext,
    uint8_t* sharedSecret
);

/// Dilithium5 PQC Signature Generation
/// NTT-based signature generation with Dilithium-5 parameters.
/// @param message    Message to sign
/// @param msgLen     Message length in bytes
/// @param secretKey  4896-byte secret key
/// @param signature  4595-byte output signature
/// @return 0 on success, non-zero on failure
uint64_t SwarmV29_Dilithium5_PQC_Sign(
    uint8_t* message,
    uint64_t msgLen,
    uint8_t* secretKey,
    uint8_t* signature
);

/// Entropy Mixer (RDRAND + RDTSC Whitening)
/// Blends hardware TRNG with TSC jitter for cryptographically safe seeds.
/// @return 64-bit whitened entropy seed (keep in register, never spill)
uint64_t SwarmV29_Entropy_Mixer(void);

/// Atemporal Quantum Lock (Surgical lfence barrier)
/// Minimal memory barrier: only lfence for load ordering.
/// NEVER use mfence/sfence unless explicitly synchronizing across cache domains.
void SwarmV29_Atemporal_Quantum_Lock(void);

/// AVX-512 Feature Detection
/// Runtime check for AVX-512F support (CPUID leaf 7, EBX bit 16).
/// Must be called before any AVX-512 kernel to prevent #UD crashes.
uint64_t SwarmV29_AVX512_Feature_Detect(void);

// -- Thread Synchronization (Titan Barriers) --

/// Titan Spin-Wait Barrier
/// Low-latency userspace spin-wait on a signal flag.
/// @param signal_address     Pointer to volatile uint32_t flag
/// @param target_ready_value Value indicating processing request
/// @return true when condition met
bool Titan_Spin_Wait_On_Signal(volatile uint32_t* signal_address, uint32_t target_ready_value);

/// Titan Atomic Signal Release
/// Atomic release with full memory barrier via lock xchg.
/// @param signal_address Pointer to volatile uint32_t flag
/// @param update_value   Value to assert atomically
/// @return true on success
bool Titan_Atomic_Signal_Release(volatile uint32_t* signal_address, uint32_t update_value);

// -- 0G Atomic Hijack System (Phase-29b) --

/// SwarmV29 Orchestrator Loop
/// The 150TPS rhythm controller with atomic pre-emption gatekeeping.
/// Runs indefinitely until externally halted. Checks HijackFlag at every
/// loop boundary; if set, performs full ZMM context save, executes 0G packet,
/// restores context, and resumes standard rhythm.
void SwarmV29_Orchestrator_Loop(void);

/// Titan Trigger 0G Hijack
/// Atomic trigger callable from any thread. Under x86-64 TSO, a simple mov
/// is sufficient for cross-thread visibility without explicit barriers.
/// The orchestrator will divert to Process_ZeroG_Packet on the next loop boundary.
void Titan_Trigger_0G_Hijack(void);

/// Titan Clear 0G Hijack
/// Manual reset of the hijack flag (if Process_ZeroG_Packet does not self-clear).
void Titan_Clear_0G_Hijack(void);

/// Process Zero-G Packet (Full NTT Transform)
/// Executes the complete 7-layer Kyber-1024 NTT transform on a 512-byte packet.
/// Called by the orchestrator when HijackFlag is set, or can be called directly.
/// @param source      64-byte aligned source buffer (512 bytes = 256 coefficients)
/// @param destination 64-byte aligned destination buffer (512 bytes)
/// @return 0 on success, 0xC0000005 on null pointer
uint64_t Process_ZeroG_Packet(
    uint64_t* source,
    uint64_t* destination
);

// -- Inverse NTT (INTT) Pipeline (Phase-29c) --

/// INTT Butterfly (Inverse Cooley-Tukey)
/// Performs the inverse butterfly operation: A' = A + B*W_inv, B' = A - B*W_inv.
/// Identical to forward butterfly but uses modular inverse of twiddle factors.
/// @param ZMM0 = A (Coefficients 1, 8 lanes) - PRE-LOADED
/// @param ZMM1 = B (Coefficients 2, 8 lanes) - PRE-LOADED
/// @param ZMM2 = W_inv (Inverse Twiddle Factors) - PRE-LOADED
/// @param ZMM15 = Q (Modulus) - PRE-LOADED by caller
/// @param ZMM16 = Q_INV (Montgomery Constant) - PRE-LOADED by caller
void SwarmV29_INTT_Butterfly(void);

/// Full INTT Transform (Inverse Cooley-Tukey Stage Loop)
/// Executes iterative in-place INTT using AVX-512 butterflies, followed by
/// final scaling by N^-1 mod Q to recover the original polynomial.
/// @param array        64-byte aligned coefficient buffer (Input/Output)
/// @param N            Size of transform (power of 2, e.g. 256)
/// @param invTwiddleTable 64-byte aligned precomputed inverse twiddle factors
/// @param Q            Modulus (e.g. 3329 for Kyber, 8380417 for Dilithium)
/// @param Q_inv        Montgomery constant (-1/Q mod 2^32)
/// @param N_inv        Modular inverse of N (N^-1 mod Q) for final scaling
void SwarmV29_INTT_Transform(
    uint64_t* array,
    uint64_t N,
    uint64_t* invTwiddleTable,
    uint64_t Q,
    uint64_t Q_inv,
    uint64_t N_inv
);

/// Generate Forward Twiddle Factor Table
/// Computes w^k mod Q for k = 0, 1, ..., N/2 - 1.
/// @param table    Output buffer (must hold N/2 elements, 64-byte aligned)
/// @param N        Size of transform (power of 2)
/// @param Q        Modulus
/// @param root     Primitive root of unity (e.g., 17 for Kyber-1024)
void SwarmV29_Generate_Twiddle_Table(
    uint64_t* table,
    uint64_t N,
    uint64_t Q,
    uint64_t root
);

/// Generate Inverse Twiddle Factor Table
/// Computes w^-k mod Q for k = 0, 1, ..., N/2 - 1 using Fermat's Little Theorem.
/// @param table    Output buffer (must hold N/2 elements, 64-byte aligned)
/// @param N        Size of transform (power of 2)
/// @param Q        Modulus
/// @param root     Primitive root of unity
void SwarmV29_Generate_Inverse_Twiddle_Table(
    uint64_t* table,
    uint64_t N,
    uint64_t Q,
    uint64_t root
);

/// Compute Modular Inverse of N
/// Computes N^-1 mod Q using Fermat's Little Theorem: N^-1 = N^(Q-2) mod Q.
/// @param N  Size of transform
/// @param Q  Modulus
/// @return   N^-1 mod Q
uint64_t SwarmV29_Compute_N_Inverse(uint64_t N, uint64_t Q);

// -- Brutal Compression (Phase-29e Bandwidth Optimization) --

/// Brutal Pack: Compress 32-bit coefficients to 16-bit
/// Packs 32x 32-bit coefficients into 32x 16-bit values for bandwidth reduction.
/// Achieves 50% memory bandwidth reduction for PQC coefficient transmission.
/// @param src    64-byte aligned source buffer (32-bit coefficients)
/// @param dest   64-byte aligned destination buffer (16-bit packed)
/// @param count  Number of 512-bit blocks to process
/// @return 0 on success, 0xDEADBEEF on misaligned source, 0xBADC0DE on misaligned dest
uint64_t SwarmV29_Brutal_Pack(
    uint64_t* src,
    uint16_t* dest,
    uint64_t count
);

/// Brutal Unpack: Expand 16-bit coefficients to 32-bit
/// Restores 16-bit packed coefficients to full 32-bit precision for NTT processing.
/// @param src    64-byte aligned source buffer (16-bit packed)
/// @param dest   64-byte aligned destination buffer (32-bit expanded)
/// @param count  Number of 512-bit blocks to process
/// @return 0 on success, error code on failure
uint64_t SwarmV29_Brutal_Unpack(
    uint16_t* src,
    uint64_t* dest,
    uint64_t count
);

/// Brutal Pack with Saturation (Signed)
/// Packs with signed saturation for coefficients that may exceed 16-bit range.
/// @param src    64-byte aligned source buffer
/// @param dest   64-byte aligned destination buffer
/// @param count  Number of 512-bit blocks
/// @return 0 on success, error code on failure
uint64_t SwarmV29_Brutal_Pack_Saturate(
    uint64_t* src,
    uint16_t* dest,
    uint64_t count
);

/// Brutal Unpack with Scaling (INTT Final Pass)
/// Unpacks and scales by N^-1 for INTT final scaling pass.
/// @param src    64-byte aligned source buffer (16-bit packed)
/// @param dest   64-byte aligned destination buffer (32-bit expanded)
/// @param count  Number of 512-bit blocks
/// @param scale  Scale factor (N^-1 mod Q)
/// @return 0 on success, error code on failure
uint64_t SwarmV29_Brutal_Unpack_With_Scale(
    uint16_t* src,
    uint64_t* dest,
    uint64_t count,
    uint64_t scale
);

// -- Pool Allocator (Phase-29e Cache-Aligned Memory) --

/// Initialize the Pool Allocator
/// Reserves a large memory slab (1MB default) for fast sub-allocation.
/// Must be called once before any Alloc_Slab calls.
void SwarmV29_Init_Pool(void);

/// Allocate Aligned Slab from Pool
/// Carves out a 64-byte aligned block from the pre-reserved pool.
/// NO syscalls - just pointer arithmetic for ultra-fast allocation.
/// @param size  Requested size in bytes
/// @return      64-byte aligned pointer, or NULL if pool exhausted
void* SwarmV29_Alloc_Slab(uint64_t size);

/// Reset Pool (Fast Clear)
/// Resets the pool pointer to base without freeing memory.
/// Use between NTT rounds for zero-allocation recycling.
void SwarmV29_Reset_Pool(void);

/// Free Pool (Release to OS)
/// Releases the entire pool back to the OS via VirtualFree.
/// Call only when completely done with the pool.
void SwarmV29_Free_Pool(void);

// -- Verification (Phase-29e Integrity Check) --

/// Verify Pack/Unpack Integrity
/// Performs a round-trip test: Pack -> Unpack -> Compare.
/// Critical for debugging buffer alignment or truncation errors.
/// @param original  Original 32-bit coefficient buffer
/// @param count     Number of 512-bit blocks
/// @return 0 on match, 1 on mismatch/corruption
int SwarmV29_Verify_Integrity(
    uint64_t* original,
    uint64_t count
);

// -- Cache-Line Aligned Sync Block (False Sharing Prevention) --

#ifdef __cplusplus
#include <atomic>

namespace SwarmV29 {

/// 64-byte aligned synchronization block to prevent false sharing.
/// Place one per core/thread. The padding ensures the flag occupies
/// its own cache line, eliminating MESI Invalidation storms.
struct alignas(64) SyncBlock {
    volatile uint32_t signal_flag;
    uint8_t padding[60];  // Pad to 64 bytes
};

} // namespace SwarmV29
#endif // __cplusplus

#ifdef __cplusplus
} // extern "C"
#endif
/// @return 1 if AVX-512F is supported, 0 otherwise
uint64_t SwarmV29_AVX512_Feature_Detect(void);

/// Zero-Knowledge Telemetry Proof
/// Generates commitment proving throughput without leaking weights.
/// @return 64-bit commitment value
uint64_t SwarmV29_Zero_Knowledge_Telemetry_Proof(void);

/// Quantum Residue Purge
/// Securely overwrites sensitive buffers using non-temporal stores.
/// @param buffer  Pointer to buffer (must be 64-byte aligned)
/// @param size    Size in bytes (must be multiple of 64)
void SwarmV29_Quantum_Residue_Purge(void* buffer, uint64_t size);

#ifdef __cplusplus
} // extern "C"
#endif

// ==============================================================================
// C++ Helper: Aligned Memory Allocation
// ==============================================================================
#ifdef __cplusplus
#include <memory>

namespace SwarmV29 {

/// RAII wrapper for 64-byte aligned memory (required for AVX-512)
template<typename T>
class AlignedBuffer {
public:
    explicit AlignedBuffer(size_t count)
        : m_ptr(static_cast<T*>(_aligned_malloc(count * sizeof(T), 64)))
        , m_count(count)
    {
        if (!m_ptr) {
            throw std::bad_alloc();
        }
    }

    ~AlignedBuffer() {
        if (m_ptr) {
            _aligned_free(m_ptr);
        }
    }

    // Non-copyable
    AlignedBuffer(const AlignedBuffer&) = delete;
    AlignedBuffer& operator=(const AlignedBuffer&) = delete;

    // Movable
    AlignedBuffer(AlignedBuffer&& other) noexcept
        : m_ptr(other.m_ptr), m_count(other.m_count)
    {
        other.m_ptr = nullptr;
        other.m_count = 0;
    }

    T* get() const noexcept { return m_ptr; }
    size_t count() const noexcept { return m_count; }
    T* begin() const noexcept { return m_ptr; }
    T* end() const noexcept { return m_ptr + m_count; }
    T& operator[](size_t i) { return m_ptr[i]; }
    const T& operator[](size_t i) const { return m_ptr[i]; }

private:
    T* m_ptr;
    size_t m_count;
};

/// Precomputed Kyber-1024 constants
constexpr uint64_t KYBER_Q     = 3329;
constexpr uint64_t KYBER_Q_INV = 62209;   // (-1/3329) mod 2^32

/// Precomputed Dilithium-5 constants
constexpr uint64_t DILITHIUM_Q     = 8380417;
constexpr uint64_t DILITHIUM_Q_INV = 58722433; // (-1/8380417) mod 2^32

} // namespace SwarmV29
#endif // __cplusplus
