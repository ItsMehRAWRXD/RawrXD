// ============================================================================
// Sovereign_ABI.h — Stable ABI between C++ Control Plane and MASM Execution Plane
// ============================================================================
// Purpose: Define the contract between layers so each can be benchmarked,
//          certified, and promoted independently.
//
// Layers:
//   Control Plane (C++)    →  Execution Plane (MASM)  →  Control Plane (C++)
//        │                           │                         │
//   B014/B015 profiler        SIMD/dequant kernels      RingTrapdoor sink
//   StreamRouter                Fused primitives          Telemetry/Control
//   Residency manager           Dot-product loops           Cancellation
//
// Rules:
//   1. All structs are packed with explicit alignment.
//   2. All function pointers use explicit calling convention.
//   3. Version field present in every struct for forward compatibility.
//   4. No C++ exceptions, RTTI, or STL across the boundary.
// ============================================================================

#ifndef SOVEREIGN_ABI_H
#define SOVEREIGN_ABI_H

#include <cstdint>
#include <cstddef>

// ============================================================================
// ABI Versioning
// ============================================================================
#define SOVEREIGN_ABI_VERSION_MAJOR 1
#define SOVEREIGN_ABI_VERSION_MINOR 0
#define SOVEREIGN_ABI_VERSION_PATCH 0

// ============================================================================
// Alignment macros (match MASM ALIGN directives)
// ============================================================================
#ifdef _MSC_VER
    #define SOV_ALIGN(x) __declspec(align(x))
#else
    #define SOV_ALIGN(x) __attribute__((aligned(x)))
#endif

// ============================================================================
// 1. Execution Plane — Kernel Dispatch Table
// ============================================================================
// The C++ control plane populates this table with function pointers.
// MASM routines are registered here, then called via indirection.
// This allows A/B testing: swap C++ vs MASM implementation at runtime.

struct SOV_ALIGN(64) SovereignKernelTable {
    uint32_t abi_version;       // Must be SOVEREIGN_ABI_VERSION_MAJOR
    uint32_t flags;             // Feature bits (see below)
    uint64_t reserved0;

    // Dequantization kernels
    // Signature: void fn(const void* src, float* dst, size_t n_elements, const void* params)
    typedef void (*DequantizeFn)(const void* src, float* dst, size_t n, const void* params);
    DequantizeFn dequant_q4_k;      // Q4_K_M → F32
    DequantizeFn dequant_q4_0;      // Q4_0 → F32
    DequantizeFn dequant_q8_0;      // Q8_0 → F32
    DequantizeFn dequant_q6_k;      // Q6_K → F32

    // Dot-product kernels
    // Signature: float fn(const float* a, const float* b, int n)
    typedef float (*DotProductFn)(const float* a, const float* b, int n);
    DotProductFn dot_f32_scalar;
    DotProductFn dot_f32_avx2;
    DotProductFn dot_f32_avx512;

    // Fused primitives
    // Signature: void fn(const float* a, const float* b, float* out, int n)
    typedef void (*FusedSiluRMSNormFn)(const float* x, const float* weight, float* out, int n, float eps);
    FusedSiluRMSNormFn fused_silu_rmsnorm;

    // Reserved slots for future kernels (maintains table size stability)
    void* reserved_kernels[16];
};

// Kernel table feature flags
#define SOV_KERNEL_HAS_AVX512    0x00000001u
#define SOV_KERNEL_HAS_AMX       0x00000002u
#define SOV_KERNEL_HAS_FMA       0x00000004u
#define SOV_KERNEL_HAS_VNNI     0x00000008u

// ============================================================================
// 2. Control Plane → Execution Plane — Invocation Context
// ============================================================================
// Passed to every kernel invocation. Carries cancellation epoch, layer info,
// and pointers back to control-plane telemetry hooks.

struct SOV_ALIGN(64) SovereignInvokeContext {
    uint32_t abi_version;
    uint32_t layer_index;           // Which transformer layer
    uint32_t head_index;              // Which attention head (if applicable)
    uint32_t token_position;          // Position in sequence

    // Cancellation epoch (read-only for execution plane)
    // Execution plane must poll this and abort if epoch changes.
    const volatile uint64_t* cancel_epoch;
    uint64_t expected_epoch;          // Epoch at invocation start

    // Telemetry sink (optional, may be null)
    // Execution plane calls this to emit events without knowing the sink type.
    typedef void (*TelemetryHook)(uint32_t event_type, uint64_t timestamp_ns, const void* data, size_t data_len);
    TelemetryHook telemetry;

    // User data (opaque to execution plane, used by telemetry hook)
    void* telemetry_user_data;

    // Reserved for future expansion
    uint64_t reserved[4];
};

// Telemetry event types (execution plane emits these)
#define SOV_EVENT_DEQUANT_START     0x10
#define SOV_EVENT_DEQUANT_END       0x11
#define SOV_EVENT_MATMUL_START      0x20
#define SOV_EVENT_MATMUL_END        0x21
#define SOV_EVENT_KERNEL_DISPATCH   0x30
#define SOV_EVENT_CANCEL_CHECK      0x40

// ============================================================================
// 3. Control Plane — RingTrapdoor Telemetry Sink
// ============================================================================
// Second sink for B014 profiler data. Writes into SPSC shared ring.
// Does NOT replace the authoritative JSON/CSV export.

struct SOV_ALIGN(64) SovereignRingTelemetryConfig {
    uint32_t abi_version;
    uint32_t ring_slot_count;       // Power of 2, default 64
    uint32_t ring_slot_size;        // Default 4096
    uint32_t flags;

    // Shared memory handle (platform-specific)
#ifdef _WIN32
    void* hMapFile;                 // HANDLE to file mapping
#else
    int   shm_fd;
#endif
    void* ring_base;                // Mapped view base address

    // Cancellation epoch pointer (shared with InvokeContext)
    volatile uint64_t* cancel_epoch;
};

// Ring telemetry feature flags
#define SOV_RING_TELEMETRY_ENABLED   0x00000001u
#define SOV_RING_TELEMETRY_HEARTBEAT 0x00000002u
#define SOV_RING_TELEMETRY_DROP_OK   0x00000004u  // OK to drop events if ring full

// ============================================================================
// 4. Execution Plane → Control Plane — Cancellation
// ============================================================================
// Simple epoch-based cancellation. Control plane increments epoch.
// Execution plane polls and aborts if epoch != expected.

static inline bool Sovereign_ShouldCancel(const SovereignInvokeContext* ctx) {
    if (!ctx || !ctx->cancel_epoch) return false;
    return *ctx->cancel_epoch != ctx->expected_epoch;
}

// ============================================================================
// 5. Registration / Discovery
// ============================================================================
// C++ control plane calls this to populate the kernel table.
// Returns true if ABI version matches and at least one kernel registered.

extern "C" {
    // MASM modules export these symbols
    bool Sovereign_RegisterKernels_MASM(SovereignKernelTable* table);
    bool Sovereign_RegisterKernels_AVX512(SovereignKernelTable* table);
    bool Sovereign_RegisterKernels_Reference(SovereignKernelTable* table);  // C++ fallback

    // RingTrapdoor adapter
    bool Sovereign_RingTelemetry_Init(const SovereignRingTelemetryConfig* config);
    void Sovereign_RingTelemetry_Shutdown();
    void Sovereign_RingTelemetry_Emit(uint32_t event_type, uint64_t timestamp_ns,
                                       const void* data, size_t data_len);
}

// ============================================================================
// 6. Bit-Exact Verification Contract
// ============================================================================
// Before any MASM kernel is promoted to production, it must pass this:
//   1. Register reference C++ kernel
//   2. Register candidate MASM kernel
//   3. Run identical inputs through both
//   4. Verify memcmp(output_ref, output_masm, size) == 0
//   5. Benchmark and require speedup > threshold

struct SovereignBitExactTest {
    const char* kernel_name;
    void* ref_kernel;
    void* test_kernel;
    size_t output_bytes;
    double min_speedup;         // e.g., 1.10 for 10% faster
    int warmup_iterations;
    int benchmark_iterations;
};

extern "C" {
    bool Sovereign_RunBitExactTest(const SovereignBitExactTest* test);
}

#endif // SOVEREIGN_ABI_H
