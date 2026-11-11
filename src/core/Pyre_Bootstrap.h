// ============================================================================
// Pyre_Bootstrap.h — Shared C++/MASM Bootstrap Page for Pyre Compute Engine
// ============================================================================
// This header is included in BOTH C++ compilation units and MASM include paths.
// The BootstrapPage is placed in a dedicated ".pyre" PE section via
// __declspec(allocate(".pyre")) so the MASM side can locate it by:
//   (a) Static linking: EXTERN g_pyreBootstrap + RIP-relative lea
//   (b) Injection: scan for magic 'PYRE' in the .pyre section
//
// Design goals:
//   - Zero-copy command queue between C++ Orchestrator and MASM kernels
//   - ASLR-safe: all addresses stored as RVAs relative to hostImageBase
//   - 4KB page-aligned for clean MMU boundaries
//   - No CRT dependency on the MASM side
// ============================================================================

#pragma once
#include <cstdint>
#include <windows.h>

// Place the bootstrap page in a dedicated PE section.
// The linker will create .pyre with READ+WRITE permissions.
// MASM code can locate this section by scanning for the magic signature.
#pragma section(".pyre", read, write)

namespace pyre {

    // 4KB bootstrap page — mapped once at engine init, never moved.
    // All pointer fields are stored as uint64_t to keep the layout
    // identical between C++ and MASM (no pointer-width ambiguity).
    struct alignas(4096) BootstrapPage {
        // --- Header (64 bytes) ---
        uint64_t    magic;              // 'PYRE' (0x000045525950)
        uint64_t    version;            // 0x0001
        uint64_t    hostImageBase;      // Actual load address of IDE.exe (ASLR)
        uint64_t    engineSectionRVA; // Offset of executable scratch space
        uint64_t    engineSectionSize;  // Capacity in bytes
        uint64_t    kvCacheMMFHandle;   // HANDLE from CreateFileMapping
        uint64_t    kvCacheView;        // Base pointer to mapped KV aperture
        uint64_t    reserved0;          // Padding / future use

        // --- Command Queue (64 bytes) ---
        uint64_t    command;            // 0=idle, 1=GEMM, 2=attn, 3=dequant, 4=softmax
        uint64_t    status;             // 0=busy, 1=done, 0xFF=error
        uint64_t    arg0;               // Out ptr (as uint64_t)
        uint64_t    arg1;               // Input ptr A
        uint64_t    arg2;               // Input ptr B
        uint64_t    arg3;               // M / rows / dims
        uint64_t    arg4;               // N / cols / dims
        uint64_t    arg5;               // K / depth / scale
        uint64_t    alpha;              // Scaling factor (IEEE-754 bits as uint64_t)

        // --- Telemetry / Feedback (64 bytes) ---
        uint64_t    startTSC;           // TSC at command dispatch
        uint64_t    endTSC;             // TSC at completion
        uint64_t    accumCycles;        // Total cycles consumed by Pyre kernels
        uint64_t    kernelFlags;        // Bitmask: AVX-512=1, AVX2=2, SSE2=4
        uint64_t    errorCode;          // Extended error information
        uint64_t    reserved1[3];       // Padding

        // --- Padding to 4KB ---
        uint8_t     pad[4096 - 25 * sizeof(uint64_t)];
    };

    // Static assert to ensure layout is exactly 4096 bytes
    static_assert(sizeof(BootstrapPage) == 4096, "BootstrapPage must be exactly 4096 bytes");
    static_assert(alignof(BootstrapPage) == 4096, "BootstrapPage must be 4096-byte aligned");

    // Command codes (must match Pyre_Entry.asm)
    constexpr uint64_t PYRE_CMD_IDLE     = 0;
    constexpr uint64_t PYRE_CMD_GEMM     = 1;
    constexpr uint64_t PYRE_CMD_ATTN     = 2;
    constexpr uint64_t PYRE_CMD_DEQUANT  = 3;
    constexpr uint64_t PYRE_CMD_SOFTMAX  = 4;
    constexpr uint64_t PYRE_CMD_SMOKE    = 5;

    // Status codes
    constexpr uint64_t PYRE_STATUS_BUSY  = 0;
    constexpr uint64_t PYRE_STATUS_DONE = 1;
    constexpr uint64_t PYRE_STATUS_ERROR = 0xFF;

    // Kernel flags
    constexpr uint64_t PYRE_FLAG_AVX512 = 1;
    constexpr uint64_t PYRE_FLAG_AVX2    = 2;
    constexpr uint64_t PYRE_FLAG_SSE2    = 4;

} // namespace pyre

// Global C-linkage symbol — definition lives in a single .cpp unit
extern "C" pyre::BootstrapPage g_pyreBootstrap;

namespace pyre {

    // Convenience C++ accessor that converts RVAs to absolute pointers
    inline void* PyrePtrFromRVA(uint64_t rva) {
        return reinterpret_cast<void*>(g_pyreBootstrap.hostImageBase + rva);
    }

    inline uint64_t PyreRVAFromPtr(const void* ptr) {
        return reinterpret_cast<uint64_t>(ptr) - g_pyreBootstrap.hostImageBase;
    }

} // namespace pyre

// ============================================================================
// MASM-friendly macro definitions (included via rawrxd_win64.inc)
// ============================================================================
// When this header is consumed by MASM (via include paths), the following
// offsets are available as constants. The MASM side should define:
//   PYRE_MAGIC        EQU 0x000045525950
//   PYRE_VERSION      EQU 0x0001
//   PYRE_CMD_IDLE     EQU 0
//   PYRE_CMD_GEMM     EQU 1
//   PYRE_CMD_ATTN     EQU 2
//   PYRE_CMD_DEQUANT  EQU 3
//   PYRE_CMD_SOFTMAX  EQU 4
//   PYRE_STATUS_BUSY  EQU 0
//   PYRE_STATUS_DONE  EQU 1
//   PYRE_STATUS_ERROR EQU 0xFF
//
// BootstrapPage field offsets (relative to struct base):
//   PYRE_OFF_MAGIC              EQU 0x0000
//   PYRE_OFF_VERSION            EQU 0x0008
//   PYRE_OFF_HOST_IMAGE_BASE    EQU 0x0010
//   PYRE_OFF_ENGINE_SECTION_RVA EQU 0x0018
//   PYRE_OFF_ENGINE_SECTION_SZ  EQU 0x0020
//   PYRE_OFF_KV_CACHE_HANDLE    EQU 0x0028
//   PYRE_OFF_KV_CACHE_VIEW    EQU 0x0030
//   PYRE_OFF_COMMAND          EQU 0x0040
//   PYRE_OFF_STATUS           EQU 0x0048
//   PYRE_OFF_ARG0             EQU 0x0050
//   PYRE_OFF_ARG1             EQU 0x0058
//   PYRE_OFF_ARG2             EQU 0x0060
//   PYRE_OFF_ARG3             EQU 0x0068
//   PYRE_OFF_ARG4             EQU 0x0070
//   PYRE_OFF_ARG5             EQU 0x0078
//   PYRE_OFF_ALPHA            EQU 0x0080
//   PYRE_OFF_START_TSC        EQU 0x0088
//   PYRE_OFF_END_TSC          EQU 0x0090
//   PYRE_OFF_ACCUM_CYCLES     EQU 0x0098
//   PYRE_OFF_KERNEL_FLAGS     EQU 0x00A0
//   PYRE_OFF_ERROR_CODE       EQU 0x00A8
//
// The MASM side should use these offsets with:
//   lea  rax, [rip + g_pyreBootstrap]
//   mov  rcx, [rax + PYRE_OFF_ARG0]   ; load arg0
// ============================================================================
