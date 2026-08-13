#pragma once
#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// RawrXD Multi-GPU Context — B018
// Explicit device enumeration, identity, and independent contexts.
// Host knows WHICH device, not HOW inference works.
// ============================================================================

#define RAWRXD_GPU_MAX_DEVICES 8
#define RAWRXD_GPU_NAME_LEN    128

// GPU device capability flags
#define RAWRXD_GPU_FLAG_VULKAN       0x0001
#define RAWRXD_GPU_FLAG_CUDA         0x0002
#define RAWRXD_GPU_FLAG_ROCM         0x0004
#define RAWRXD_GPU_FLAG_AVX512       0x0008
#define RAWRXD_GPU_FLAG_RDNA3        0x0010
#define RAWRXD_GPU_FLAG_LARGE_BAR    0x0020  // Resizable BAR / Smart Access Memory

struct rawrxd_gpu_device_info_t {
    uint32_t device_index;              // 0-based enumeration order
    char     name[RAWRXD_GPU_NAME_LEN]; // Human-readable name
    uint32_t pci_vendor_id;
    uint32_t pci_device_id;
    uint64_t vram_total_bytes;
    uint64_t vram_available_bytes;
    uint32_t compute_units;             // CUs / SMs / Xe Cores
    uint32_t max_clock_mhz;
    uint32_t flags;                     // RAWRXD_GPU_FLAG_*
    uint32_t reserved[4];
};

struct rawrxd_gpu_context_t;
typedef struct rawrxd_gpu_context_t* rawrxd_gpu_context_handle_t;

// ============================================================================
// Device enumeration
// ============================================================================

// Enumerate all GPU devices visible to the process.
//   out_devices: caller-provided array (max RAWRXD_GPU_MAX_DEVICES)
//   out_count:   written with actual device count
// Returns: RAWRXD_OK or error code
int rawrxd_gpu_enumerate(
    rawrxd_gpu_device_info_t* out_devices,
    uint32_t* out_count);

// ============================================================================
// Context lifecycle (one per active device)
// ============================================================================

// Create an explicit GPU context for the specified device index.
// The context is opaque to the host; only the engine knows internals.
rawrxd_gpu_context_handle_t rawrxd_gpu_context_create(uint32_t device_index);

// Destroy context and release all associated device resources.
void rawrxd_gpu_context_destroy(rawrxd_gpu_context_handle_t ctx);

// Query the device info associated with a context.
int rawrxd_gpu_context_get_info(
    rawrxd_gpu_context_handle_t ctx,
    rawrxd_gpu_device_info_t* out_info);

// ============================================================================
// Capability queries (host-visible, no engine internals)
// ============================================================================

// Check if a specific capability flag is present.
bool rawrxd_gpu_has_flag(
    const rawrxd_gpu_device_info_t* info,
    uint32_t flag);

// Estimate whether a model with given parameter count and quantization
// could fit in this device's VRAM (conservative estimate).
bool rawrxd_gpu_can_fit_model(
    const rawrxd_gpu_device_info_t* info,
    uint64_t parameter_count,
    uint32_t bits_per_weight);

#ifdef __cplusplus
}
#endif
