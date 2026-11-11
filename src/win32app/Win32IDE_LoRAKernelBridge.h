// ============================================================================
// Win32IDE_LoRAKernelBridge.h — LoRA MASM Kernel Integration Header
// ============================================================================
#pragma once

#include <windows.h>
#include <cstddef>
#include <cstdint>

// ============================================================================
// C API for LoRA Kernel Bridge
// ============================================================================

#ifdef __cplusplus
extern "C" {
#endif

// Initialize the LoRA kernel bridge
// Returns true on success, false on failure
__declspec(dllexport) bool LoRAKernel_Initialize();

// Shutdown the LoRA kernel bridge
__declspec(dllexport) void LoRAKernel_Shutdown();

// Submit work to the kernel for async processing
// input_buffer: Float array of size buffer_size
// buffer_size: Number of floats in input
// target_hwnd: Window to receive WM_APP + 200 completion message
// request_id: Unique identifier for this request
// Returns true if work was queued, false otherwise
__declspec(dllexport) bool LoRAKernel_Submit(
    const float* input_buffer,
    size_t buffer_size,
    HWND target_hwnd,
    uint32_t request_id
);

// Check if kernel is ready for processing
__declspec(dllexport) bool LoRAKernel_IsReady();

// ============================================================================
// Message Constants
// ============================================================================

// WM_APP + 210 = LoRA kernel completion notification
// WPARAM = request_id
// LPARAM = pointer to std::vector<float>* (caller must delete after copying)
#define WM_LORA_COMPLETION (WM_APP + 210)

#ifdef __cplusplus
}

// ============================================================================
// C++ Interface (for internal use)
// ============================================================================

namespace RawrXD::LoRAKernelBridge {

// Forward declaration
class LoRAKernelBridge;

// Get the singleton instance
LoRAKernelBridge& GetLoRAKernelBridge();

} // namespace RawrXD::LoRAKernelBridge

#endif // __cplusplus
