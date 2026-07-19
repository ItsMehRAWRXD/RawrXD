/*===========================================================================
 * SovereignRuntimeStatus.cpp
 * 
 * Implementation of IDE runtime status monitoring
 *===========================================================================*/

#include "SovereignRuntimeStatus.hpp"
#include "../kernel/SovereignKernelRuntimeLog.hpp"
#include "../kernel/SovereignKernelRegistry.hpp"
#include "SovereignInferenceBridge_Q4.hpp"
#include <chrono>

namespace RawrXD {
namespace IDE {

/*===========================================================================
 * RuntimeStatusMonitor Implementation
 *===========================================================================*/

void RuntimeStatusMonitor::Initialize() {
    using namespace Kernel;
    
    status_.initialized = true;
    
    // Check Q4_K_M availability
    status_.q4km_available = (SovereignKernel_Q4KM_Available() != 0);
    
    if (status_.q4km_available) {
        status_.kernel_version = SovereignKernel_Q4KM_GetVersion();
        
        // Get selected kernel
        auto kernel = GetQ4KMDequantKernel();
        if (kernel) {
            auto& detector = CPUFeatureDetector::Instance();
            status_.has_avx2 = detector.HasAVX2();
            status_.has_avx512 = detector.HasAVX512();
            
            if (status_.has_avx512) {
                status_.selected_kernel = "q4_k_m_dequant_avx512";
            } else if (status_.has_avx2) {
                status_.selected_kernel = "q4_k_m_dequant_avx2";
            } else {
                status_.selected_kernel = "q4_k_m_dequant";
            }
        }
    }
}

void RuntimeStatusMonitor::Update() {
    // Re-check availability (in case runtime state changed)
    status_.q4km_available = (SovereignKernel_Q4KM_Available() != 0);
}

void RuntimeStatusMonitor::RecordInference(uint64_t tokens, uint64_t time_ms) {
    status_.tokens_generated += tokens;
    status_.total_inference_time_ms += time_ms;
    
    // Calculate rolling TPS
    if (status_.total_inference_time_ms > 0) {
        status_.current_tps = 
            (status_.tokens_generated * 1000.0) / status_.total_inference_time_ms;
    }
}

void RuntimeStatusMonitor::ResetMetrics() {
    status_.tokens_generated = 0;
    status_.total_inference_time_ms = 0;
    status_.current_tps = 0.0;
}

/*===========================================================================
 * IDE Integration
 *===========================================================================*/

void IDE_InitRuntimeStatus() {
    // Initialize the runtime status monitor
    RuntimeStatusMonitor::Instance().Initialize();
    
    // Also initialize kernel logging
    Kernel::KernelRuntimeLog::Instance().Initialize(Kernel::KernelRuntimeLog::Level::Info);
    Kernel::KernelRuntimeLog::Instance().PrintStartupBanner();
}

void IDE_UpdateRuntimeStatus(HWND hStatusBar) {
    if (!hStatusBar) return;
    
    auto& monitor = RuntimeStatusMonitor::Instance();
    monitor.Update();
    
    std::wstring status = monitor.GetStatusString();
    
    // Update status bar text
    SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)status.c_str());
}

void IDE_SetModelQuantized(bool is_quantized, int quant_bits) {
    auto& monitor = RuntimeStatusMonitor::Instance();
    
    if (is_quantized && quant_bits == 4) {
        // Q4 model loaded
        monitor.Update();
    } else {
        // FP32 or other quantization
        monitor.ResetMetrics();
    }
}

void IDE_UpdateInferenceMetrics(uint64_t tokens, uint64_t time_ms) {
    RuntimeStatusMonitor::Instance().RecordInference(tokens, time_ms);
}

} // namespace IDE
} // namespace RawrXD

/*===========================================================================
 * C API for IDE Integration
 *===========================================================================*/

extern "C" {

// Initialize runtime status in IDE
__declspec(dllexport)
void RawrXD_IDE_InitRuntimeStatus(void) {
    RawrXD::IDE::IDE_InitRuntimeStatus();
}

// Update status bar
__declspec(dllexport)
void RawrXD_IDE_UpdateRuntimeStatus(HWND hStatusBar) {
    RawrXD::IDE::IDE_UpdateRuntimeStatus(hStatusBar);
}

// Get status string for display
__declspec(dllexport)
const wchar_t* RawrXD_IDE_GetRuntimeStatusString(void) {
    static thread_local wchar_t buffer[256];
    
    std::wstring status = RawrXD::IDE::RuntimeStatusMonitor::Instance().GetStatusString();
    wcsncpy_s(buffer, 256, status.c_str(), _TRUNCATE);
    
    return buffer;
}

// Check if Q4 is ready
__declspec(dllexport)
int RawrXD_IDE_IsQ4Ready(void) {
    return RawrXD::IDE::RuntimeStatusMonitor::Instance().IsQ4Available() ? 1 : 0;
}

} // extern "C"
