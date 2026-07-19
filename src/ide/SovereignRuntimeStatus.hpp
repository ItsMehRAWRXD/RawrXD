/*===========================================================================
 * SovereignRuntimeStatus.hpp
 * 
 * IDE UI component for displaying Sovereign Runtime status
 * 
 * Displays in IDE status bar or panel:
 *   [SovereignKernelRegistry]
 *   Q4_K_M: AVX-512 | 22.5 TPS | Ready
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <string>

namespace RawrXD {
namespace IDE {

/*===========================================================================
 * Runtime Status Info
 *===========================================================================*/
struct RuntimeStatusInfo {
    bool initialized = false;
    bool q4km_available = false;
    const char* kernel_version = "N/A";
    const char* selected_kernel = "N/A";
    bool has_avx2 = false;
    bool has_avx512 = false;
    double current_tps = 0.0;
    uint64_t tokens_generated = 0;
    uint64_t total_inference_time_ms = 0;
    
    // Format for status bar: "Q4_K_M: AVX-512 | 22.5 TPS | Ready"
    std::wstring ToStatusString() const {
        if (!initialized) {
            return L"Sovereign: Not Initialized";
        }
        
        if (!q4km_available) {
            return L"Sovereign: FP32 Mode";
        }
        
        wchar_t buffer[256];
        const wchar_t* arch = has_avx512 ? L"AVX-512" : (has_avx2 ? L"AVX2" : L"Scalar");
        
        if (current_tps > 0.0) {
            swprintf_s(buffer, 256, L"Q4_K_M: %s | %.1f TPS | Ready", 
                      arch, current_tps);
        } else {
            swprintf_s(buffer, 256, L"Q4_K_M: %s | Ready", arch);
        }
        
        return std::wstring(buffer);
    }
    
    // Format for tooltip: detailed info
    std::wstring ToTooltipString() const {
        if (!initialized) {
            return L"Sovereign Runtime not initialized";
        }
        
        wchar_t buffer[512];
        
        if (q4km_available) {
            swprintf_s(buffer, 512, 
                L"Sovereign Runtime\n"
                L"Kernel: %S\n"
                L"Version: %S\n"
                L"CPU Features: AVX2=%s, AVX-512=%s\n"
                L"Tokens Generated: %llu\n"
                L"Avg TPS: %.2f",
                selected_kernel,
                kernel_version,
                has_avx2 ? L"Yes" : L"No",
                has_avx512 ? L"Yes" : L"No",
                tokens_generated,
                current_tps);
        } else {
            swprintf_s(buffer, 512, 
                L"Sovereign Runtime (FP32 Mode)\n"
                L"Q4_K_M kernels not available");
        }
        
        return std::wstring(buffer);
    }
};

/*===========================================================================
 * Runtime Status Monitor
 * Singleton for tracking runtime status
 *===========================================================================*/
class RuntimeStatusMonitor {
public:
    static RuntimeStatusMonitor& Instance() {
        static RuntimeStatusMonitor instance;
        return instance;
    }
    
    // Initialize and query runtime
    void Initialize();
    void Update();
    
    // Get current status
    const RuntimeStatusInfo& GetStatus() const { return status_; }
    
    // Update performance metrics
    void RecordInference(uint64_t tokens, uint64_t time_ms);
    void ResetMetrics();
    
    // Check if Q4 is available
    bool IsQ4Available() const { return status_.q4km_available; }
    
    // Get status string for UI
    std::wstring GetStatusString() const { return status_.ToStatusString(); }
    std::wstring GetTooltipString() const { return status_.ToTooltipString(); }

private:
    RuntimeStatusMonitor() = default;
    RuntimeStatusInfo status_;
};

/*===========================================================================
 * Status Bar Integration
 * Helper for adding runtime status to IDE status bar
 *===========================================================================*/

// Call from IDE initialization
void IDE_InitRuntimeStatus();

// Call to update status bar
void IDE_UpdateRuntimeStatus(HWND hStatusBar);

// Call when model is loaded
void IDE_SetModelQuantized(bool is_quantized, int quant_bits);

// Call during inference to update TPS
void IDE_UpdateInferenceMetrics(uint64_t tokens, uint64_t time_ms);

} // namespace IDE
} // namespace RawrXD
