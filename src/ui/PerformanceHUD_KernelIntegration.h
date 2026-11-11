// PerformanceHUD_KernelIntegration.h
// Phase 25: The Performance HUD - Kernel Integration
// ============================================================================
// Macros and utilities for instrumenting kernel code with HUD telemetry
// ============================================================================

#pragma once

#include "ui/PerformanceHUD.h"
#include <chrono>

// ============================================================================
// Kernel Instrumentation Macros
// ============================================================================

// Record a kernel latency measurement (in microseconds)
#define HUD_RECORD_KERNEL_LATENCY(kernelName, microseconds) \
    do { \
        auto* hud = RawrXD::UI::GetPerformanceHUD(); \
        if (hud) { \
            hud->RecordKernelLatency(L##kernelName, static_cast<double>(microseconds)); \
        } \
    } while(0)

// Record memory bandwidth (in GB/s)
#define HUD_RECORD_MEMORY_BANDWIDTH(gbps) \
    do { \
        auto* hud = RawrXD::UI::GetPerformanceHUD(); \
        if (hud) { \
            hud->RecordMemoryBandwidth(static_cast<double>(gbps)); \
        } \
    } while(0)

// Record TPS (tokens per second)
#define HUD_RECORD_TPS(tps) \
    do { \
        auto* hud = RawrXD::UI::GetPerformanceHUD(); \
        if (hud) { \
            hud->RecordTPS(static_cast<double>(tps)); \
        } \
    } while(0)

// Record GPU utilization (0-100%)
#define HUD_RECORD_GPU_UTIL(percent) \
    do { \
        auto* hud = RawrXD::UI::GetPerformanceHUD(); \
        if (hud) { \
            hud->RecordGPUUtilization(static_cast<double>(percent)); \
        } \
    } while(0)

// Record a custom metric
#define HUD_RECORD_METRIC(metricName, value) \
    do { \
        auto* hud = RawrXD::UI::GetPerformanceHUD(); \
        if (hud) { \
            hud->RecordMetric(L##metricName, static_cast<double>(value)); \
        } \
    } while(0)

// ============================================================================
// Scoped Timer for Automatic Latency Recording
// ============================================================================
namespace RawrXD {
namespace UI {

class HUDScopedTimer {
public:
    HUDScopedTimer(const std::wstring& kernelName) 
        : kernelName_(kernelName), start_(std::chrono::high_resolution_clock::now()) {}
    
    ~HUDScopedTimer() {
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start_).count();
        
        auto* hud = GetPerformanceHUD();
        if (hud) {
            hud->RecordKernelLatency(kernelName_, static_cast<double>(duration));
        }
    }
    
private:
    std::wstring kernelName_;
    std::chrono::high_resolution_clock::time_point start_;
};

} // namespace UI
} // namespace RawrXD

// Convenience macro for scoped timing
#define HUD_SCOPED_TIMER(kernelName) \
    RawrXD::UI::HUDScopedTimer _hud_timer_##__LINE__(L##kernelName)

// ============================================================================
// Example Usage in Kernel Code
// ============================================================================
/*

// In your LoRA kernel:
void LoRA_Apply_Kernel(...) {
    HUD_SCOPED_TIMER("LoRA_Apply");
    
    // ... kernel implementation ...
    
    // Or manual recording:
    auto start = std::chrono::high_resolution_clock::now();
    // ... do work ...
    auto end = std::chrono::high_resolution_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    HUD_RECORD_KERNEL_LATENCY("LoRA_Apply", us);
}

// In your inference loop:
void Inference_Step() {
    HUD_SCOPED_TIMER("Inference_Step");
    
    // ... inference ...
    
    // Record TPS
    double tps = tokens_generated / elapsed_seconds;
    HUD_RECORD_TPS(tps);
}

*/
