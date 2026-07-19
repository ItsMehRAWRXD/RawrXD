/*===========================================================================
 * SovereignRuntimeStatus_MultiQuant.hpp
 *
 * Enhanced IDE status display for multi-format quantization
 *
 * Displays:
 *   Model: llama-3.1-70b-Q6_K.gguf
 *   Quant: Q6_K
 *   Kernel: Sovereign_Q6K_AVX512
 *   Device: Ryzen CPU
 *   Throughput: 18.7 TPS
 *   Status: READY
 *===========================================================================*/

#pragma once

#include "SovereignRuntimeStatus.hpp"
#include "../bridge/Deep2_Quantized.hpp"
#include <string>

namespace RawrXD {
namespace IDE {

/*===========================================================================
 * Multi-Format Runtime Status Info
 *===========================================================================*/
struct MultiQuantRuntimeStatus {
    // Model info
    std::wstring modelName;
    std::wstring modelPath;
    uint64_t modelParams = 0;

    // Quantization info
    Deep2::QuantType quantType = Deep2::QuantType::Unknown;
    const char* quantName = "Unknown";
    uint32_t quantBits = 0;

    // Kernel info
    const char* kernelName = "Unknown";
    const char* kernelVersion = "N/A";
    bool hasAVX2 = false;
    bool hasAVX512 = false;

    // Device info
    std::wstring deviceName = L"CPU";
    uint32_t numCores = 0;

    // Performance
    double currentTPS = 0.0;
    double avgLatencyMs = 0.0;
    uint64_t tokensGenerated = 0;
    uint64_t totalTokens = 0;

    // Status
    bool initialized = false;
    bool ready = false;
    std::wstring statusMessage = L"Not initialized";

    // Format detailed status for display
    std::wstring ToDetailedString() const {
        if (!initialized) {
            return L"Sovereign Runtime: Not initialized";
        }

        wchar_t buffer[512];

        // Extract model name from path
        std::wstring shortName = modelName;
        size_t pos = shortName.find_last_of(L"/\\");
        if (pos != std::wstring::npos) {
            shortName = shortName.substr(pos + 1);
        }

        swprintf_s(buffer, 512,
            L"Model: %s\n"
            L"Quant: %S\n"
            L"Kernel: %S\n"
            L"Device: %s\n"
            L"Throughput: %.1f TPS\n"
            L"Status: %s",
            shortName.c_str(),
            quantName,
            kernelName,
            deviceName.c_str(),
            currentTPS,
            ready ? L"READY" : statusMessage.c_str()
        );

        return std::wstring(buffer);
    }

    // Format compact status for status bar
    std::wstring ToStatusBarString() const {
        if (!initialized) {
            return L"Sovereign: Not Ready";
        }

        wchar_t buffer[128];

        if (ready) {
            swprintf_s(buffer, 128, L"%S: %s | %.1f TPS | Ready",
                quantName,
                hasAVX512 ? L"AVX-512" : (hasAVX2 ? L"AVX2" : L"Scalar"),
                currentTPS);
        } else {
            swprintf_s(buffer, 128, L"%S: %s",
                quantName,
                statusMessage.c_str());
        }

        return std::wstring(buffer);
    }

    // Format for tooltip (detailed)
    std::wstring ToTooltipString() const {
        if (!initialized) {
            return L"Sovereign Runtime not initialized\n"
                   L"Load a quantized model to begin";
        }

        wchar_t buffer[1024];

        swprintf_s(buffer, 1024,
            L"Sovereign Runtime\n"
            L"=================\n"
            L"Model: %s\n"
            L"Parameters: %.1fB\n"
            L"\n"
            L"Quantization:\n"
            L"  Format: %S (%d-bit)\n"
            L"  Block size: %zu values\n"
            L"\n"
            L"Kernel:\n"
            L"  Implementation: %S\n"
            L"  Version: %S\n"
            L"  CPU Features: AVX2=%s, AVX-512=%s\n"
            L"\n"
            L"Performance:\n"
            L"  Throughput: %.2f TPS\n"
            L"  Avg latency: %.2f ms\n"
            L"  Tokens generated: %llu\n"
            L"\n"
            L"Device:\n"
            L"  %s (%u cores)\n"
            L"\n"
            L"Status: %s",
            modelName.c_str(),
            modelParams / 1e9,
            quantName,
            quantBits,
            GetBlockSize(),
            kernelName,
            kernelVersion,
            hasAVX2 ? "Yes" : "No",
            hasAVX512 ? "Yes" : "No",
            currentTPS,
            avgLatencyMs,
            tokensGenerated,
            deviceName.c_str(),
            numCores,
            ready ? "READY" : "Not ready"
        );

        return std::wstring(buffer);
    }

private:
    size_t GetBlockSize() const {
        auto* info = Deep2::GetBlockInfo(quantType);
        return info ? info->blockSize : 0;
    }
};

/*===========================================================================
 * Multi-Format Runtime Status Monitor
 *===========================================================================*/
class MultiQuantRuntimeMonitor {
public:
    static MultiQuantRuntimeMonitor& Instance() {
        static MultiQuantRuntimeMonitor instance;
        return instance;
    }

    // Initialize with model
    void Initialize(const std::wstring& modelPath,
                    Deep2::QuantType quantType,
                    uint64_t modelParams);

    // Update performance metrics
    void UpdateMetrics(uint64_t tokens, double timeMs);

    // Get current status
    const MultiQuantRuntimeStatus& GetStatus() const { return status_; }

    // Set ready state
    void SetReady(bool ready, const std::wstring& message = L"") {
        status_.ready = ready;
        if (!message.empty()) {
            status_.statusMessage = message;
        }
    }

    // Check if specific format is active
    bool IsFormatActive(Deep2::QuantType type) const {
        return status_.quantType == type;
    }

    // Get recommended format for current model
    Deep2::QuantType GetRecommendedFormat() const;

private:
    MultiQuantRuntimeMonitor() = default;
    MultiQuantRuntimeStatus status_;
};

/*===========================================================================
 * IDE Integration Functions
 *===========================================================================*/

// Initialize multi-format runtime status
void IDE_InitMultiQuantRuntime();

// Update status when model is loaded
void IDE_SetMultiQuantModel(const std::wstring& path,
                            Deep2::QuantType quantType,
                            uint64_t params);

// Update performance metrics
void IDE_UpdateMultiQuantMetrics(uint64_t tokens, double timeMs);

// Get formatted status for UI
std::wstring IDE_GetMultiQuantStatusString();
std::wstring IDE_GetMultiQuantTooltipString();

} // namespace IDE
} // namespace RawrXD
